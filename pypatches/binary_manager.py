"""
Binary program wrapper
"""

from dataclasses import dataclass
from io import BytesIO
from logging import getLogger
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union, cast

from angr import Project
from cle.backends import Backend
from lief import Binary as LIEFBinary  # pylint: disable=no-name-in-module
from lief import parse  # pylint: disable=no-name-in-module
from lief.ELF import (  # pylint: disable=no-name-in-module,import-error
    SEGMENT_FLAGS,
    SEGMENT_TYPES,
    Segment,
)
from capstone import CsInsn
from pysquishy.squishy import Squishy
from pypatches.dynamic_info import DynamicInfo

from pypatches.error import NoSectionError
from pypatches.types import Code, PreTransformInfo, TransformInfo

logger = getLogger(__name__)


@dataclass
class WriteOperation:
    """
    A write operation to be performed on a section

    :attribute data: Either raw bytes or a function that takes the resolved
        labels for all patches and returns raw bytes

    :attribute vaddr: The virtual address or label location to write to
    """

    data: Union[bytes, Callable[[Dict[str, int]], bytes], Code]
    where: Union[str, int]


class BinaryManager:
    """
    Wrapper for a binary program to provide information for patching
    """

    path: Optional[Path] = None
    blob: BytesIO
    lief_binary: LIEFBinary
    angr_project: Project
    cle_binary: Backend
    cle_opts: Dict[str, bool] = {
        "auto_load_libs": False,
        "use_system_libs": False,
    }
    cfg_opts: Dict[str, bool] = {
        "normalize": True,
        "data_references": False,
        "cross_references": False,
        "skip_unmapped_addrs": True,
        "force_complete_scan": False,
    }
    writes: List[WriteOperation] = []
    code_to_add: Dict[str, Code] = {}
    alignment: int = 0x1000
    data_to_add: Dict[str, bytes] = {}

    def __init__(
        self,
        binary: Union[Path, str, bytes],
        cle_opts: Optional[Dict[str, bool]] = None,
        cfg_opts: Optional[Dict[str, bool]] = None,
        silence_angr_logs: bool = False,
        alignment: int = 8,
    ) -> None:
        """
        Initialize the binary wrapper via one of several methods.

        :param binary: If `binary` is a `Path` or `str` we will attempt
            to load it from that path on disk. If it is `bytes`, we will
            first try to load it from the decoded path, and if there is
            no such path, we will try to load it as a binary blob.
        :param cle_opts: If provided, will override the kwargs passed to
            `cle.Loader`
        """
        if isinstance(binary, Path):
            self.path = binary
        elif isinstance(binary, str):
            self.path = Path(binary)
        elif isinstance(binary, bytes):
            self.path = None
        else:
            raise TypeError(
                f"Requested binary is of type {type(binary)}"
                ", expected Path, str, or bytes."
            )

        if self.path is not None and not self.path.is_file():
            raise FileNotFoundError(
                f"Requested binary {self.path} was not found or could not be opened."
            )

        if cle_opts is not None:
            self.cle_opts = cle_opts

        if cfg_opts is not None:
            self.cfg_opts = cfg_opts

        if silence_angr_logs:
            for logger_name in ("angr", "pyvex", "cle", "archinfo", "claripy"):
                getLogger(logger_name).setLevel("ERROR")

        self.alignment = alignment

        if self.path is None:
            self.blob = BytesIO(cast(bytes, binary))
            self.lief_binary = parse(binary)
            self.angr_project = Project(
                self.blob,
                main_opts={"base_addr": self.lief_binary.imagebase},
                load_options=self.cle_opts,
            )
            self.angr_project.analyses.CFGFast(  # type: ignore
                **self.cfg_opts,
            )

            if self.angr_project.loader.main_object is None:
                raise FileNotFoundError(
                    f"Requested binary {self.path} "
                    "was not found or could not be opened."
                )

            self.cle_binary = self.angr_project.loader.main_object
        else:
            self.blob = BytesIO(self.path.read_bytes())
            self.lief_binary = parse(str(self.path))
            self.angr_project = Project(
                str(self.path),
                main_opts={"base_addr": self.lief_binary.imagebase},
                load_options=self.cle_opts,
            )
            self.angr_project.analyses.CFGFast(  # type: ignore
                **self.cfg_opts,
            )

            if self.angr_project.loader.main_object is None:
                raise FileNotFoundError(
                    f"Requested binary {self.path} "
                    "was not found or could not be opened."
                )

            self.cle_binary = self.angr_project.loader.main_object

    def write(
        self,
        where: Union[int, str],
        data: Union[bytes, Callable[[Dict[str, int]], bytes], Code],
    ) -> None:
        """
        Write data to the binary at the given virtual address

        :param where: Either an address or a label that will resolve to an address
        :param data: The bytes or a function that takes a dictionary of labels
            and addresses and returns bytes to write to the patch
        """

        operation = WriteOperation(data, where)
        logger.info(f"Queuing write operation: {operation}")
        self.writes.append(operation)

    def read(self, vaddr: int, size: int) -> bytes:
        """
        Read data from the binary at the given virtual address
        """
        try:
            section = next(
                filter(lambda s: s.contains_addr(vaddr), self.cle_binary.sections)
            )
        except StopIteration as e:
            logger.error(f"Could not find section for address {vaddr}")
            raise NoSectionError(f"Could not find section for address {vaddr}") from e

        self.blob.seek(section.addr_to_offset(vaddr))
        return self.blob.read(size)

    def code_to_bytes(self, code: Code) -> bytes:
        """
        Get the raw code from a code object

        :param code: The code object
        """
        if code.c_code:
            compiled_code = Squishy().compile(code.c_code)

            return compiled_code

        if code.assembly:
            # TODO: Handle PC-relative assembly by making this a callable taking the addr
            return self.asm(code.assembly, 0)

        if code.raw:
            return code.raw

        raise ValueError("Code object has no code or assembly")

    def add_code(self, code: Code, label: Optional[str] = None) -> None:
        """
        Mark some code as being added on next save

        :param code: The binary code being added
        :param label: The label to associate with the code for resolution of
            other patches referencing it
        """
        if label is None:
            label = f"code_{len(self.code_to_add)}"

        logger.info(f"Queueing code addition at label {label}: {code}")

        self.code_to_add[label] = code

    def add_data(self, data: bytes, label: Optional[str] = None) -> None:
        """
        Add some data to the binary

        :param data: The data to add
        :param label: The label to associate with the data location
        """
        if label is None:
            label = f"data_{len(self.data_to_add)}"

        logger.info(f"Queueing data addition at label {label}: ({len(data)} bytes)")

        self.data_to_add[label] = data

    def save(self, where: Path) -> None:
        """
        Apply patches and save the binary to where

        :param where: Path to save the binary to
        """

        offsets = {}
        base_addr = None

        text_section_offset = self.lief_binary.get_section(".text").offset

        # Add code to the binary if there is any to add
        if self.code_to_add:

            got_plt = self.lief_binary.get_section(".got.plt")
            plt = self.lief_binary.get_section(".plt")
            has_rela = (
                self.lief_binary.get_section(".rela.dyn") is not None
                or self.life_binary.get_section(".rela.plt") is not None
            )

            gotplt_addr = got_plt.virtual_address
            plt_addr = plt.virtual_address
            dynamic_addr = got_plt.virtual_address
            link_map_addr = got_plt.virtual_address + 0x8
            dl_resolve_addr = got_plt.virtual_address + 0x10

            dynamic_info = DynamicInfo(
                gotplt_addr,
                plt_addr,
                dynamic_addr,
                link_map_addr,
                dl_resolve_addr,
                has_rela,
            )
            ptinfo = PreTransformInfo(
                dynamic_info=dynamic_info,
                new_code_segment_base=0,
                new_data_segment_addrs=[0],
            )

            # Pre-generate the content with current (wrong probably)
            # offsets
            content = b""

            for label, code in self.code_to_add.items():
                code.pretransform(ptinfo)
                logger.info(f"Adding code at label {label}: {code}")
                offsets[label] = len(content)
                content += self.code_to_bytes(code)

            segment = Segment()
            data_segment = Segment()

            # Create the segment with the (not correct, but probably the right size)
            # code
            segment.content = list(content)
            segment.type = SEGMENT_TYPES.LOAD
            segment.alignment = self.alignment
            segment.flags = SEGMENT_FLAGS(SEGMENT_FLAGS.X | SEGMENT_FLAGS.R)  # R/X

            # Create a data segment for storing patch data
            data_segment.content = list(b"\x00" * 0x1000)
            data_segment.type = SEGMENT_TYPES.LOAD
            data_segment.alignment = self.alignment
            data_segment.flags = SEGMENT_FLAGS(SEGMENT_FLAGS.R | SEGMENT_FLAGS.W)

            new_segment = self.lief_binary.add(segment)
            new_data_segment = self.lief_binary.add(data_segment)

            base_addr = new_segment.virtual_address
            got_plt = self.lief_binary.get_section(".got.plt")
            plt = self.lief_binary.get_section(".plt")

            gotplt_addr = got_plt.virtual_address
            plt_addr = plt.virtual_address
            dynamic_addr = got_plt.virtual_address
            link_map_addr = got_plt.virtual_address + 0x8
            dl_resolve_addr = got_plt.virtual_address + 0x10

            dynamic_info = DynamicInfo(
                gotplt_addr,
                plt_addr,
                dynamic_addr,
                link_map_addr,
                dl_resolve_addr,
                has_rela,
            )
            ptinfo = PreTransformInfo(
                dynamic_info=dynamic_info,
                new_code_segment_base=base_addr,
                new_data_segment_addrs=[new_data_segment.virtual_address],
            )

            # Now regenerate the content with the actual offsets
            content = b""

            for label, code in self.code_to_add.items():
                code.reset()
                code.pretransform(ptinfo)
                logger.info(f"Adding code at label {label}: {code}")
                offsets[label] = len(content)
                content += self.code_to_bytes(code)

            # Set the content to the correct content
            new_segment.content = list(content)

            disassembly = self.angr_project.arch.disasm(content, base_addr)

            logger.debug("Disassembly of added code:")

            for disas_line in disassembly.splitlines():
                logger.debug(f"{disas_line}")

            for label, offset in offsets.items():
                offsets[label] += base_addr

        new_text_section_offset = self.lief_binary.get_section(".text").offset
        text_section_adjust = new_text_section_offset - text_section_offset

        # After adding code, the program headers move to the end of the file and
        # the .text section address changes on disk, so we need to perform a relocation
        # based on the new offset of the text section

        tinfo = TransformInfo(
            offsets,
            text_section_adjust,
            self.lief_binary,
            new_segment.virtual_address,
            [new_data_segment.virtual_address],
        )

        # Apply any writes to the binary
        for write in self.writes:
            if isinstance(write.where, str):
                offset = offsets[write.where]
            else:
                offset = write.where

            offset += text_section_adjust

            if isinstance(write.data, bytes):
                data = write.data
            elif isinstance(write.data, Code):
                write.data.transform(tinfo)
                data = self.code_to_bytes(write.data)
                disassembly = self.angr_project.arch.disasm(data, offset)
                logger.debug("Disassembly of code being written:")
                for disas_line in disassembly.splitlines():
                    logger.debug(f"{disas_line}")
            else:
                data = write.data(offsets)

            logger.info(f"Writing {len(data)} bytes at {offset:#0x}")

            self.lief_binary.patch_address(offset, list(data))

        # Save the binary to disk
        self.lief_binary.write(str(where))

    def asm(self, asm: str, vaddr: int) -> bytes:
        """
        Assemble the given assembly code at the given virtual address
        """
        return self.cle_binary.arch.asm(asm, vaddr, as_bytes=True)  # type: ignore

    def disasm(self, vaddr: int) -> CsInsn:
        """
        Disassemble the binary at an address

        :param vaddr: The virtual address to disassemble at
        """
        block = (
            self.binary.angr_project.kb.cfgs["CFGFast"]
            .get_any_node(vaddr, anyaddr=True)
            .block
        )

        for instr in block.capstone.insns:
            if instr.address == vaddr:
                return instr

        raise ValueError(f"Could not find instruction at {vaddr:#0x}")

    def relative_call_addr(self, source: int, dest: int) -> int:
        """
        Calculate the relative offset of dest from source

        :param source: The address of the instruction making the call
        :param dest: The address of the instruction that should be called
            to
        """
        isize = self.disasm(source).size
