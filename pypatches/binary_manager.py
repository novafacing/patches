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

from pypatches.error import NoSectionError
from pypatches.types import Code, TransformInfo

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

    def __init__(
        self,
        binary: Union[Path, str, bytes],
        cle_opts: Optional[Dict[str, bool]] = None,
        cfg_opts: Optional[Dict[str, bool]] = None,
        silence_angr_logs: bool = False,
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

    def code(self, code: Code) -> bytes:
        """
        Get the raw code from a code object

        :param code: The code object
        """
        if code.c_code:
            compiled_code = Squishy().compile(code.c_code)

            disassembly = self.angr_project.arch.disasm(compiled_code, 0)
            logger.info(f"Disassembly: {disassembly}")

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

    def save(self, where: Path) -> None:
        """
        Save the binary to where

        :param where: Path to save the binary to
        """
        offsets = {}
        base_addr = None

        text_section_offset = self.lief_binary.get_section(".text").offset

        # Add code to the binary if there is any to add
        if self.code_to_add:
            segment = Segment()
            content = b""

            for label, code in self.code_to_add.items():
                logger.info(f"Adding code at label {label}: {code}")
                offsets[label] = len(content)
                content += self.code(code)

            segment.content = list(content)
            segment.type = SEGMENT_TYPES.LOAD
            segment.alignment = self.cle_binary.arch.instruction_alignment
            segment.flags = SEGMENT_FLAGS(5)
            new_segment = self.lief_binary.add(segment)
            base_addr = new_segment.virtual_address

            for label, offset in offsets.items():
                offsets[label] += base_addr

        new_text_section_offset = self.lief_binary.get_section(".text").offset
        text_section_adjust = new_text_section_offset - text_section_offset

        # After adding code, the program headers move to the end of the file and
        # the .text section address changes on disk, so we need to perform a relocation
        # based on the new offset of the text section

        tinfo = TransformInfo(offsets, text_section_adjust, self.lief_binary)

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
                data = self.code(write.data)
            else:
                data = write.data(offsets)

            logger.info(f"Writing {len(data)} bytes at {offset:#0x}")

            self.lief_binary.patch_address(offset, list(data))

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
