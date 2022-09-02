"""Binary program wrapper providing modification and analysis via LIEF and angr
"""

from dataclasses import dataclass
from io import BytesIO
from logging import getLogger
from pathlib import Path
from tempfile import NamedTemporaryFile
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

from pypatches.error import NoSectionError
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo
from pypatches.write_operation import WriteOperation

logger = getLogger(__name__)


class BinaryManager:
    """Wrapper for a binary program to provide information for patching

    Attributes:
        path: The path to the binary, if it exists on disk
        blob: The binary blob of the binary
        lief_binary: The LIEF binary object, which provides the majority of the program
            information for modification
        angr_project: The angr project, which provides the CFG and other information
            for analysis and deep inspection
        cle_binary: The CLE binary object, which provides angr's loader information
        cle_opts: The kwargs passed to `cle.Loader`, which can be used to override
            the default loader options
        cfg_opts: The kwargs passed to `angr.Project.analyses.CFGFast`, which can be
            used to override the default CFG options
        writes: A list of `WriteOperation`s that are queued for application to the
            binary
        code_to_add: A dictionary of `Code` objects to add to the binary, keyed by
            the label they are associated with
        alignment: The alignment to use when aligning addresses
        data_to_add: A dictionary of data to add to the binary, keyed by the label
            the data is associated with

    Args:
        binary: If `binary` is a `Path` or `str` we will attempt to load it from that
            path on disk. If it is `bytes`, we will load the bytes as a binary blob.
        cle_opts: If provided, will override the kwargs passed to `cle.Loader`, defaults
            to sane options.
        cfg_opts: If provided, will override the kwargs passed to
            `angr.Project.analyses.CFGFast`, defaults to sane options.
        silence_angr_logs: If `True`, will silence angr's logging output, defaults to
            `False`
        alignment: The alignment to use when aligning addresses, defaults to 8, but will
            be overridden by lief's alignment if it discovers a different alignment when
            loading the binary

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
        """Initialize the binary wrapper via one of several methods."""
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
        else:
            self.blob = BytesIO(self.path.read_bytes())

        self.load_lief_binary()
        self.load_angr_project()

    def reload_blob_from_lief(self) -> None:
        """Reload the blob from the current LIEF binary"""
        tempfile = NamedTemporaryFile(delete=False)
        temppath = Path(tempfile.name)

        try:
            tempfile.close()
            self.lief_binary.write(str(temppath.resolve()))
            self.blob = BytesIO(temppath.read_bytes())
        except Exception as e:
            raise e
        finally:
            temppath.unlink(missing_ok=True)

        self.load_lief_binary()
        self.load_angr_project()

    def load_lief_binary(self) -> None:
        """Load the binary into LIEF"""
        self.lief_binary = parse(self.blob.getbuffer())

    def load_angr_project(self) -> None:
        """Load the angr project from the binary blob"""
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
                f"Requested binary {self.path} " "was not found or could not be opened."
            )

        self.cle_binary = self.angr_project.loader.main_object

    def align(
        self,
        address: int,
        alignment: Optional[int] = None,
    ) -> int:
        """Align an address to the specified alignment. If no alignment is
        provided, the default alignment will be used.

        Args:
            address: The address to align
            alignment: The alignment to use, defaults to the default alignment of the
                binary
        """
        if alignment is None:
            alignment = self.alignment

        address = (address + (alignment - 1)) & ~(alignment - 1)

        return address

    def write(
        self,
        where: Union[int, str, Callable[[TransformInfo], int]],
        data: Union[bytes, Callable[[Dict[str, int]], bytes], Code],
    ) -> None:
        """Write data to the binary at the given virtual address

        Args:

            where: Either an address or a label that will resolve to an address, or
                a function that takes the transform info after segment modification and
                returns an address
            data: The bytes or a function that takes a dictionary of labels
                and addresses and returns bytes to write to the patch
        """

        operation = WriteOperation(data, where)
        logger.info(f"Queuing write operation: {operation}")
        self.writes.append(operation)

    def read(self, vaddr: int, size: int) -> bytes:
        """Read data from the binary at the given virtual address

        Args:
            vaddr: The virtual address to read from
            size: The number of bytes to read
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

    def add_code(self, code: Code, label: Optional[str] = None) -> None:
        """Mark some code as being added on next save

        Args:
            code: The binary code being added
            label: The label to associate with the code for resolution of
                other patches referencing it
        """
        if label is None:
            label = f"code_{len(self.code_to_add)}"

        logger.info(f"Queueing code addition at label {label}: {code}")

        code.label = label

        self.code_to_add[label] = code

    def add_data(self, data: bytes, label: Optional[str] = None) -> None:
        """Add some data to the binary

        Args:
            data: The data to add
            label: The label to associate with the data location
        """
        if label is None:
            label = f"data_{len(self.data_to_add)}"

        logger.info(f"Queueing data addition at label {label}: ({len(data)} bytes)")

        self.data_to_add[label] = data

    def apply(self) -> None:
        """Apply patches to the binary"""
        # Offsets is filled in twice:
        # - first time fills in offset in the new section
        # - second time fills in offset from base address
        transform_info = TransformInfo(self.lief_binary, self.angr_project)

        transform_info.code_size = 0
        transform_info.data_size = 0
        transform_info.all_data = b""
        transform_info.data_offsets = {}
        transform_info.code_offsets = {}

        # Figure out how much space we need for code
        # Each code patch is dummy compiled and placed in a subsection that is aligned
        # to the alignment of the binary.
        for label, code in self.code_to_add.items():
            code.reset()
            code.dummy()
            compiled = code.compile(
                "dummy",
            )

            # TODO: There might be a smarter way but we don't really prioritize size
            aligned_size = self.align(len(compiled), self.alignment) * 2

            transform_info.code_offsets[label] = transform_info.code_size
            transform_info.code_size += aligned_size

        for label, data in self.data_to_add.items():
            transform_info.data_offsets[label] = len(data)
            transform_info.data_size += len(data)
            transform_info.all_data += data

        # Round up code and data sizes to the next multiple of self.alignment
        transform_info.code_size = (
            transform_info.code_size + (self.alignment - 1)
        ) & ~(self.alignment - 1)

        transform_info.data_size = (
            transform_info.data_size + (self.alignment - 1)
        ) & ~(self.alignment - 1)

        # Create new sections

        if transform_info.data_size > 0:
            new_data_segment = Segment()
            new_data_segment.content = list(transform_info.all_data)
            new_data_segment.type = SEGMENT_TYPES.LOAD
            new_data_segment.alignment = self.alignment
            new_data_segment.flags = SEGMENT_FLAGS(SEGMENT_FLAGS.R | SEGMENT_FLAGS.W)
            new_data_segment = self.lief_binary.add(new_data_segment)

            transform_info.data_base = new_data_segment.virtual_address

            # Fix up offsets to they point to the actual address
            for label, addr in transform_info.data_offsets.items():
                transform_info.data_offsets[label] = (
                    cast(int, transform_info.data_base) + addr
                )

        if transform_info.code_size > 0:
            new_code_segment = Segment()
            new_code_segment.content = list(b"\x00" * transform_info.code_size)
            new_code_segment.type = SEGMENT_TYPES.LOAD
            new_code_segment.alignment = self.alignment
            new_code_segment.flags = SEGMENT_FLAGS(SEGMENT_FLAGS.X | SEGMENT_FLAGS.R)
            new_code_segment = self.lief_binary.add(new_code_segment)

            transform_info.code_base = new_code_segment.virtual_address

            # Fix up offsets to they point to the actual address
            for label, addr in transform_info.code_offsets.items():
                transform_info.code_offsets[label] = (
                    cast(int, transform_info.code_base) + addr
                )

            # Queue writes for code
            for label, code in self.code_to_add.items():
                self.writes.append(WriteOperation(code, label))

        # Reload the angr project to get the new sections
        self.reload_blob_from_lief()
        transform_info.lief_binary = self.lief_binary
        transform_info.angr_project = self.angr_project

        for write in self.writes:
            if isinstance(write.where, str):
                offset = transform_info.data_offsets.get(
                    write.where, transform_info.code_offsets.get(write.where, None)
                )
                if offset is None:
                    raise KeyError(f"Could not find offset for label {write.where}")

            elif isinstance(write.where, int):
                offset = write.where

            else:
                offset = write.where(transform_info)

            if isinstance(write.data, bytes):
                data = write.data

            elif isinstance(write.data, Code):

                write.data.reset()
                write.data.build(transform_info)
                data = write.data.compile(cast(str, write.data.label), transform_info)

                disassembly = self.angr_project.arch.disasm(data, offset)

                logger.debug(f"Disassembly of data for label {write.data.label}:")

                for disas_line in disassembly.splitlines():
                    logger.debug(f"  {disas_line}")
            else:
                data = write.data(transform_info.code_offsets)

            logger.info(f"Writing {len(data)} bytes to {offset:#0x}")
            self.lief_binary.patch_address(offset, list(data))

    def save(self, where: Path) -> None:
        """Apply any pending operations and save the binary to a file

        Args:
            where: The path to the destination to save the binary
        """
        logger.info("Applying pending operations")
        self.apply()

        logger.info(f"Saving binary to {where}")
        self.lief_binary.write(str(where.resolve()))

    def asm(self, asm: str, vaddr: int) -> bytes:
        """Assemble the given assembly code at the given virtual address

        Args:
            asm: The assembly code to assemble
            vaddr: The virtual address to assemble at
        """
        return self.cle_binary.arch.asm(asm, vaddr, as_bytes=True)  # type: ignore

    def disasm(self, vaddr: int) -> CsInsn:
        """Disassemble one instruction from the binary at an address

        Args:
            vaddr: The virtual address to disassemble at
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
