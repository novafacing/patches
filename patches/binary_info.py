"""
Binary program wrapper
"""

from io import BytesIO
from pathlib import Path
from typing import Dict, Optional, Union, cast
from logging import getLogger

from lief import parse, Binary as LIEFBinary  # pylint: disable=no-name-in-module

from cle.backends import Backend
from cle.loader import Loader

from patches.error import NoSectionError

logger = getLogger(__name__)


class BinaryInfo:
    """
    Wrapper for a binary program to provide information for patching
    """

    path: Optional[Path] = None
    blob: BytesIO
    lief_binary: LIEFBinary
    cle_binary: Backend
    cle_opts: Dict[str, bool] = {
        "auto_load_libs": False,
        "use_system_libs": False,
    }

    def __init__(
        self,
        binary: Union[Path, str, bytes],
        cle_opts: Optional[Dict[str, bool]] = None,
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

        if self.path is None:
            self.blob = BytesIO(cast(bytes, binary))
            self.lief_binary = parse(binary)
            self.cle_binary = Loader(  # type: ignore
                self.blob,
                **self.cle_opts,
            ).main_object
        else:
            self.blob = BytesIO(self.path.read_bytes())
            self.lief_binary = parse(str(self.path))
            self.cle_binary = Loader(  # type: ignore
                str(self.path),
                **self.cle_opts,
            ).main_object

    def write(self, vaddr: int, data: bytes) -> None:
        """
        Write data to the binary at the given virtual address
        """
        try:
            section = next(
                filter(lambda s: s.contains_addr(vaddr), self.cle_binary.sections)
            )
        except StopIteration as e:
            logger.error(f"Could not find section for address {vaddr}")
            raise NoSectionError(f"Could not find section for address {vaddr}") from e

        self.blob.seek(section.addr_to_offset(vaddr))
        self.blob.write(data)

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

    def asm(self, asm: str, vaddr: int) -> bytes:
        """
        Assemble the given assembly code at the given virtual address
        """
        return self.cle_binary.arch.asm(asm, vaddr, as_bytes=True)

    def add_space(
        self, size: int, readable: bool, writable: bool, executable: bool
    ) -> int:
        """
        Add space to the binary and return the virtual address where it was added
        """
        raise NotImplemented("add_space is not implemented")
