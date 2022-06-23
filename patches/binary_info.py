"""
Binary program wrapper
"""

from io import BytesIO
from json import load
from pathlib import Path
from typing import Dict, Optional, Union, cast

from lief import parse, Binary as LIEFBinary  # pylint: disable=no-name-in-module

from cle.loader import Loader


class BinaryInfo:
    """
    Wrapper for a binary program to provide information for patching
    """

    path: Optional[Path] = None
    blob: Optional[BytesIO] = None
    lief_binary: Optional[LIEFBinary] = None
    cle_binary: Optional[Loader] = None
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
            )
        else:
            self.lief_binary = parse(str(self.path))
            self.cle_binary = Loader(  # type: ignore
                str(self.path),
                **self.cle_opts,
            )
