"""Write operation to be performed on a binary."""

from dataclasses import dataclass
from typing import Callable, Union, Dict

from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


@dataclass
class WriteOperation:
    """A write operation to be performed on a section

    Attributes:
        data: Either raw bytes or a function that takes the resolved
        labels for all patches and returns raw bytes
        vaddr: The virtual address or label location to write to
    """

    data: Union[bytes, Callable[[Dict[str, int]], bytes], Code]
    where: Union[str, int, Callable[[TransformInfo], int]]
