"""Write operation to be performed on a binary."""

from dataclasses import dataclass
from typing import Callable, List, Union, Dict

from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


@dataclass
class WriteOperation:
    """A write operation to be performed on a section

    Attributes:
        data: Either raw bytes or a function that takes the resolved
            labels for all patches and returns raw bytes
        vaddr: The virtual address or label location to write to
        where: The address to replace the code at, optional. This "address" can either
            be a label, an actual address, a list of addresses, a function that takes a
            [TransformInfo][TransformInfo] and returns an address, or a function that
            takes a [TransformInfo][TransformInfo] and returns a list of addresses.
    """

    data: Union[bytes, Callable[[Dict[str, int]], bytes], Code]
    where: Union[
        str,
        Callable[[TransformInfo], int],
        int,
        List[int],
        Callable[[TransformInfo], List[int]],
    ]
