"""Transform info
"""

from dataclasses import dataclass, field
from typing import Dict
from lief import Binary as LIEFBinary  # pylint: disable=no-name-in-module
from angr import Project


@dataclass
class TransformInfo:
    """Info for transformations of [Code][pypatches.code.code.Code] objects

    Attributes:
        lief_binary: The lief binary for the binary
        angr_project: The angr project for the binary
        code_base: The base address of the code in the binary
        code_size: The size of the code in the binary
        code_offsets: A dictionary mapping labels to offsets in the binary
        data_base: The base address of the data in the binary
        data_size: The size of the data in the binary
        data_offsets: A dictionary mapping labels to offsets in the binary
    """

    lief_binary: LIEFBinary
    angr_project: Project

    code_base: int = 0
    code_size: int = 0
    code_offsets: Dict[str, int] = field(default_factory=dict)
    data_base: int = 0
    data_size: int = 0
    data_offsets: Dict[str, int] = field(default_factory=dict)
    all_data: bytes = b""
