"""
Transform info
"""

from dataclasses import dataclass, field
from typing import Dict, Optional
from lief import Binary as LIEFBinary  # pylint: disable=no-name-in-module
from angr import Project


@dataclass
class TransformInfo:
    """
    Info for transform
    """

    lief_binary: LIEFBinary
    angr_project: Project

    code_base: int = 0
    code_size: int = 0
    data_base: int = 0
    data_size: int = 0
    code_offsets: Dict[str, int] = field(default_factory=dict)
    data_offsets: Dict[str, int] = field(default_factory=dict)
    all_data: bytes = b""
