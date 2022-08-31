"""
Transform info
"""

from dataclasses import dataclass
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

    code_base: Optional[int] = None
    code_size: Optional[int] = None
    data_base: Optional[int] = None
    data_size: Optional[int] = None
    code_offsets: Optional[Dict[str, int]] = None
    data_offsets: Optional[Dict[str, int]] = None
