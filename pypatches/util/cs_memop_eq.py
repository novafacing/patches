"""Check if two capstone MemOp objects are equal, since they don't
have a __eq__ method that works.
"""

from ctypes import Structure
from typing import Tuple

from capstone.arm import ArmOpMem
from capstone.arm64 import Arm64OpMem
from capstone.m68k import M68KOpMem
from capstone.mips import MipsOpMem
from capstone.ppc import PpcOpMem
from capstone.sparc import SparcOpMem
from capstone.systemz import SyszOpMem
from capstone.tms320c64x import TMS320C64xOpMem
from capstone.x86 import X86OpMem
from capstone.xcore import XcoreOpMem


def cs_memop_eq(first: Structure, second: Structure) -> bool:
    """Check equality of two memory operands

    Args:
        first: The first memory operand
        second: The second memory operand

    Returns:
        True if the memory operands are equal, False otherwise

    """
    # If they aren't the same subclass, they can't possibly be equal
    # in a memory operand sense
    if first.__class__.__name__ != second.__class__.__name__:
        return False

    check: Tuple[str, ...] = ()
    if isinstance(first, ArmOpMem):
        check = ("base", "index", "scale", "disp", "lshift")
    elif isinstance(first, M68KOpMem):
        check = (
            "base_reg",
            "index_reg",
            "in_base_reg",
            "in_disp",
            "out_disp",
            "disp",
            "scale",
        )
    elif isinstance(first, MipsOpMem):
        check = ("base", "disp")
    elif isinstance(first, Arm64OpMem):
        check = ("base", "index", "disp")
    elif isinstance(first, PpcOpMem):
        check = ("base", "disp")
    elif isinstance(first, X86OpMem):
        check = ("segment", "base", "index", "scale", "disp")
    elif isinstance(first, XcoreOpMem):
        check = ("base", "index", "disp", "direct")
    elif isinstance(first, TMS320C64xOpMem):
        check = ("base", "disp", "unit", "scaled", "disptype", "direction", "modify")
    elif isinstance(first, SparcOpMem):
        check = ("base", "index", "disp")
    elif isinstance(first, SyszOpMem):
        check = ("base", "index", "length", "disp")

    for attr in check:
        if getattr(first, attr) != getattr(second, attr):
            return False

    return True
