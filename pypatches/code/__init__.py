"""Reexports of the code module.

This module reexports the code module to make it easier to import the code
from external modules.

"""

from pypatches.code.code import Code
from pypatches.code.c_code import CCode, build_c_code
from pypatches.code.asm import ASMCode
from pypatches.code.raw import RawCode
