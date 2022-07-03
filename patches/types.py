"""
Common types used by patches
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class TYPECLASS(str, Enum):
    """
    An enum representing various classes a type may be a member of
    """

    BASIC = "BASIC"
    POINTER = "POINTER"
    STRUCT = "STRUCT"
    UNION = "UNION"
    FUNCTION = "FUNCTION"


@dataclass
class Type:
    """
    Type representing a Type in a (C/ASM) type language
    """

    label: str
    size: int
    signed: bool = False
    typeclass: TYPECLASS = TYPECLASS.BASIC
    fields: List[Tuple[Optional[str], "Type"]] = field(default_factory=list)
    base: Optional["Type"] = None


@dataclass
class Value(Type):
    """
    Value of a given type, where the value is None if the type is a pointer
    """

    value: Optional[bytes] = None


@dataclass
class ReturnValue(Value):
    """
    A return value, which can be of any `Type` and its
    value
    """


@dataclass(frozen=True)
class AddressRange:
    """
    An address range with a start and end.
    If start == end, this address range is just one address
    """

    start: int
    end: int

    @property
    def address(self) -> bool:
        """
        Returns whether this range is "an address"
        """
        return self.start == self.end


@dataclass
class Code:
    """
    Code either in assembly, C, or already assembled bytes
    """

    assembly: Optional[str] = None
    c_code: Optional[str] = None
    raw: Optional[bytes] = None

    def __post_init__(self) -> None:
        """
        Check that we got one of the above
        """
        if self.assembly is None and self.c_code is None and self.raw is None:
            raise ValueError("No code was provided.")

    @classmethod
    def build_c_code(
        cls,
        body: str,
        getreg_helper: bool = True,
        includes: Optional[List[str]] = None,
    ) -> str:
        """
        Build a C code snippet from a body of code.

        :param body: The body of the code to build, which will be wrapped in
            a main function and compiled.
        :param getreg_helper: Whether to include the getreg helper macro that
            can be used by calling `getreg(variable_name, reg_name)` in the body
            of the function
        :param includes: A list of include files like `["#include <stdint.h>", ...]`
        """
        code = ""

        if includes is not None:
            code = "\n".join(includes)
            code += "\n"

        if getreg_helper:
            code += (
                """#define getreg(dest, src)  \\\n"""
                """    register long long dest __asm__ (#src); \\\n"""
                """    __asm__ ("" :"=r"(dest));\n"""
            )

        code += """__attribute__((annotate("shellvm-main"))) int main() {\n"""
        code += body + "\n"
        code += "}"

        return code
