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
