"""
Patch descriptors for various types of patches

Patches require various parameters to specify how to apply them, but some are common.

`label`, if available, allows a label to be specified. In any later patch, that label
can be used to reference the location of that patch (this is especially useful for
data patches)
"""

from dataclasses import InitVar, dataclass, field
from typing import List, Optional, Set, Union

from pypatches.types import AddressRange, Code, ReturnValue, Value


@dataclass
class NopPatch:
    """
    Patch that converts specific addresses or ranges of addresses to no-operations
    """

    addresses: InitVar[Optional[List[int]]] = None
    address_ranges: Set[AddressRange] = field(default_factory=set)

    def __post_init__(self, addresses: Optional[List[int]]) -> None:
        """
        Convert optionally provided addresses to address ranges

        :param addresses: Addresses that can be provided in lieu of address ranges
        """
        if addresses is None:
            return

        for address in addresses:
            self.address_ranges.add(AddressRange(start=address, end=address))


@dataclass
class BranchPatch:
    """
    Base patch that modifies a conditional branch at a particular address
    """

    address: int


@dataclass
class InvertBranchPatch(BranchPatch):
    """
    Patch that inverts the true/false branch targets of a conditional branch
    """


@dataclass
class AlwaysBranchPatch(BranchPatch):
    """
    Patch that converts a conditional branch into an unconditional branch
    that always takes the "true" branch
    """


@dataclass
class NeverBranchPatch(BranchPatch):
    """
    Patch that converts a conditional branch into an unconditional branch
    that always takes the "false" branch
    """


@dataclass
class SkipAndReturnPatch:
    """
    Patch that skips a call to a subroutine at a particular address and
    fakes a return value as if the called function had returned it using
    the default calling convention
    """

    caller_address: int
    return_value: ReturnValue


@dataclass
class FunctionReplacePatch:
    """
    Patch that will replace a function's contents with new code
    """

    function_address: int
    new_code: Code


@dataclass
class CallerReplacePatch:
    """
    Patch that will redirect all or some callers of a function elsewhere
    """

    new_code: Code
    function_address: Optional[int] = None
    callers: Set[int] = field(default_factory=set)

    def __post_init__(self) -> None:
        """
        Check that we either got a function address or callers, or both
        """
        if self.function_address is None and not self.callers:
            raise ValueError(
                "A function address and/or set of callers must be provided."
            )


@dataclass
class InitPatch:
    """
    Patch that will run some code immediately on entry to the program
    """

    priority: int
    code: Code


@dataclass
class FiniPatch:
    """
    Patch that will run some code upon exit from the program
    """

    priority: int
    code: Code


@dataclass
class DataPatch:
    """
    Patch that adds some data with some protections
    """

    data: Value
    read: bool = True
    write: bool = False
    exec: bool = False
    label: Optional[str] = None


@dataclass
class CodePatch:
    """
    Patch that holds some code
    """

    code: Code


@dataclass
class AddCodePatch(CodePatch):
    """
    Patch that adds some code to the binary at some location
    """

    label: Optional[str] = None


@dataclass
class ReplaceCodePatch(CodePatch):
    """
    Patch that replaces some code with some other code
    """

    address: int


PatchType = Union[
    NopPatch,
    BranchPatch,
    InvertBranchPatch,
    AlwaysBranchPatch,
    NeverBranchPatch,
    SkipAndReturnPatch,
    FunctionReplacePatch,
    CallerReplacePatch,
    InitPatch,
    DataPatch,
    AddCodePatch,
    ReplaceCodePatch,
]
