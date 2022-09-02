"""
Patch descriptors for various types of patches

Patches require various parameters to specify how to apply them, but some are common.

`label`, if available, allows a label to be specified. In any later patch, that label
can be used to reference the location of that patch (this is especially useful for
data patches)
"""

from dataclasses import InitVar, dataclass, field
from typing import List, Optional, Set, Union
from pypatches.code.code import Code
from pypatches.address_range import AddressRange


@dataclass
class NopPatch:
    """Patch that converts specific addresses or ranges of addresses to no-operations

    Attributes:
        address_ranges: The address ranges to convert to no-operations

    Args:
        addresses: Individual addresses to convert to no-operations, optional.
        address_ranges: The address ranges to convert to no-operations, optional.

    """

    addresses: InitVar[Optional[List[int]]] = None
    address_ranges: Set[AddressRange] = field(default_factory=set)

    def __post_init__(self, addresses: Optional[List[int]]) -> None:
        """Convert optionally provided addresses to address ranges

        Args:
            addresses: Addresses that can be provided in lieu of address ranges
        """
        if addresses is None:
            return

        for address in addresses:
            self.address_ranges.add(AddressRange(start=address, end=address))


@dataclass
class BranchPatch:
    """Base patch that modifies a conditional branch at a particular address

    Attributes:
        address: The address of the branch to modify
    """

    address: int


@dataclass
class InvertBranchPatch(BranchPatch):
    """Patch that inverts the true/false branch targets of a conditional branch"""


@dataclass
class AlwaysBranchPatch(BranchPatch):
    """Patch that converts a conditional branch into an unconditional branch
    that always takes the "true" branch
    """


@dataclass
class NeverBranchPatch(BranchPatch):
    """Patch that converts a conditional branch into an unconditional branch
    that always takes the "false" branch
    """


@dataclass
class SkipAndReturnPatch:
    """Patch that skips a call to a subroutine at a particular address and
    fakes a return value as if the called function had returned it using
    the default calling convention

    Attributes:
        address: The address of the call to skip
        return_value: The value to return from the call
    """

    caller_address: int
    return_value: int


@dataclass
class FunctionReplacePatch:
    """Patch that will replace a function's contents with new code

    Attributes:
        function_address: The name of the function to replace
        new_code: The new code to replace the function with
    """

    function_address: int
    new_code: Code


@dataclass
class CallerReplacePatch:
    """Patch that will redirect all or some callers of a function elsewhere

    Attributes:
        new_code: The new code to replace the function with
        function_address: The name of the function to replace
        callers: The set of callers to redirect, optional

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
    """Patch that will run some code immediately on entry to the program

    Attributes:
        code: The code to run
        priority: The priority of the code to run, optional
    """

    code: Code
    priority: int = 0


@dataclass
class FiniPatch:
    """Patch that will run some code upon exit from the program

    Attributes:
        code: The code to run
        priority: The priority of the code to run, optional
    """

    code: Code
    priority: int = 0


@dataclass
class DataPatch:
    """Patch that adds some data with some protections

    Attributes:
        data: The data to add
        label: The label to give the data, optional
        read: Whether the data should be readable, defaults to True
        write: Whether the data should be writable, defaults to False
        execute: Whether the data should be executable, defaults to False
    """

    data: bytes
    read: bool = True
    write: bool = False
    exec: bool = False
    label: Optional[str] = None


@dataclass
class CodePatch:
    """Base patch that holds some code

    Attributes:
        code: The code to add

    """

    code: Code


@dataclass
class AddCodePatch(CodePatch):
    """Patch that adds some code to the binary at some labeled location

    Attributes:
        label: The label to add the code at
    """

    label: Optional[str] = None


@dataclass
class ReplaceCodePatch(CodePatch):
    """Patch that replaces some code with some other code

    Attributes:
        address: The address to replace the code at, optional

    """

    address: Optional[int] = None


@dataclass
class RuntimeResolverPatch(CodePatch):
    """Patch that adds a runtime resolver to the binary"""


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
