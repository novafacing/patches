"""
Common types used by patches
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from lief import Binary

from pypatches.dynamic_info import DynamicInfo


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
class TransformInfo:
    """
    Information container used for transforming code based on context

    :attribute label_offsets: Dictionary of label: address of the addresses
        of each label added to the program
    :attribute text_offset: If the text section has moved, add this to any
        address that was in the text section to refer to it and reflect
        the movement
    """

    label_offsets: Dict[str, int]
    text_offset: int
    lief_binary: Binary
    new_code_segment_addr: int
    new_data_segment_addrs: List[int]


@dataclass
class PreTransformInfo:
    """
    Information container used for transforming code without context

    :attribute dynamic_info: Information about the plt/dynamic information
    """

    dynamic_info: DynamicInfo
    new_code_segment_base: int
    new_data_segment_addrs: List[int]


# A function that takes the code str (or bytes if raw) and the reloc and
# dynamic info if available and returns a new code str (or bytes if raw)
CodePreTransformFunctionType = Callable[
    [str, PreTransformInfo],
    str,
]
RawPreTransformFunctionType = Callable[
    [bytes, PreTransformInfo],
    bytes,
]
CodeTransformFunctionType = Callable[
    [str, TransformInfo],
    str,
]
RawTransformFunctionType = Callable[
    [bytes, TransformInfo],
    bytes,
]


@dataclass
class Code:
    """
    Code either in assembly, C, or already assembled bytes
    """

    assembly: Optional[str] = None
    c_code: Optional[str] = None
    raw: Optional[bytes] = None
    transform_asm: Optional[CodeTransformFunctionType] = None
    transform_c_code: Optional[CodeTransformFunctionType] = None
    transform_raw: Optional[RawTransformFunctionType] = None
    pretransform_asm: Optional[CodePreTransformFunctionType] = None
    pretransform_c_code: Optional[CodePreTransformFunctionType] = None
    pretransform_raw: Optional[RawPreTransformFunctionType] = None
    dynamic_info: Optional[DynamicInfo] = None
    original_assembly = None
    original_c_code = None
    original_raw = None

    def __post_init__(self) -> None:
        """
        Check that we got one of the above
        """
        self.original_assembly = self.assembly
        self.original_c_code = self.c_code
        self.original_raw = self.raw

        if self.assembly is None and self.c_code is None and self.raw is None:
            raise ValueError("No code was provided.")

    def reset(self) -> None:
        """
        Reset the code to its original state
        """
        self.assembly = self.original_assembly
        self.c_code = self.original_c_code
        self.raw = self.original_raw

    def pretransform(self, tinfo: PreTransformInfo) -> None:
        """
        Call a transformer function if one is present that modifies the current code

        :param tinfo: Pre-transformation information
        """
        if self.assembly is not None and self.pretransform_asm is not None:
            self.assembly = self.pretransform_asm(self.assembly, tinfo)

        if self.c_code is not None and self.pretransform_c_code is not None:
            self.c_code = self.pretransform_c_code(self.c_code, tinfo)

        if self.raw is not None and self.pretransform_raw is not None:
            self.raw = self.pretransform_raw(self.raw, tinfo)

    def transform(self, tinfo: TransformInfo) -> None:
        """
        Call a transformer function if one is present that modifies the current code
        using the label to address mapping provided

        :param tinfo: Transforminformation
        """
        if self.assembly is not None and self.transform_asm is not None:
            self.assembly = self.transform_asm(self.assembly, tinfo, self.dynamic_info)

        if self.c_code is not None and self.transform_c_code is not None:
            self.c_code = self.transform_c_code(self.c_code, tinfo, self.dynamic_info)

        if self.raw is not None and self.transform_raw is not None:
            self.raw = self.transform_raw(self.raw, tinfo, self.dynamic_info)

    @classmethod
    def build_c_code(
        cls,
        body: str,
        helpers: Optional[List[str]] = None,
        includes: Optional[List[str]] = None,
        extra_code: Optional[str] = None,
    ) -> str:
        """
        Build a C code snippet from a body of code.

        :param body: The body of the code to build, which will be wrapped in
            a main function and compiled.
        :param helpers: A list of filenames or paths to include into the program as helpers from
            `libs` like: `['liblink.c', 'libutil.c', 'libgetreg.c']
        :param includes: A list of include files like `["#include <stdint.h>", ...]`
        """
        code = ""

        if includes is not None:
            code = "\n".join(includes)
            code += "\n"

        if extra_code is not None:
            code += extra_code + "\n"

        if helpers is not None:
            for helper in helpers:
                lib_text = get_lib(helper)
                code += f"\n{lib_text}\n"

        code += """int main() {\n"""
        code += body + "\n"
        code += "}"

        return code
