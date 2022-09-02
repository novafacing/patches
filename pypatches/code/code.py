"""Superclass for all code types
"""

from pypatches.transform.info import TransformInfo
from abc import ABC
from typing import Callable, Optional, Union

default_dummy_transformer = lambda b: b
default_build_transformer = lambda t, b: b
default_post_transformer = lambda t, b: b


class Code(ABC):
    """Superclass for other code types defining required functions

    Code objects are used to represent code that can be compiled or assembled into
    machine code. The code object is used to represent the code in a way that can be
    modified by the patching process, and then compiled or assembled into machine code
    for insertion into the binary.

    Generally, each code object goes through the following life cycle:
    - [dummy][pypatches.code.code.Code.dummy] is called to generate a dummy version of
        the code that can be used
        to estimate the size of the code in the binary.
    - [build][pypatches.code.code.Code.build] is called to generate the final version of
        the code that will be
        compiled or assembled.
    - [compile][pypatches.code.code.Code.compile] is called to compile or assemble the
        code into machine code
        bytes.
    - [post_build][pypatches.code.code.Code.post_build] is called to modify the compiled
        code after compilation
        (for example, to add a jump to the end of the code).

    Attributes:
        code (str): The code to be compiled or assembled
        original_code (str): The original code, before any modifications
        dummy_transformer (Callable[[str], str]): A function that takes this container's
            code and returns a valid compile/assemble-able code (see `self.dummy`)
        build_transformer (Callable[[TransformInfo, str], str]): A function that takes a
            `TransformInfo` object and this container's code and returns valid and final
            compile/assemble-able code.
        post_transformer (Callable[[TransformInfo, bytes], bytes]): A function that
            takes
            a `TransformInfo` object and the result of compiling this container's code
            to
            machine code bytes and returns a valid and final machine code byte string.

    Args:
        code (str): The code, to initialize with
        dummy_transformer (Callable[[str], str]): A function that takes this container's
            code and returns a valid compile/assemble-able code (see `self.dummy`),
            optional. Defaults to a function that returns the code unchanged.
        build_transformer (Callable[[TransformInfo, str], str]): A function that takes a
            `TransformInfo` object and this container's code and returns valid and final
            compile/assemble-able code, optional. Defaults to a function that returns
            the code unchanged.
        post_transformer (Callable[[TransformInfo, bytes], bytes]): A function that
            takes a `TransformInfo` object and the result of compiling this container's
            code to machine code bytes and returns a valid and final machine code byte
            string, optional. Defaults to a function that returns the compiled code
            unchanged.
    """

    code: Union[str, bytes]
    original_code: Union[str, bytes]
    label: Optional[str] = None

    def __init__(
        self,
        code: Union[str, bytes],
        dummy_transformer: Optional[
            Callable[[Union[str, bytes]], Union[str, bytes]]
        ] = None,
        build_transformer: Optional[
            Callable[[TransformInfo, Union[str, bytes]], Union[str, bytes]]
        ] = None,
        post_transformer: Optional[Callable[[TransformInfo, bytes], bytes]] = None,
    ) -> None:
        """Initialize the Code object"""
        self.code = code
        self.original_code = self.code

        self.dummy_transformer = (
            dummy_transformer
            if dummy_transformer is not None
            else default_dummy_transformer
        )

        self.build_transformer = (
            build_transformer
            if build_transformer is not None
            else default_build_transformer
        )

        self.post_transformer = (
            post_transformer
            if post_transformer is not None
            else default_post_transformer
        )

    def reset(self) -> None:
        """Reset the code to its original state without any modifications"""
        self.code = self.original_code

    def dummy(self) -> None:
        """Generate valid dummy code to determine the size required to fit this code in
        the binary.


        This function will be called to create a dummy result from the code -- the dummy
        result should be valid code (ie if this Code instance is C code it should
        compile, and if it is assembly it should assemble) but is not necessarily
        the correct code to go into the final patch.

        For example, a code snippet:

        ```
        int get_data(void) {
            return {DATA_VALUE};
        }
        ```

        might have a "dummy" result of:

        ```
        int get_data(void) {
            return 0x41414141;
        }
        ```

        The code returned by this function will never be used to produce a binary, only
        to estimate the required size for segment insertion.
        """
        self.code = self.dummy_transformer(self.code)

    def build(self, info: TransformInfo) -> None:
        """Build the code into the final version that can be built with the binary
        context into the final patch.

        Args:
            info: The `TransformInfo` object containing information about the current
                patching context.
        """
        self.code = self.build_transformer(info, self.code)

    def post_build(self, info: TransformInfo) -> bytes:
        """Modify the built code after compilation

        Args:
            info: The `TransformInfo` object containing information about the current
                patching context.

        """
        return self.post_transformer(info, self.code)

    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        """Compile or assemble the code (or do not change it if raw)

        Args:
            label: The label to use for this code
            info: The `TransformInfo` object to use for this code
        """
        raise NotImplementedError("Subclasses must implement compile()")
