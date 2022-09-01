"""
Superclass for all code types
"""

from pypatches.transform.info import TransformInfo
from abc import ABC
from typing import Callable, Optional, Union

default_dummy_transformer = lambda b: b
default_build_transformer = lambda t, b: b
default_post_transformer = lambda t, b: b


class Code(ABC):
    """
    Superclass for other code types defining required functions
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
        """
        Initialize the code object

        :param code: The code, to initialize with
        :param dummy_transformer: A function that takes this container's code and returns
            a valid compile/assemble-able code (see `self.dummy`)
        :param build_transformer: A function that takes a `TransformInfo` object and
            this container's code and returns valid and final compile/assemble-able
            code.
        :param post_transformer: A function that takes a `TransformInfo` object and
            the result of compiling this container's code to machine code bytes and
            returns a valid and final machine code byte string.
        """
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
        """
        Reset the code to its original state
        """
        self.code = self.original_code

    def dummy(self) -> None:
        """
        Generate valid dummy code to determine the size required to fit this code in the
        binary.


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

        :param dummy_transformer: A function that will be called with `self.code` as a
            parameter that should return the dummy code.
        """
        self.code = self.dummy_transformer(self.code)

    def build(self, info: TransformInfo) -> None:
        """
        Build the code into the final version that can be built with the binary context
        into the final patch.

        :param build_transformer: A function that will be called with `self.code` as a
            parameter that should return the final code.
        """
        self.code = self.build_transformer(info, self.code)

    def post_build(self, info: TransformInfo) -> bytes:
        """
        Modify the built code after compilation
        """
        return self.post_transformer(info, self.code)

    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        """
        Compile or assemble the code (or do not change it if raw)
        """
        raise NotImplementedError("Subclasses must implement compile()")
