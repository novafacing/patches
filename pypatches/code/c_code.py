"""
Code type for C code
"""

from typing import Callable, List, Optional, Union, cast

from pysquishy.squishy import Squishy
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo
from pypatches.util.libs.libs import get_lib


class CCode(Code):
    """C code container for patching

    C code should be written such that it can be compiled by
    [squishy](https://github.com/novafacing/squishy). Generally, that means that the
    `inline` keyword should not be used, code should be written as C99-like as possible,
    and that most importantly external library calls must not be used. However, you can
    write code that uses system headers using the `#include <...>` syntax, and you can
    use data structures and macros from those headers.
    """

    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        """Compile the C code to raw machine code bytes

        Args:
            label: The label to use for the code
            info: Optional transform info to use for the compilation

        Returns:
            The raw bytes of the compiled code
        """
        return cast(bytes, Squishy().compile(self.code))


def build_c_code(
    main_body: str,
    helpers: Optional[List[str]] = None,
    includes: Optional[List[str]] = None,
    extra_code: Optional[str] = None,
    dummy_transformer: Optional[
        Callable[[Union[str, bytes]], Union[str, bytes]]
    ] = None,
    build_transformer: Optional[
        Callable[[TransformInfo, Union[str, bytes]], Union[str, bytes]]
    ] = None,
    post_transformer: Optional[Callable[[TransformInfo, bytes], bytes]] = None,
) -> CCode:
    """Build a C code snippet a main body, helpers, and include files

    Generally, you should use this function instead of manually creating a
    [CCode][pypatches.code.c_code.CCode] object manually.

    Args:
        main_body: The body of the main function to build, do not include `int main(){`
            or `}`
        helpers: A list of filenames or paths to include into the program as helpers from
            `libs` like: `['liblink.c', 'libutil.c', 'libgetreg.c']. Some of these
            helpers are provided, and you can use them without a full path. The helpers
            included are:
            - `liblink.c`: A library for linking to other functions and calling library
                functions
            - `libutil.c`: A library for utility functions prefixed with `_` like
                `_strcpy` and `_strlen`
            - `libgetreg.c`: A library for getting the value of a register
            - `libsyscall.c`: A library for calling system calls
            - `libgetbase.c`: A library for getting the base address of the binary
                (note libgetbase.c requires libsyscall.c)
        includes: A list of include files like `["#include <stdint.h>", ...]`
        extra_code: Extra code to include in the program at global scope, write any
            functions you want to use in `main_body` here
        dummy_transformer: A function that is passed [self.code](#code) and returns a
            string of code to use for the dummy compilation. The result must compile but
            is not the code that will be inserted into the final patched binary, it is
            only used to obtain a size estimate. If not provided, the default is to
            return [self.code](#code) unchanged.
        build_transformer: A function that is passed
            [self.code][pypatches.code.code.Code.code] and returns a
            string of code to use for the final compilation. The result must compile and
            will be inserted into the final patched binary. If not provided, the code
            will be passed through unchanged.
        post_transformer: A function that is passed the compiled code and returns the
            final bytes to use for the patch. This is useful for doing things like
            padding the code to a certain size. If not provided, the result of
            compilation will be used unchanged.
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
    code += main_body + "\n"
    code += "}"

    return CCode(
        code,
        dummy_transformer=dummy_transformer,
        build_transformer=build_transformer,
        post_transformer=post_transformer,
    )
