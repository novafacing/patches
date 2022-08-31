"""
Code type for C code
"""

from typing import Callable, List, Optional, Union, cast

from pysquishy.squishy import Squishy
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo
from pypatches.util.libs.libs import get_lib


class CCode(Code):
    """
    C Code container
    """

    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        """
        Compile the C code
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
    """
    Build a C code snippet from a body of code.

    :param body: The body of the main function to build
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
    code += main_body + "\n"
    code += "}"

    return CCode(
        code,
        dummy_transformer=dummy_transformer,
        build_transformer=build_transformer,
        post_transformer=post_transformer,
    )
