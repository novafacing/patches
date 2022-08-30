"""
ASM type code
"""

from typing import cast
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


class ASMCode(Code):
    def compile(self, label: str, info: TransformInfo) -> bytes:
        return cast(
            bytes,
            info.angr_project.arch.asm(
                self.code, info.code_offsets.get(label), as_bytes=True
            ),
        )
