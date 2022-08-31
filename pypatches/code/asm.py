"""
ASM type code
"""

from typing import Optional, cast
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


class ASMCode(Code):
    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:

        assert info is not None, "Must provide info for ASM compile"

        vaddr = info.code_offsets.get(label, 0)

        return cast(
            bytes,
            info.angr_project.arch.asm(self.code, vaddr, as_bytes=True),
        )
