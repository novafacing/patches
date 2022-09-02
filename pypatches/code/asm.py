"""ASM subclass for assembly code used in patches
"""

from typing import Optional, cast
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


class ASMCode(Code):
    """Assembly code container for patching

    Assembly code should be written in a format that can be assembled
    by keystone-engine. Generally, that means AT&T syntax for x86 and
    standard syntax for everything else.
    """

    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        """Assemble the assembly code to raw bytes of machine code.

        Args:
            label: The label to use for the code
            info: Optional transform info to use for the compilation

        Returns:
            The raw bytes of the compiled code
        """

        assert info is not None, "Must provide info for ASM compile"

        vaddr = info.code_offsets.get(label, 0)

        return cast(
            bytes,
            info.angr_project.arch.asm(self.code, vaddr, as_bytes=True),
        )
