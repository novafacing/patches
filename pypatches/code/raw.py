"""Raw machine code Code subclass"""

from typing import Optional
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


class RawCode(Code):
    """Raw code bytes

    Raw code is a container for raw bytes of machine code. It can be used to insert
    arbitrary machine code into a binary.
    """

    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        """Return the raw bytes of the code

        Args:
            label: The label to use for the code
            info: Optional transform info to use for the compilation

        Returns:
            The raw bytes of the code
        """
        return self.code
