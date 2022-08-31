from typing import Optional
from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


class RawCode(Code):
    def compile(self, label: str, info: Optional[TransformInfo] = None) -> bytes:
        return self.code
