from pypatches.code.code import Code
from pypatches.transform.info import TransformInfo


class RawCode(Code):
    def compile(self, label: str, info: TransformInfo) -> bytes:
        return self.code
