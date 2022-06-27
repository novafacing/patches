"""
Main patcher utility
"""

from pathlib import Path
from typing import Dict, Optional, Union
from re import sub
from patches.binary_info import BinaryInfo
from patches.patches import (
    AddCodePatch,
    AlwaysBranchPatch,
    CallerReplacePatch,
    DataPatch,
    FiniPatch,
    FunctionReplacePatch,
    InitPatch,
    InvertBranchPatch,
    NeverBranchPatch,
    NopPatch,
    PatchType,
    SkipAndReturnPatch,
)


class Patcher:
    """
    Patch processor, actually applies patches to the target binary
    """

    def __init__(
        self,
        binary: Union[Path, str, bytes],
        cle_opts: Optional[Dict[str, bool]] = None,
    ) -> None:
        """
        Set up patcher with the target binary
        """
        self.binary = BinaryInfo(binary, cle_opts)

    def apply(self, patch: PatchType) -> None:
        """
        Apply a patch to the target binary
        """

        def camel_to_snake(name: str) -> str:
            """
            Convert a camel case string to snake case
            """
            name = sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
            return sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()

        patch_dispatch_func_name = f"apply_{camel_to_snake(patch.__class__.__name__)}"
        if not hasattr(self, patch_dispatch_func_name):
            raise NotImplementedError(
                f"Patch type {patch.__class__.__name__} is not supported."
            )

        patch_dispatch_func = getattr(self, patch_dispatch_func_name)
        patch_dispatch_func(patch)

    def apply_nop_patch(self, patch: NopPatch) -> None:
        """
        Apply a nop patch to the target binary
        """
        raise NotImplementedError("Nop patches are not supported.")

    def apply_invert_branch_patch(self, patch: InvertBranchPatch) -> None:
        """
        Apply a branch patch to the target binary
        """
        raise NotImplementedError("Branch patches are not supported.")

    def apply_always_branch_patch(self, patch: AlwaysBranchPatch) -> None:
        """
        Apply a branch patch to the target binary
        """
        raise NotImplementedError("Branch patches are not supported.")

    def apply_never_branch_patch(self, patch: NeverBranchPatch) -> None:
        """
        Apply a branch patch to the target binary
        """
        raise NotImplementedError("Branch patches are not supported.")

    def apply_skip_and_return_patch(self, patch: SkipAndReturnPatch) -> None:
        """
        Apply a branch patch to the target binary
        """
        raise NotImplementedError("Branch patches are not supported.")

    def apply_function_replace_patch(self, patch: FunctionReplacePatch) -> None:
        """
        Apply a function replace patch to the target binary
        """
        raise NotImplementedError("Function replace patches are not supported.")

    def apply_caller_replace_patch(self, patch: CallerReplacePatch) -> None:
        """
        Apply a caller replace patch to the target binary
        """
        raise NotImplementedError("Caller replace patches are not supported.")

    def apply_init_patch(self, patch: InitPatch) -> None:
        """
        Apply an init patch to the target binary
        """
        raise NotImplementedError("Init patches are not supported.")

    def apply_fini_patch(self, patch: FiniPatch) -> None:
        """
        Apply a fini patch to the target binary
        """
        raise NotImplementedError("Fini patches are not supported.")

    def apply_data_patch(self, patch: DataPatch) -> None:
        """
        Apply a data patch to the target binary
        """
        raise NotImplementedError("Data patches are not supported.")

    def apply_add_code_patch(self, patch: AddCodePatch) -> None:
        """
        Apply an add code patch to the target binary
        """
        raise NotImplementedError("Add code patches are not supported.")
