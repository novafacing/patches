"""
Main patcher utility
"""

from pathlib import Path
from re import sub
from typing import Dict, Optional, Union, cast

from archinfo import Arch

from pypatches.binary_manager import BinaryManager
from pypatches.patches import (
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
    ReplaceCodePatch,
    SkipAndReturnPatch,
)


class Patcher:
    """Patch processor, applies patches to the target binary

    Args:
        binary: Either a path to the target binary or the raw bytes
            of the binary
        cle_opts: An optional replacement set of options to pass to
            cle.Loader
    """

    def __init__(
        self,
        binary: Union[Path, str, bytes],
        cle_opts: Optional[Dict[str, bool]] = None,
    ) -> None:
        """Set up patcher with the target binary"""
        self.binary = BinaryManager(binary, cle_opts)

    def apply(self, patch: PatchType) -> None:
        """Apply a patch to the target binary

        Args:
            patch: The patch to apply, can be any of the patch types
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

    def save(self, path: Union[str, Path]) -> None:
        """
        Save the patched binary to the given path
        """
        if isinstance(path, str):
            path = Path(path)

        self.binary.save(path)

        path.chmod(0o755)

    def apply_nop_patch(self, patch: NopPatch) -> None:
        """
        Apply a nop patch to the target binary
        """
        nop_len = len(cast(Arch, self.binary.cle_binary.arch).nop_instruction)

        for address_range in patch.address_ranges:
            for address in range(
                address_range.start,
                max(address_range.end, address_range.start + nop_len),
                nop_len,
            ):
                self.binary.write(
                    address, cast(Arch, self.binary.cle_binary.arch).nop_instruction
                )

    def apply_invert_branch_patch(self, patch: InvertBranchPatch) -> None:
        """
        Apply a branch patch to the target binary
        """
        raise NotImplementedError("Branch patches are not supported.")

    def apply_always_branch_patch(self, patch: AlwaysBranchPatch) -> None:
        """
        Apply a branch patch to the target binary
        """

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
        self.binary.add_data(patch.data, patch.label)

    def apply_add_code_patch(self, patch: AddCodePatch) -> None:
        """
        Apply an add code patch to the target binary
        """
        self.binary.add_code(patch.code, patch.label)

    def apply_replace_code_patch(self, patch: ReplaceCodePatch) -> None:
        """
        Apply a replace code patch to the target binary
        """
        self.binary.write(patch.address, patch.code)
