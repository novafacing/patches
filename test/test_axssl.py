from test.fixtures import bins
from angr.errors import SimTranslationError

from pathlib import Path
from pypatches.patcher import Patcher
from pypatches.patches import AddCodePatch, ReplaceCodePatch, CallerReplacePatch
from pypatches.types import AddressRange, TransformInfo
from pypatches.types import Code


def test_axssl_patch(bins) -> None:
    """
    Test the patch against axssl
    """
    # Make a path to the binary
    bin = bins.get("axssl")

    # Create a patcher with the default options
    pat = Patcher(bin)

    # The patcher's `binary` attribute has the binary loaded with angr and LIEF:
    lief_bin = pat.binary.lief_binary
    angr_proj = pat.binary.angr_project

    extra_reface_code = """
                int retone() {
                    return 1;
                }
                """

    reface_code = """
                getreg(arg3, r10);
                // read(0, (char*)arg3, (int)(arg3+8));
                int a = retone();
                return a;
                """

    # Create a wrapper patch -- the below code will be placed into a function body, compiled, and mapped
    # as an executable segment and can be referenced from the "reinterfaced_func" label
    reface_func = Code(
        c_code=Code.build_c_code(
            reface_code,
            includes=["#include <unistd.h>"],
            getreg_helper=True,
            extra_code=extra_reface_code,
        ),
    )
    reface_addfunc_patch = AddCodePatch(reface_func, label="reinterfaced_func")

    # define a set of call sites to patch for a given target function
    callers = set()
    for func in angr_proj.kb.functions.values():
        for block in func.blocks:
            try:
                if block.vex.jumpkind == "Ijk_Call":
                    jts = block.vex.constant_jump_targets
                    try:
                        target = next(iter(jts))

                        if angr_proj.kb.functions.get(target).name == "pem_decrypt":
                            insn = block.disassembly.insns[-1]
                            callers.add(insn.address)
                    except (StopIteration, AttributeError):
                        continue
            except SimTranslationError:
                continue

    patches = []
    for caller in callers:

        def transformer(asm: str, tinfo: TransformInfo) -> str:
            offset_to = (
                tinfo.label_offsets.get("reinterfaced_func")
                - caller
                - tinfo.text_offset
            )
            return asm.format(reinterfaced_func=f"{offset_to:#0x}")

        patches.append(
            ReplaceCodePatch(
                Code(
                    assembly="call {reinterfaced_func};",
                    transform_asm=transformer,
                ),
                address=caller,
            )
        )

    pat.apply(reface_addfunc_patch)
    for p in patches:
        pat.apply(p)

    pat.save(bin.with_suffix(".patched"))
