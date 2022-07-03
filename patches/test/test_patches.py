# pylint: disable=redefined-outer-name, unused-import
"""
Tests for the various types of patches

Generally, patches should be figured out dynamically instead of hard coding the address
ranges or anything like that to allow the tests to be built on various systems and
tested on them as well
"""

from ast import main
from subprocess import run
from typing import Optional, Tuple, cast
from patches.test.fixtures import BINARIES_DIR, bins
from patches.patches import AddCodePatch, NopPatch
from patches.patcher import Patcher
from patches.types import AddressRange, Code

from angr import Block, Project
from angr.knowledge_plugins.functions.function import Function
from capstone.x86_const import (
    X86_REG_RAX,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_EAX,
    X86_REG_AX,
)
from capstone import CS_OP_REG, CS_OP_MEM

from patches.util.cs_memop_eq import cs_memop_eq


def test_nop_patch(bins) -> None:
    """
    Make sure nop patch can be applied
    """
    print_twice = bins.get("print_twice.bin")
    assert print_twice is not None
    p = Patcher(print_twice)
    proj = p.binary.angr_project
    mutate_func = cast(
        Function, proj.kb.functions.get(proj.loader.find_symbol("mutate").rebased_addr)
    )
    main_func = cast(
        Function, proj.kb.functions.get(proj.loader.find_symbol("main").rebased_addr)
    )
    vrf = proj.analyses.VariableRecoveryFast(main_func)
    vm = vrf.variable_manager[main_func.addr]

    ranges = set()
    for block in mutate_func.blocks:
        if block.vex.jumpkind == "Ijk_Call" and any(
            map(
                lambda a: proj.kb.functions.get(a).name == "memcpy",
                block.vex.constant_jump_targets,
            )
        ):
            ranges.add(
                AddressRange(
                    block.disassembly.insns[-1].address,
                    block.disassembly.insns[-1].address
                    + block.disassembly.insns[-1].size,
                )
            )

    assign_ret_source = None
    try:
        for block in reversed(list(main_func.blocks)):
            for instr in reversed(block.disassembly.insns):
                if (
                    instr.operands
                    and instr.operands[0].type == CS_OP_REG
                    and instr.operands[0].value.reg
                    in (X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AH, X86_REG_AL)
                ):
                    # Figure out where the last assign to RAX is and get the source
                    # of the assignment
                    assign_ret_source = instr.operands[1]

                if (
                    assign_ret_source is not None
                    and instr.operands
                    and instr.operands[0].type == CS_OP_MEM
                    and cs_memop_eq(instr.operands[0], assign_ret_source)
                ):
                    # Figure out where the last assign to where the return value is stored
                    # is and add a nop patch to it
                    ranges.add(
                        AddressRange(
                            instr.address,
                            instr.address + instr.size,
                        )
                    )
                    raise StopIteration()

    except StopIteration:
        pass

    np = NopPatch(address_ranges=ranges)
    print(np)
    p.apply(np)
    p.save(BINARIES_DIR / "print_twice_nop.bin")
    res = run([str(BINARIES_DIR / "print_twice_nop.bin")], capture_output=True)
    assert (
        res.stdout
        == b"""Hello, world!
Goodbye, world!
Hello, World!
"""
    )
    assert res.returncode == 1


def test_add_code_patch(bins) -> None:
    """
    Make sure nop patch can be applied
    """
    print_twice = bins.get("print_twice.bin")
    assert print_twice is not None
    p = Patcher(print_twice)
    acp = AddCodePatch(
        Code(
            c_code=Code.build_c_code(
                """
                getreg(arg0, rdi);
                getreg(arg1, rsi);
                getreg(arg2, rdx);
                for (size_t i = 0; i < arg2; i++) {
                    ((char *) arg0)[i] = ((char *) arg1)[arg2 - i - 1];
                }""",
                getreg_helper=True,
                includes=["#include <stdint.h>", "#include <stddef.h>"],
            )
        ),
        label="retone",
    )
    p.apply(acp)
    p.save(BINARIES_DIR / "print_twice_add_code.bin")
    proj = Project(
        str(BINARIES_DIR / "print_twice_add_code.bin"),
        main_opts={"base_addr": p.binary.lief_binary.imagebase},
        auto_load_libs=False,
    )
    for segment in proj.loader.main_object.segments:
        if segment.vaddr == 0xD000:
            break
    else:
        raise AssertionError("Could not find expected code segment at 0xd000!")
