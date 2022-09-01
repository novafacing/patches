# pylint: disable=redefined-outer-name, unused-import
"""
Tests for the various types of patches

Generally, patches should be figured out dynamically instead of hard coding the address
ranges or anything like that to allow the tests to be built on various systems and
tested on them as well
"""

from distutils.command.build import build
from subprocess import run
from typing import Optional, Tuple, cast
from pypatches.address_range import AddressRange
from test.fixtures import BINARIES_DIR, bins
from pypatches.patches import AddCodePatch, NopPatch, ReplaceCodePatch
from pypatches.patcher import Patcher
from pypatches.code.code import Code
from pypatches.code.asm import ASMCode
from pypatches.transform.info import TransformInfo

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
from ptpython.repl import embed

from pypatches.util.cs_memop_eq import cs_memop_eq
from pypatches.code.c_code import build_c_code
from logging import getLogger

logger = getLogger(__name__)


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

    ranges = set()
    for block in mutate_func.blocks:
        if block.vex.jumpkind == "Ijk_Call":
            ranges.add(
                AddressRange(
                    block.disassembly.insns[-1].address,
                    block.disassembly.insns[-1].address
                    + block.disassembly.insns[-1].size,
                )
            )

    assert ranges, "No memcpy calls found in mutate function"

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
    Make sure we can add code to a binary
    """
    print_twice = bins.get("print_twice.bin")
    assert print_twice is not None
    p = Patcher(print_twice)
    acp = AddCodePatch(
        build_c_code(
            """
            getreg(arg0, rdi);
            getreg(arg1, rsi);
            getreg(arg2, rdx);
            for (size_t i = 0; i < arg2; i++) {
                ((char *) arg0)[i] = ((char *) arg1)[arg2 - i - 1];
            }""",
            helpers=["libgetreg.c"],
            includes=["#include <stdint.h>", "#include <stddef.h>"],
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
        if segment.vaddr == 0xF000:
            break
    else:
        raise AssertionError("Could not find expected code segment at 0xd000!")


def test_add_code_and_replace_code(bins) -> None:
    """
    Add code to a binary, replace a call to one function with a call to the added
    code, and make sure the output is what we expect (reversed, because we replaced
    a call to memcpy with a call to our memcpy that copies backward)
    """
    print_twice = bins.get("print_twice.bin")
    assert print_twice is not None
    p = Patcher(print_twice)
    acp = AddCodePatch(
        build_c_code(
            """
            getreg(arg0, rdi);
            getreg(arg1, rsi);
            getreg(arg2, rdx);
            // Memcpy the data backward
            for (size_t i = 0; i < arg2; i++) {
                ((char *) arg0)[i] = ((char *) arg1)[arg2 - i - 1];
            }""",
            helpers=["libgetreg.c"],
            includes=["#include <stdint.h>", "#include <stddef.h>"],
        ),
        label="rev_memcpy",
    )

    def address_fixup(tinfo: TransformInfo) -> int:
        """
        Figure out where memcpy is called and use that as the address to write our
        code to

        :param tinfo: The transform info object after segment modification
        """
        proj = tinfo.angr_project
        mutate_func = cast(
            Function,
            proj.kb.functions.get(proj.loader.find_symbol("mutate").rebased_addr),
        )
        assert mutate_func is not None, "No mutate function found"
        memcpy_call_addr = None

        memcpy_call_addr = list(mutate_func.blocks)[-2].disassembly.insns[-1].address

        assert memcpy_call_addr is not None, "No memcpy call found"

        logger.info(f"Found memcpy call at {memcpy_call_addr:#0x}")

        return memcpy_call_addr

    def transformer(tinfo: TransformInfo, asm: str) -> str:
        """
        Transform the format string with the program context

        :param asm: The original asm string
        :param tinfo: The program context information
        """
        proj = tinfo.angr_project
        mutate_func = cast(
            Function,
            proj.kb.functions.get(proj.loader.find_symbol("mutate").rebased_addr),
        )
        assert mutate_func is not None, "No mutate function found"
        memcpy_call_addr = None

        memcpy_call_addr = list(mutate_func.blocks)[-2].disassembly.insns[-1].address

        assert memcpy_call_addr is not None, "No memcpy call found"

        logger.info(f"Found memcpy call at {memcpy_call_addr:#0x}")

        offset_to = tinfo.code_offsets.get("rev_memcpy") - memcpy_call_addr

        return asm.format(rev_memcpy=f"{offset_to:#0x}")

    rcp = ReplaceCodePatch(
        ASMCode(
            code="call {rev_memcpy};",
            dummy_transformer=lambda asm: asm.format(rev_memcpy=0),
            build_transformer=transformer,
        ),
        address=address_fixup,
    )

    p.apply(acp)
    p.apply(rcp)
    p.save(BINARIES_DIR / "print_twice_add_code_and_replace.bin")
    res = run(
        [str(BINARIES_DIR / "print_twice_add_code_and_replace.bin")],
        capture_output=True,
    )
    assert (
        res.stdout
        == b"""Hello, world!
Goodbye, world!
!slriG ,olleH
"""
    )
