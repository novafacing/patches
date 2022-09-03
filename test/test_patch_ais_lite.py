"""Test patches against AIS-Lite binary

The target of the test is:

```c
int cgc_parse_sentence(const char *buf, struct sentence_struct *ss);
```

from sentence.c
"""

from pathlib import Path
from typing import List

from logging import getLogger

from test.fixtures import bins
from pypatches.code.asm import ASMCode
from pypatches.patcher import Patcher
from pypatches.patches import AddCodePatch, ReplaceCodePatch
from pypatches.code import build_c_code
from pypatches.transform.info import TransformInfo


logger = getLogger(__name__)


def test_patch_ais_lite(bins) -> None:
    """Test patching AIS-Lite binary"""

    p = Patcher(bins.get("AIS-Lite.bin"))

    parse_sentence_patch = """
    struct sentence_struct {
        unsigned int frag_num;
        unsigned int frag_total;
        unsigned int session_id;
        char *p_ais_msg_idx;			// ptr to idx after last byte received in ais_msg
        unsigned char msg_status;		// ais message receive status (EMPTY, PARTIAL, DONE)
        unsigned char msg_type;			// ais message type
        char *ais_msg; // ASCII encoded ais message content
    };

    int cgc_parse_sentence(const char *buf, struct sentence_struct *ss) {
        _syscall3(SYS_read, 0, ss->frag_num, sizeof(ss->frag_num));
        _syscall3(SYS_read, 0, ss->frag_total, sizeof(ss->frag_total));
        _syscall3(SYS_read, 0, ss->session_id, sizeof(ss->session_id));
        size_t ais_msg_len = 0;
        _syscall3(SYS_read, 0, &ais_msg_len, sizeof(ais_msg_len));
        uint64_t rv = _syscall3(SYS_read, 0, ss->p_ais_msg_idx, ais_msg_len);
        ss->ais_msg = ss->p_ais_msg_idx;
        ss->p_ais_msg_idx += rv;
        return 0;
    }
    """

    main_code = """
    getreg(arg0, rdi);
    getreg(arg1, rsi);
    return cgc_parse_sentence((const char *)arg0, (struct sentence_struct *)arg1);
    """

    code = build_c_code(
        main_code,
        extra_code=parse_sentence_patch,
        helpers=["libgetreg.c", "libutil.c", "libsyscall.c"],
        includes=["#include <stddef.h>", "#include <stdint.h>", "#include <syscall.h>"],
    )

    acp = AddCodePatch(code, "cgc_parse_sentence")

    def find_cgc_parse_sentence_call_locations(tinfo: TransformInfo) -> List[int]:
        """
        Find all locations where cgc_parse_sentence is called
        """
        cgc_parse_sentence = tinfo.angr_project.kb.functions.get("cgc_parse_sentence")

        cfg = tinfo.angr_project.kb.cfgs.get_most_accurate()

        func_node = cfg.get_any_node(cgc_parse_sentence.addr)

        locs = []

        for predecessor, kind in func_node.predecessors_and_jumpkinds():
            if kind != "Ijk_Call":
                continue

            pred_block = predecessor.block

            if pred_block is not None and pred_block.vex.jumpkind == "Ijk_Call":
                locs.append(predecessor.block.disassembly.insns[-1].address)

        logger.debug(f"Found call locations: {', '.join(map(hex, locs))}")

        return locs

    def asm_build_transformer(tinfo: TransformInfo, asm: str) -> str:
        """
        Build the asm code at the call location(s)
        """

        call_offset = tinfo.current_offset
        logger.debug(f"Building asm code {asm} at {call_offset:#0x}")

        target_offset = tinfo.code_offsets.get("cgc_parse_sentence")
        logger.debug(f"Target offset: {target_offset:#0x}")

        return asm.format(cgc_parse_sentence=f"{target_offset-call_offset:#0x}")

    asm_code = ASMCode(
        """call {cgc_parse_sentence}""",
        dummy_transformer=lambda c: c.format(cgc_parse_sentence="0"),
        build_transformer=asm_build_transformer,
    )

    rcp = ReplaceCodePatch(asm_code, find_cgc_parse_sentence_call_locations)

    p.apply(acp)
    p.apply(rcp)

    p.save(Path(__file__).with_name("binaries") / "AIS-Lite" / "AIS-Lite.patched")
