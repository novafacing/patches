"""
Test symbol resolution in a patch
"""
from pathlib import Path
from pypatches.dynamic_info import DynamicInfo
from pypatches.patcher import Patcher
from pypatches.patches import AddCodePatch, ReplaceCodePatch
from pypatches.types import Code, PreTransformInfo, TransformInfo
from test.fixtures import BINARIES_DIR, bins
from logging import getLogger

logger = getLogger(__name__)


def test_get_link_map(bins) -> None:
    """
    Test symbol resolution in a patch
    """
    print_twice = bins.get("print_twice.bin")
    assert print_twice is not None
    p = Patcher(print_twice)

    def c_pretransformer(code: str, ptinfo: PreTransformInfo) -> str:
        """
        Replace the link map address with the real address
        """
        logger.debug(f"Transforming {code} with {ptinfo}")
        result = (
            code.replace(
                # Don't actually do it like this in real patcher code
                "{gotplt_offset}",
                f"{ptinfo.dynamic_info.gotplt_addr:#0x}",
            )
            .replace("{plt_offset}", f"{ptinfo.dynamic_info.plt_addr:#0x}")
            .replace("{link_map_addr}", f"{ptinfo.dynamic_info.link_map_addr:#0x}")
            .replace(
                "{dl_runtime_resolve_addr}",
                f"{ptinfo.dynamic_info.dl_runtime_resolve_addr:#0x}",
            )
            .replace(
                "{new_segment_base}",
                f"{ptinfo.new_code_segment_base:#0x}",
            )
            .replace("{has_rela}", "1" if ptinfo.dynamic_info.has_rela else "0")
            .replace("{data_segment_address}", f"{ptinfo.new_data_segment_addrs[0]}")
        )
        logger.debug(f"Transformed to {result}")
        return result

    acp = AddCodePatch(
        Code(
            c_code=Code.build_c_code(
                """
                // Link map struct was grabbed with:
                // clang -I string -I sysdeps/x86 -I sysdeps/generic/ -I . -x c -E - < include/link.h
                // Get the instruction pointer (lol this is pretty stupid tbh)
                // Returns the return value of the resolved function
                // _dl_runtime_resolve example
                // https://github.com/bminor/glibc/blob/b92a49359f33a461db080a33940d73f47c756126/sysdeps/i386/dl-trampoline.S
                // _dl_fixup
                // https://github.com/bminor/glibc/blob/b92a49359f33a461db080a33940d73f47c756126/elf/dl-runtime.c
                // link_map
                //https://github.com/bminor/glibc/blob/master/include/link.h
                // https://gist.github.com/ricardo2197/8c7f6f5b8950ed6771c1cd3a116f7e62
                // https://syst3mfailure.io/ret2dl_resolve


                #if ({has_rela})
                #define PLTREL ElfW(Rela)
                #define HAS_RELA 1
                #else
                #define PLTREL ElfW(Rel)
                #define HAS_RELA 0
                #endif
                #ifndef reloc_offset
                # define reloc_offset reloc_arg
                # define reloc_index  reloc_arg / sizeof (PLTREL)
                #endif
                #define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
                #define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))

                unsigned char *base_addr = (unsigned char *)_getbase();
                unsigned char *data_segment = base_addr + {data_segment_address};
                uint64_t *gotplt = (uint64_t *)(base_addr + {gotplt_offset});
                unsigned char *plt = base_addr + {plt_offset};
                unsigned char *link_map = base_addr + {link_map_addr};
                unsigned char *dl_runtime_resolve = base_addr + {dl_runtime_resolve_addr};

                void *(*__dl_runtime_resolve)(struct link_map *l, ElfW(Word) reloc_arg) = (void *(*)(struct link_map *l, ElfW(Word) reloc_arg)) plt;
                struct link_map_private *linkmap = *(struct link_map_private**) link_map;

                PLTREL *reloc_base = (PLTREL *) linkmap->l_info[DT_JMPREL];
                ElfW(Sym) *symtab_base = (ElfW(Sym) *) linkmap->l_info[DT_SYMTAB];
                char *strtab_base = (char *) linkmap->l_info[DT_STRTAB];

                uint64_t *fakegot = (uint64_t *) data_segment;
                PLTREL *fakereloc = (PLTREL *) ALIGN((uint64_t)(fakegot + 1), sizeof(PLTREL));
                ElfW(Sym) *fakesymtab = (ElfW(Sym) *) ALIGN((uint64_t)(fakereloc + 1), sizeof(ElfW(Sym)));
                char *fakestrtab = (char *) (fakesymtab + sizeof(ElfW(Sym)));
                _strcpy(fakestrtab, "puts\\x00");

                uint32_t rel_arg = fakereloc - reloc_base;
                ptrdiff_t rel_offset = fakegot - gotplt;
                ptrdiff_t symtab_offset = fakesymtab - symtab_base;
                ptrdiff_t strtab_offset = fakestrtab - strtab_base;

                fakereloc->r_offset = rel_offset;
                fakereloc->r_info = (symtab_offset << 32) | R_X86_64_JUMP_SLOT;
                fakesymtab->st_name = strtab_offset;


                __asm__(".intel_syntax noprefix\\n"
                        "mov rax, %0\\n"
                        "mov rbx, %1\\n"
                        "mov rcx, %2\\n"
                        "mov rdx, %3\\n"
                        "mov r8, %4\\n"
                        "mov r9, %5\\n"
                        "mov r10, %6\\n"
                        "mov r11, %7\\n"
                        "mov r12, %8\\n"
                        :
                        : "g" (reloc_base), "g" (symtab_base), "g" (strtab_base),
                          "g" (fakegot), "g" (fakereloc), "g" (fakesymtab),
                          "g" (fakestrtab), "g" (rel_offset), "g" (rel_arg)
                        : "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12");


                uint64_t rv = 0;
                char *teststr = "test string";
                asm goto (".intel_syntax noprefix\\n"
                        "mov rdi, %0\\n"
                        "call %l1\\n"
                        :
                        : "r" (teststr)
                        : "memory", "rdi"
                        : trampoline);

                /* DO NOT PUT ANY CODE HERE! lol */

                trampoline:
                __asm__(".intel_syntax noprefix\\n"
                        "push %2\\n"
                        "jmp %1\\n"
                        "mov %0, rax\\n"
                        : "=r" (rv)
                        : "r" (__dl_runtime_resolve), "g" (rel_arg)
                        : "memory");

                // reloc.r_info = R_X86_64_JMP_SLOT | ;

                return 0;
                """,
                includes=[
                    "#include <link.h>",
                    "#include <stdint.h>",
                    "#include <stddef.h>",
                ],
                helpers=[
                    "libsyscall.c",
                    "libgetbase.c",
                    "libgetreg.c",
                    "libutil.c",
                    "liblink.c",
                ],
            ),
            pretransform_c_code=c_pretransformer,
        ),
        label="resolve_symbol",
    )

    def asm_transformer(asm: str, tinfo: TransformInfo, *args) -> str:
        """
        Transform the format string with the program context
        """
        offset_to = (
            tinfo.label_offsets.get("resolve_symbol")
            - p.binary.lief_binary.get_symbol("main").value
        )
        return asm.format(resolve_symbol=f"{offset_to:#0x}")

    rcp = ReplaceCodePatch(
        Code(
            assembly="call {resolve_symbol};",
            transform_asm=asm_transformer,
        ),
        address=p.binary.lief_binary.get_symbol("main").value,
    )
    p.apply(acp)
    p.apply(rcp)
    p.save(BINARIES_DIR / "print_twice_link_map.bin")
