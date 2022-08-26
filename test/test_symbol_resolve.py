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

    def c_pretransformer(code: str, tinfo: PreTransformInfo) -> str:
        """
        Replace the link map address with the real address
        """
        logger.debug(f"Transforming {code} with {tinfo}")
        result = (
            code.replace(
                "{link_map_address}", f"{tinfo.dynamic_info.link_map_addr:#0x}"
            )
            .replace(
                # Don't actually do it like this in real patcher code
                "{puts_address}",
                f"{tinfo.dynamic_info.link_map_addr+24:#0x}",
            )
            .replace(
                "{new_segment_base}",
                f"{tinfo.new_code_segment_base:#0x}",
            )
        )
        logger.debug(f"Transformed to {result}")
        return result

    acp = AddCodePatch(
        Code(
            c_code=Code.build_c_code(
                """
                // Link map struct was grabbed with:
                // clang -I string -I sysdeps/x86 -I sysdeps/generic/ -I . -x c -E - < include/link.h
                uintptr_t iaddr = 0;
                __asm__(".intel_syntax noprefix\\n"
                        "lea %V0, [rip+0];\\n" : "=r" (iaddr) : : "rax");
                iaddr = iaddr & ~0xfff; // mask off 4k page offset
                ptrdiff_t new_segment_base = {new_segment_base};
                uintptr_t base_addr = iaddr - new_segment_base;

                void *puts_offset = (void *){puts_address} + base_addr;
                void *link_map_offset = (void *){link_map_address} + base_addr;

                void (*puts)(const char *) = *(uint64_t *) puts_offset;
                struct link_map *link_map = *(uint64_t *) link_map_offset;

                void * libc_handle = NULL;

                while (link_map->l_next != NULL) {
                    if (_contains(link_map->l_name, "libc")) {
                        puts("Found libc:");
                        puts(link_map->l_name);
                        libc_handle = link_map->l_addr;
                        break;
                    }

                    link_map = link_map->l_next;
                }

                Elf64_Addr libc_addr = (Elf64_Addr)libc_handle;
                Elf64_Ehdr *ehdr = (Elf64_Ehdr*)libc_handle;
                Elf64_Phdr *phdr = (Elf64_Phdr*)ehdr+ehdr->e_phoff;
                Elf64_Phdr *interp_phdr = (Elf64_Phdr*)phdr+sizeof(Elf64_Phdr);
                Elf64_Addr interp_addr = interp_phdr->p_vaddr;
                char *interp = (char *)interp_addr;
                puts("Interpreter:");
                puts(interp);




                return 0;
                """,
                includes=[
                    "#include <link.h>",
                    "#include <stdint.h>",
                    "#include <stddef.h>",
                ],
                extra_code="""
                int _strlen(const char *s) {
                    int len = 0;
                    while (*s++ && len) len++;
                    return len;
                }

                int _strncmp(const char *a, const char *b, int len) {
                    while (*a == *b && *a && *b && len >= 0) a++, b++, len--;
                    return *a - *b;
                }

                int _contains(const char *haystack, const char *needle) {
                    while (*haystack++) {
                        if (_strlen(haystack) < _strlen(needle)) {
                            break;
                        }
                        if (!_strncmp(haystack, needle, _strlen(needle))) {
                            return 1;
                        }
                    }
                    return 0;
                }
                """,
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
