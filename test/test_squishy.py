"""
Test shellvm compilation
"""

from pysquishy.squishy import Squishy
from pysquishy.clang import ClangArch, ClangVendor, ClangOS, ClangEnvironment

from archinfo.arch_amd64 import ArchAMD64


def test_compile_squishy() -> None:
    """
    Test that a basic program can be compiled with squishy
    """
    squishy = Squishy()

    code = squishy.compile(
        """int main() { return 0; }""",
        arch=ClangArch("x86_64"),
        vendor=ClangVendor("pc"),
        os=ClangOS("linux"),
        environment=ClangEnvironment("gnu"),
    )

    dis = ArchAMD64().disasm(code)

    # Make sure the disassembly matches the expected output for a blank ret 0 main
    assert list(map(lambda l: l.strip(), dis.splitlines())) == [
        "0x0:\tpush rbp",
        "0x1:\tmov rbp, rsp",
        "0x4:\tmov dword ptr [rbp - 4], 0",
        "0xb:\txor eax, eax",
        "0xd:\tpop rbp",
        "0xe:\tret",
        "0xf:\tnop",
    ]

    assert code, "No code generated."
