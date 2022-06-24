"""
Test shellvm compilation
"""

from patches.shellvm.wrapper import SheLLVM


def test_compile_shellvm() -> None:
    """
    Test that a basic program can be compiled with shellvm
    """
    shellvm = SheLLVM()

    code = shellvm.compile(
        """__attribute__((annotate("shellvm-main"))) int main() { return 0; }""",
        arch="x86_64",
        vendor="pc",
        os="linux",
        environment="gnu",
    )

    assert code, "No code generated."
