"""
Shellvm wrapper utilities
"""

from pathlib import Path
from subprocess import CalledProcessError, run
from tempfile import NamedTemporaryFile
from typing import Any, Dict, Optional, Union

SHELLVM_SO_PATH = Path(__file__).with_name("shellvm.so")


def get_shellvm_so_path() -> Path:
    """
    Get the path to the shellvm shared object
    """
    if not SHELLVM_SO_PATH.is_file():
        raise FileNotFoundError("shellvm.so not found")

    return SHELLVM_SO_PATH


class SheLLVM:
    """
    Shellvm wrapper class
    """

    @classmethod
    def test_command(cls, command: str) -> None:
        """
        Test a command
        """
        cmd = [command, "--version"]
        try:
            run(cmd, capture_output=True, check=True)
        except CalledProcessError as e:
            raise FileNotFoundError(f"{command} not found") from e

    def __init__(
        self,
        cc: str = "clang",
        opt: str = "opt",
        llvm_link: str = "",  # Currently unused but is required to use any libraries (windows)
        llvm_dis: str = "",  # Set if you want to see the bitcode for debugging
        objcopy: str = "objcopy",
    ) -> None:
        """
        Set up wrapper and check that we have everything we need:
        - The library
        - clang/clang++
        - llvm-link
        """
        self.test_command(cc)
        self.test_command(opt)

        if llvm_link:
            self.test_command(llvm_link)

        if llvm_dis:
            self.test_command(llvm_dis)

        self.test_command(objcopy)
        self.cc = cc
        self.opt = opt
        self.llvm_link = llvm_link
        self.llvm_dis = llvm_dis
        self.objcopy = objcopy
        self.so_path = get_shellvm_so_path()

    def compile(
        self,
        code: Union[str, bytes],
        arch: str = "",
        vendor: str = "",
        os: str = "",
        environment: str = "",
        extra_run_args: Optional[Dict[str, Any]] = None,
    ) -> bytes:
        """
        Compile code with shellvm. The recommended compilation process from shellvm is:
        ```
        clang -target i686-w64-mingw32 -c -emit-llvm -o main.bc main.c
        clang -target i686-w64-mingw32 -c -emit-llvm -o hello.bc hello.c
        llvm-link -o linked.bc main.bc hello.bc shellvm-built/winnt-{user,kernel}32.bc
        clang -load=shellvm-built/shellvm.so -O3 -shellvm -o shellcode.elf linked.bc
        objcopy -O binary --only-section=.text shellcode.elf shellcode.bin
        msfvenom -p - -a i386 --platform win32 -e x86/shikata_ga_nai < s
        ```
        but these instructions are for Windows.

        `code`, `arch`, `vendor`, `os` and `environment` can be found in:
        https://github.com/llvm/llvm-project/blob/main/llvm/lib/Support/Triple.cpp
        """

        if extra_run_args is None:
            extra_run_args = {}

        if isinstance(code, str):
            code = code.encode("utf-8")

        triple = (
            f"{arch + '-' if arch else arch}"
            f"{vendor + '-' if vendor else vendor}"
            f"{os + '-' if os else os}"
            f"{environment + '-' if environment else environment}"
        )

        bitcode = run(
            [
                self.cc,
                "-target",
                triple,
                "-c",
                "-emit-llvm",
                # Language is C
                "-x",
                "c",
                # Output to stdout
                "-o",
                "-",
                # Input from stdin
                "-",
            ],
            check=True,
            input=code,
            capture_output=True,
            **extra_run_args,
        ).stdout

        try:
            opt_bitcode = run(
                [
                    self.opt,
                    "-load",
                    f"{str(self.so_path.resolve())}",
                    "--shellvm-prepare",
                    "--shellvm-precheck",
                    "--shellvm-flatten",
                    "--shellvm-global2stack",
                    "--shellvm-inlinectors",
                    "--shellvm-postcheck",
                    "-enable-new-pm=0",
                    "-f",
                    # Input from stdin
                    "-",
                ],
                check=True,
                input=bitcode,
                capture_output=True,
                **extra_run_args,
            ).stdout

            if self.llvm_dis:
                human_opt_bitcode = run(
                    [
                        self.llvm_dis,
                        "-",
                    ],
                    check=True,
                    input=bitcode,
                    capture_output=True,
                ).stdout.decode("utf-8")
                print(human_opt_bitcode)

        except CalledProcessError as e:
            raise RuntimeError(
                f"Failed to optimize bitcode:\nSTDERR: {e.stderr.decode('utf-8')}\n"
                f"STDOUT: {e.stdout.decode('utf-8')}"
            ) from e

        output_path = NamedTemporaryFile(suffix=".bin", delete=False)

        run(
            [
                self.cc,
                "-target",
                triple,
                "-Oz",
                "-s",
                "-x",
                "ir",
                "-o",
                f"{output_path.name}",
                # Input from stdin
                "-",
            ],
            check=True,
            input=opt_bitcode,
            capture_output=True,
            **extra_run_args,
        )

        elf_path = Path(output_path.name)
        elf_text_path = Path(output_path.name + ".text")

        text_section = run(
            [
                self.objcopy,
                "-O",
                "binary",
                "--only-section=.text",
                str(elf_path),
                str(elf_text_path),
            ],
            check=True,
            capture_output=True,
            **extra_run_args,
        )

        code_output = elf_text_path.read_bytes()
        elf_path.unlink(missing_ok=True)
        elf_text_path.unlink(missing_ok=True)

        print(f"Produced ELF file with {len(code_output)} bytes.")

        return code_output
