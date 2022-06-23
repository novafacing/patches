"""
Build script to compile shellvm
"""

from pathlib import Path
from shutil import rmtree
from subprocess import run
from typing import Any

SHELLVM_DIR = Path(__file__).with_name("third_party") / "shellvm"
SHELLVM_OUTPUT_FILE = Path(__file__).with_name("patches") / "shellvm" / "libshellvm.so"


def check_clang() -> None:
    """
    Check if clang is installed
    """
    try:
        c = run(["clang", "--version"], capture_output=True, check=True)
        cpp = run(["clang++", "--version"], capture_output=True, check=True)
        if b"clang version 15" not in c.stdout or b"clang version 15" not in cpp.stdout:
            raise ValueError("clang/++ version >= 15 is required")
    except Exception as e:
        raise Exception("clang/++ version >= 15 is required") from e


def compile_shellvm() -> None:
    """
    Compile shellvm
    """
    SHELLVM_BUILD_DIR = SHELLVM_DIR / "build"
    try:
        SHELLVM_BUILD_DIR.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        rmtree(SHELLVM_BUILD_DIR)
        SHELLVM_BUILD_DIR.mkdir(parents=True, exist_ok=False)

    run(["cmake", ".."], cwd=SHELLVM_BUILD_DIR, check=True)
    run(["cmake", "--build", "."], cwd=SHELLVM_BUILD_DIR, check=True)

    SHELLVM_SO_OUTPUT = SHELLVM_BUILD_DIR / "llvm" / "shellvm.so"

    if not SHELLVM_SO_OUTPUT.is_file():
        raise FileNotFoundError("shellvm.so not found, compilation failed")

    SHELLVM_SO_OUTPUT.rename(SHELLVM_OUTPUT_FILE)

    if not SHELLVM_OUTPUT_FILE.is_file():
        raise FileNotFoundError("libshellvm.so not found, copying failed")


def build(_: Any) -> None:
    """
    Build the shellvm
    """

    if not SHELLVM_DIR.is_dir():
        raise ValueError(
            "shellvm directory not found, run `git submodule update --init`"
        )

    check_clang()
    compile_shellvm()
