from pathlib import Path
from subprocess import DEVNULL, run
from typing import Dict
from pytest import fixture


BINARIES_DIR = Path(__file__).with_name("binaries")


def build_binaries() -> None:
    """
    (Re)-build the test binaries
    """
    run(
        ["make", "-C", f"{str(BINARIES_DIR)}", "clean"],
        check=True,
        stdout=DEVNULL,
        stderr=DEVNULL,
    )

    run(
        ["make", "-C", f"{str(BINARIES_DIR)}", "all"],
        check=True,
        stdout=DEVNULL,
        stderr=DEVNULL,
    )


@fixture
def bins() -> Dict[str, Path]:
    """
    Fixture to list binaries from the binary test directory easily
    """
    build_binaries()

    binaries = {}
    for file in BINARIES_DIR.rglob("**/*"):
        if file.is_file():
            binaries[file.name] = file

    return binaries
