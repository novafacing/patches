from pathlib import Path
from typing import Dict
from pytest import fixture


@fixture
def bins() -> Dict[str, Path]:
    """
    Fixture to list binaries from the binary test directory easily
    """
    binaries = {}
    binaries_dir = Path(__file__).with_name("binaries")

    for file in binaries_dir.rglob("**/*"):
        if file.is_file():
            binaries[file.name] = file

    return binaries
