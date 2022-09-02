"""Accessors for various libraries to add to patches
"""

from pathlib import Path

LIBS_DIR = Path(__file__).parent


def get_lib(name: str) -> str:
    """Return the text of a library file with a given name

    Args:
        name: The name of the library file to get, either a relative path to this file
            to retrieve a built in library or a full path to a library file
            to retrieve a custom library
    """
    try:
        return (LIBS_DIR / name).read_text(encoding="utf-8")
    except FileNotFoundError:
        return Path(name).read_text(encoding="utf-8")
