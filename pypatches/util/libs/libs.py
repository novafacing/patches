"""
Accessors for various libraries to add to patches
"""

from pathlib import Path

LIBS_DIR = Path(__file__).parent


def get_lib(name: str) -> str:
    """
    Return the text of a library file with a given name
    """
    try:
        return (LIBS_DIR / name).read_text(encoding="utf-8")
    except FileNotFoundError:
        return Path(name).read_text(encoding="utf-8")
