# pylint: disable=redefined-outer-name, unused-import
"""
Test BinaryInfo class and binary loading
"""

from pathlib import Path
from typing import Dict

from pypatches.binary_manager import BinaryManager
from test.fixtures import bins


def test_load_ais_lite_path(bins: Dict[str, Path]) -> None:
    """
    Test that we can load AIS-Lite from file
    """
    pth = bins.get("AIS-Lite.bin")
    assert pth is not None
    BinaryManager(pth)


def test_load_ais_lite_spath(bins: Dict[str, Path]) -> None:
    """
    Test that we can load AIS-Lite from file
    """
    pth = str(bins.get("AIS-Lite.bin"))
    assert pth is not None
    BinaryManager(pth)


def test_load_ais_lite_blob(bins: Dict[str, Path]) -> None:
    """
    Test that we can load AIS-Lite from file
    """
    pth = bins.get("AIS-Lite.bin")
    assert pth is not None
    blb = pth.read_bytes()
    assert blb
    BinaryManager(blb)
