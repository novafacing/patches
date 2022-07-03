# pylint: disable=redefined-outer-name, unused-import
"""
Test BinaryInfo class and binary loading
"""

from pathlib import Path
from typing import Dict
from patches.binary_info import BinaryInfo

from patches.test.fixtures import bins


def test_load_ais_lite_path(bins: Dict[str, Path]) -> None:
    """
    Test that we can load AIS-Lite from file
    """
    pth = bins.get("AIS-Lite")
    assert pth is not None
    BinaryInfo(pth)


def test_load_ais_lite_spath(bins: Dict[str, Path]) -> None:
    """
    Test that we can load AIS-Lite from file
    """
    pth = str(bins.get("AIS-Lite"))
    assert pth is not None
    BinaryInfo(pth)


def test_load_ais_lite_blob(bins: Dict[str, Path]) -> None:
    """
    Test that we can load AIS-Lite from file
    """
    pth = bins.get("AIS-Lite")
    assert pth is not None
    blb = pth.read_bytes()
    assert blb
    BinaryInfo(blb)
