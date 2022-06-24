"""
Tests for the various types of patches
"""

from patches.patches import NopPatch


def test_nop_patch_create() -> None:
    """
    Test the creation of a nop patch
    """
    addresses = [0x400000, 0x430000, 0x0]
    p = NopPatch(addresses)
    assert len(p.address_ranges) == 3
    for address_range in p.address_ranges:
        assert (
            address_range.start == address_range.end
            and address_range.start in addresses
        )
