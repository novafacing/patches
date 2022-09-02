"""Dataclass implementing comparable address ranges.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class AddressRange:
    """An address range with a start and end.
    If start == end, this address range is just one address

    Attributes:
        start: The start address of the range
        end: The end address of the range
    """

    start: int
    end: int

    @property
    def address(self) -> bool:
        """Returns whether this range is "an address" """
        return self.start == self.end
