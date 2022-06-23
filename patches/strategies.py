"""
Enumeration of patching strategies
"""

from enum import Enum


class STRATEGY(str, Enum):
    """
    Patching strategy enumeration
    """

    CAVE = "CAVE"
    ADD = "ADD"
    REPLACE = "REPLACE"
