"""
Container for dynamic info needed to resolve symbols or use _dl_runtime_resolve
"""
from dataclasses import dataclass


@dataclass
class DynamicInfo:
    """
    Container for dynamic info needed to resolve symbols or use _dl_runtime_resolve
    """

    dynamic_section_addr: int
    link_map_addr: int
    dl_runtime_resolve_addr: int
