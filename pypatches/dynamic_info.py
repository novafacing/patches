"""
Container for dynamic info needed to resolve symbols or use _dl_runtime_resolve
"""
from dataclasses import dataclass


@dataclass
class DynamicInfo:
    """
    Container for dynamic info needed to resolve symbols or use _dl_runtime_resolve
    """

    ## gotplt_addr == dynamic_section_addr
    gotplt_addr: int
    plt_addr: int
    dynamic_section_addr: int
    link_map_addr: int
    dl_runtime_resolve_addr: int
    has_rela: bool
