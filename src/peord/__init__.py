"""PE import analysis that does not miss by-ordinal imports.

Why this exists
---------------
`ws2_32.lib` exports `send`, `sendto`, `socket`, `bind`, `connect` and friends
**by ordinal**. After linking, the PE import table contains only numbers, no
names. Tools that read import names alone will report "this binary has no send
function" on a program that obviously sends packets.

That mistake is common enough to be worth a dedicated tool.
"""
from .pe import PE, resolve_ordinals, ExportTable, ImportEntry
from .xref import iat_xrefs, find_pattern, scan_forward
from .scan import iter_strings

__all__ = [
    "PE",
    "resolve_ordinals",
    "ExportTable",
    "ImportEntry",
    "iat_xrefs",
    "find_pattern",
    "scan_forward",
    "iter_strings",
]

__version__ = "0.1.0"
