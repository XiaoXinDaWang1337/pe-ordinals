"""Printable string scanning with file offsets."""
from __future__ import annotations

import re
from typing import Iterator, List, Optional

from .pe import PE


def iter_strings(pe: PE, min_len: int = 6,
                 keywords: Optional[List[str]] = None) -> Iterator[tuple]:
    """Yield (file_offset, string). Keywords filter case-insensitively."""
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_len))
    kws = [k.lower() for k in keywords] if keywords else None
    for m in rx.finditer(pe.buf):
        s = m.group().decode("latin1")
        if kws and not any(k in s.lower() for k in kws):
            continue
        yield m.start(), s
