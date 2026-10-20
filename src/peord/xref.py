"""Cross references: who calls each imported function, and byte patterns."""
from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional, Tuple

from .pe import PE


def _iat_slots(pe: PE, dll_filter: Optional[str]) -> Dict[int, Tuple[str, str]]:
    """virtual address of an IAT slot -> (dll, display name)"""
    slots: Dict[int, Tuple[str, str]] = {}
    for dll, entries in pe.imports().items():
        if dll_filter and dll_filter.lower() not in dll.lower():
            continue
        for e in entries:
            va = pe.image_base + e.iat_rva
            slots[va] = (dll, e.name or ("ord %d" % e.ordinal))
    return slots


def iat_xrefs(pe: PE, dll_filter: Optional[str] = None) -> Dict[str, List[int]]:
    """Function -> list of virtual addresses that call/jmp through its IAT slot.

    Matches `call qword ptr [rip+disp32]` (FF 15) and `jmp ...` (FF 25), which is
    how MSVC emits calls to imported functions in x64 code.
    """
    slots = _iat_slots(pe, dll_filter)
    text = pe.section(".text")
    if not text or not slots:
        return {}
    vaddr, blob = text
    hits: Dict[str, List[int]] = {}
    for i in range(len(blob) - 6):
        if blob[i] != 0xFF or blob[i + 1] not in (0x15, 0x25):
            continue
        disp = struct.unpack_from("<i", blob, i + 2)[0]
        insn_va = pe.image_base + vaddr + i
        target = insn_va + 6 + disp
        slot = slots.get(target)
        if slot:
            hits.setdefault(slot[1], []).append(insn_va)
    return hits


def find_pattern(pe: PE, signature: str, section: str = ".text") -> List[int]:
    """Byte signature scan. `??` is a wildcard byte: "48 8B ?? E8".

    Returns virtual addresses.
    """
    parts = signature.split()
    rx = b"".join(b"." if p in ("??", "?") else re.escape(bytes([int(p, 16)]))
                  for p in parts)
    sec = pe.section(section)
    if not sec:
        return []
    vaddr, blob = sec
    return [pe.image_base + vaddr + m.start()
            for m in re.finditer(rx, blob, re.DOTALL)]


def scan_forward(pe: PE, va: int, length: int) -> bytes:
    """Raw bytes at a virtual address (for handing to a disassembler)."""
    off = pe.rva_to_off(va - pe.image_base)
    if off is None:
        return b""
    return pe.buf[off:off + length]


def annotate_rip(pe: PE, insn_va: int, insn_len: int, disp: int,
                 max_string: int = 90) -> Optional[str]:
    """Resolve a rip-relative operand to a printable string, if any."""
    target = insn_va + insn_len + disp
    off = pe.rva_to_off(target - pe.image_base)
    if off is None:
        return None
    raw = pe.buf[off:pe.buf.find(b"\0", off)]
    if len(raw) < 3:
        return None
    if sum(32 <= c < 127 for c in raw) < len(raw) * 0.75:
        return None
    return raw.decode("latin1")[:max_string]
