"""Minimal, dependency-free PE parser focused on imports and exports."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple


@dataclass
class ImportEntry:
    dll: str
    name: Optional[str]      # None when imported by ordinal
    ordinal: Optional[int]
    iat_rva: int
    index: int

    def __str__(self) -> str:
        return self.name if self.name else "ord %d" % self.ordinal


class PE:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            self.buf = f.read()
        b = self.buf
        if b[:2] != b"MZ":
            raise ValueError("not a PE (no MZ): %s" % path)
        self.path = path
        self.pe_off = struct.unpack_from("<I", b, 0x3C)[0]
        if b[self.pe_off:self.pe_off + 4] != b"PE\0\0":
            raise ValueError("not a PE (no PE signature)")
        coff = self.pe_off + 4
        (self.machine, self.nsec, self.time_date, _sym, _nsym,
         self.opt_size, self.chars) = struct.unpack_from("<HHIIIHH", b, coff)
        opt = coff + 20
        self.magic = struct.unpack_from("<H", b, opt)[0]
        if self.magic not in (0x10B, 0x20B):
            raise ValueError("unknown optional header magic 0x%x" % self.magic)
        self.pe32plus = self.magic == 0x20B
        self.image_base = struct.unpack_from("<Q" if self.pe32plus else "<I", b, opt + 24)[0]
        dd = opt + (112 if self.pe32plus else 96)
        self.dirs = [struct.unpack_from("<II", b, dd + i * 8) for i in range(16)]
        sec = opt + self.opt_size
        self.sections: List[Tuple[str, int, int, int, int]] = []
        for i in range(self.nsec):
            o = sec + i * 40
            name = b[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", b, o + 8)
            self.sections.append((name, vaddr, vsize, rptr, rsize))

    # ---- addressing -------------------------------------------------------
    def rva_to_off(self, rva: int) -> Optional[int]:
        for _n, vaddr, vsize, rptr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                d = rva - vaddr
                return rptr + d if d < rsize else None
        return None

    def cstr(self, rva: int) -> Optional[str]:
        off = self.rva_to_off(rva)
        if off is None:
            return None
        end = self.buf.find(b"\0", off)
        return self.buf[off:end].decode("latin1", "replace")

    def section(self, name: str) -> Optional[Tuple[int, bytes]]:
        for n, vaddr, vsize, rptr, rsize in self.sections:
            if n == name:
                return vaddr, self.buf[rptr:rptr + rsize]
        return None

    # ---- imports ----------------------------------------------------------
    def _thunks(self, rva: int) -> Iterator[Tuple[str, object]]:
        off = self.rva_to_off(rva)
        if off is None:
            return
        step = 8 if self.pe32plus else 4
        fmt = "<Q" if self.pe32plus else "<I"
        hi = 1 << (63 if self.pe32plus else 31)
        while True:
            v = struct.unpack_from(fmt, self.buf, off)[0]
            if v == 0:
                return
            if v & hi:
                yield ("ord", v & 0xFFFF)
            else:
                yield ("name", self.cstr((v & 0x7FFFFFFF) + 2))
            off += step

    def imports(self) -> Dict[str, List[ImportEntry]]:
        """dll -> entries. Ordinals are kept as ordinals; resolve separately."""
        rva, _size = self.dirs[1]
        out: Dict[str, List[ImportEntry]] = {}
        if not rva:
            return out
        off = self.rva_to_off(rva)
        if off is None:
            return out
        i = 0
        while True:
            d = self.buf[off + i * 20: off + i * 20 + 20]
            if len(d) < 20:
                break
            ilt, _ts, _fc, name_rva, iat = struct.unpack("<IIIII", d)
            if name_rva == 0:
                break
            dll = self.cstr(name_rva) or "?"
            step = 8 if self.pe32plus else 4
            entries = []
            for idx, (kind, val) in enumerate(self._thunks(ilt or iat)):
                entries.append(ImportEntry(
                    dll=dll,
                    name=val if kind == "name" else None,
                    ordinal=val if kind == "ord" else None,
                    iat_rva=iat + idx * step,
                    index=idx,
                ))
            out[dll] = entries
            i += 1
        return out

    def delay_imports(self) -> Dict[str, List[ImportEntry]]:
        rva, _ = self.dirs[13]
        out: Dict[str, List[ImportEntry]] = {}
        if not rva:
            return out
        off = self.rva_to_off(rva)
        if off is None:
            return out
        i = 0
        while True:
            d = self.buf[off + i * 32: off + i * 32 + 32]
            if len(d) < 32:
                break
            attrs, name_rva, _mod, iat, int_rva, _b, _u, _t = struct.unpack("<IIIIIIII", d)
            if name_rva == 0:
                break
            dll = self.cstr(name_rva) or "?"
            base = 0 if (attrs & 1) else self.image_base
            step = 8 if self.pe32plus else 4
            entries = []
            for idx, (kind, val) in enumerate(self._thunks(int_rva - base if int_rva else 0)):
                entries.append(ImportEntry(dll, val if kind == "name" else None,
                                           val if kind == "ord" else None,
                                           iat + idx * step, idx))
            out[dll] = entries
            i += 1
        return out

    def exports(self) -> "ExportTable":
        rva, _size = self.dirs[0]
        return ExportTable(self, rva)


class ExportTable:
    """ordinal -> name map for a DLL (ordinal-only exports map to None)."""

    def __init__(self, pe: PE, dir_rva: int):
        self.pe = pe
        self.names: Dict[int, Optional[str]] = {}
        if not dir_rva:
            return
        off = pe.rva_to_off(dir_rva)
        if off is None:
            return
        base = struct.unpack_from("<I", pe.buf, off + 16)[0]
        n_func = struct.unpack_from("<I", pe.buf, off + 20)[0]
        n_name = struct.unpack_from("<I", pe.buf, off + 24)[0]
        aof = pe.rva_to_off(struct.unpack_from("<I", pe.buf, off + 28)[0])
        aon = pe.rva_to_off(struct.unpack_from("<I", pe.buf, off + 32)[0])
        aoo = pe.rva_to_off(struct.unpack_from("<I", pe.buf, off + 36)[0])
        for i in range(n_func):
            if struct.unpack_from("<I", pe.buf, aof + i * 4)[0]:
                self.names[base + i] = None
        for i in range(n_name):
            nrva = struct.unpack_from("<I", pe.buf, aon + i * 4)[0]
            idx = struct.unpack_from("<H", pe.buf, aoo + i * 2)[0]
            self.names[base + idx] = pe.cstr(nrva)

    def get(self, ordinal: int, default=None):
        return self.names.get(ordinal, default)

    def __len__(self) -> int:
        return len(self.names)


def resolve_ordinals(dll_path: str) -> Dict[int, Optional[str]]:
    """ordinal -> name for a system DLL such as ws2_32.dll."""
    return PE(dll_path).exports().names
