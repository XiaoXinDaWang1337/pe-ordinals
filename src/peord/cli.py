"""Command line interface for pe-ordinals."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from .pe import PE, resolve_ordinals
from .scan import iter_strings
from .xref import find_pattern, iat_xrefs


def _default_sysdir() -> str:
    if os.name == "nt":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    return ""


class OrdinalResolver:
    """Lazily resolve ordinals for a DLL, keeping results across calls."""

    def __init__(self, sysdir: Optional[str]):
        self.sysdir = sysdir if sysdir is not None else _default_sysdir()
        self.cache: Dict[str, Dict[int, Optional[str]]] = {}

    def get(self, dll: str) -> Dict[int, Optional[str]]:
        if dll in self.cache:
            return self.cache[dll]
        table: Dict[int, Optional[str]] = {}
        if self.sysdir:
            path = os.path.join(self.sysdir, dll)
            if os.path.exists(path):
                try:
                    table = resolve_ordinals(path)
                except Exception:
                    table = {}
        self.cache[dll] = table
        return table


def cmd_imports(args) -> int:
    pe = PE(args.pe)
    resolver = OrdinalResolver(args.sysdir)
    named = ordinal = 0
    out = {}
    for dll, entries in pe.imports().items():
        if args.dll and args.dll.lower() not in dll.lower():
            continue
        names = [e for e in entries if e.name]
        ords = [e for e in entries if e.ordinal is not None]
        named += len(names)
        ordinal += len(ords)
        table = resolver.get(dll) if ords else {}
        out[dll] = {
            "by_name": [e.name for e in names],
            "by_ordinal": [{"ordinal": e.ordinal, "name": table.get(e.ordinal)} for e in ords],
        }
    if args.json:
        json.dump(out, sys.stdout, indent=1)
        print()
        return 0

    print("imports: %d by name, %d by ordinal" % (named, ordinal))
    for dll, info in out.items():
        print("\n%s  (%d by name, %d by ordinal)"
              % (dll, len(info["by_name"]), len(info["by_ordinal"])))
        for n in info["by_name"]:
            print("    name  %s" % n)
        for o in info["by_ordinal"]:
            print("    ord   %-5d -> %s" % (o["ordinal"], o["name"] or "<unresolved>"))
    if ordinal and not resolver.sysdir:
        print("\nwarning: no system directory to resolve ordinals against")
    return 0


def cmd_iatxrefs(args) -> int:
    pe = PE(args.pe)
    hits = iat_xrefs(pe, args.dll)
    rows = sorted(hits.items(), key=lambda kv: -len(kv[1]))
    if args.json:
        json.dump({k: [hex(v) for v in vs] for k, vs in rows}, sys.stdout, indent=1)
        print()
        return 0
    for name, sites in rows:
        print("%-30s %4d call site(s)   first: 0x%x" % (name, len(sites), sites[0]))
    if not rows:
        print("no references found (wrong dll filter?)")
    return 0


def cmd_pattern(args) -> int:
    pe = PE(args.pe)
    hits = find_pattern(pe, args.signature)
    if args.json:
        json.dump([hex(h) for h in hits], sys.stdout, indent=1)
        print()
        return 0
    print("hits: %d" % len(hits))
    for h in hits[:args.limit]:
        print("  0x%x" % h)
    return 0


def cmd_strings(args) -> int:
    pe = PE(args.pe)
    n = 0
    for off, s in iter_strings(pe, args.min, args.kw):
        print("0x%08x  %s" % (off, s[:160]))
        n += 1
        if n >= args.limit:
            break
    return 0


def cmd_exports(args) -> int:
    pe = PE(args.dll_path)
    table = pe.exports().names
    if args.json:
        json.dump({k: v for k, v in sorted(table.items())}, sys.stdout, indent=1)
        print()
        return 0
    print("exports: %d" % len(table))
    for ord_, name in sorted(table.items())[:args.limit]:
        print("  %-6d %s" % (ord_, name or "<ordinal only>"))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="peord", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("imports", help="import table with ordinals resolved")
    p.add_argument("pe")
    p.add_argument("--dll", help="only this DLL (substring match)")
    p.add_argument("--sysdir", help="directory holding the system DLLs")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_imports)

    p = sub.add_parser("iatxrefs", help="who calls each imported function")
    p.add_argument("pe")
    p.add_argument("--dll", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_iatxrefs)

    p = sub.add_parser("pattern", help="byte signature scan, ?? wildcards")
    p.add_argument("pe")
    p.add_argument("signature")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_pattern)

    p = sub.add_parser("strings", help="printable strings")
    p.add_argument("pe")
    p.add_argument("--min", type=int, default=6)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("kw", nargs="*")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("exports", help="export table of a DLL")
    p.add_argument("dll_path")
    p.add_argument("--limit", type=int, default=60)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_exports)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
