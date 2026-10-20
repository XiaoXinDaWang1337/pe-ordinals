# pe-ordinals

PE import analysis that **does not miss by-ordinal imports**.

```python
>>> from peord import PE, resolve_ordinals
>>> pe = PE(r"C:\path\to\game.exe")
>>> for e in pe.imports()["WS2_32.dll"]:
...     print(e)
...
WSAWaitForMultipleEvents
WSASetEvent
ord 111
ord 3
ord 4
ord 19        # <- send
ord 20        # <- sendto
```

## The problem

`ws2_32.lib` exports `send`, `sendto`, `socket`, `bind`, `connect`, `select`,
`listen` and friends **by ordinal**. After linking, the PE import table holds
only numbers.

A tool that reads import names alone therefore reports:

> this binary imports 14 functions from WS2_32.dll and has no send capability

for a program that obviously sends packets.

Real example, a shipping game client:

```
$ peord imports game.exe --dll ws2_32
WS2_32.dll  (14 by name, 29 by ordinal)
    name  WSAWaitForMultipleEvents
    name  WSASetEvent
    ...
    ord   19    -> send
    ord   20    -> sendto
    ord   23    -> socket
    ord    2    -> bind
    ord    4    -> connect
```

Names: 14. Reality: 43. And the three functions that matter most were invisible.

## Install

```
pip install pe-ordinals
```

No dependencies. Ordinal resolution needs the real system DLLs, so pass
`--sysdir` if the tool is not running on Windows:

```
peord imports game.exe --sysdir /path/to/win-dlls
```

## Use

```
peord imports  <pe> [--dll WS2_32] [--json]
peord iatxrefs <pe> --dll WS2_32 [--json]
peord pattern  <pe> "48 8B ?? E8" [--json]
peord strings  <pe> --min 6 [keywords...]
peord exports  <dll>
```

Library:

```python
from peord import PE, iat_xrefs, resolve_ordinals

pe = PE("target.exe")
entries = pe.imports()["WS2_32.dll"]          # ImportEntry(name=..., ordinal=...)
table   = resolve_ordinals(r"C:\Windows\System32\ws2_32.dll")   # {19: 'send', ...}
calls   = iat_xrefs(pe, "WS2_32.dll")         # {'send': [0x140001234, ...]}
```

## What `iatxrefs` answers

Importing a function is not the same as calling it. `iatxrefs` counts the actual
`call qword ptr [rip+disp32]` sites that go through each IAT slot:

```
$ peord iatxrefs game.exe --dll ws2_32
sendto                         13 call site(s)   first: 0x141aa5bf1
send                           14 call site(s)   first: 0x141a90f9e
socket                          9 call site(s)   first: 0x141aa4651
```

That distinction matters: an audit can only claim "this program cannot send"
after showing that no code path reaches the import.

## Scope

Deliberately small: one file of PE parsing, one of cross-referencing, one of
string scanning. It is meant to be dropped into an analysis pipeline, not to be
a framework. If you need a full featured parser, use `pefile`; this library
covers the import/export/xref slice that `pefile` leaves to the caller.

## License

MIT.
