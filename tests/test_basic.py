"""Tests. Most run against the real system DLLs on Windows."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from peord import PE, resolve_ordinals, iat_xrefs, find_pattern  # noqa: E402

WINDOWS = os.name == "nt"
SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")


def _dll(name):
    path = os.path.join(SYS32, name)
    if not os.path.exists(path):
        pytest.skip("%s not present" % name)
    return path


@pytest.mark.skipif(not WINDOWS, reason="needs Windows system DLLs")
def test_parses_kernel32():
    pe = PE(_dll("kernel32.dll"))
    imports = pe.imports()
    assert len(imports) > 5
    total = sum(len(v) for v in imports.values())
    assert total > 50


@pytest.mark.skipif(not WINDOWS, reason="needs Windows system DLLs")
def test_ws2_32_ordinals_resolve():
    """The whole point: send/sendto are imported by ordinal, not by name."""
    table = resolve_ordinals(_dll("ws2_32.dll"))
    assert table.get(19) == "send"
    assert table.get(20) == "sendto"
    assert table.get(23) == "socket"


@pytest.mark.skipif(not WINDOWS, reason="needs Windows system DLLs")
def test_iat_xrefs_finds_call_sites():
    # a DLL does not import from itself: use a real executable instead
    pe = PE(_dll("notepad.exe"))
    hits = iat_xrefs(pe, "kernel32.dll")
    assert hits, "expected at least one call through the IAT"
    assert sum(len(v) for v in hits.values()) > 10


@pytest.mark.skipif(not WINDOWS, reason="needs Windows system DLLs")
def test_pattern_scan_mz_header_in_image():
    pe = PE(_dll("kernel32.dll"))
    hits = find_pattern(pe, "4D 5A", section=".text")
    assert isinstance(hits, list)


@pytest.mark.skipif(not WINDOWS, reason="needs Windows system DLLs")
def test_exports_have_names():
    pe = PE(_dll("ws2_32.dll"))
    table = pe.exports().names
    assert len(table) > 100
    assert any(v == "send" for v in table.values())
