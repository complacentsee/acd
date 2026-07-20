"""Unit tests for the <InternetProtocol> ConfigType dispatch.

Code 1 = Manual (static address block emitted); code 0 = BOOTP (bare element,
address block is all zero); any other code omits the element (fail closed).
"""
import acd.l5x.controller_ports as CP


def _v(code, block=b""):
    """A 0x1 ext-attr value: config code at byte 0, address block at _IP_BLOCK."""
    v = bytearray(CP._IP_BLOCK + 20)
    v[0] = code
    if block:
        v[CP._IP_BLOCK:CP._IP_BLOCK + len(block)] = block
    return bytes(v)


def test_bootp_is_a_bare_element(monkeypatch):
    monkeypatch.setattr(CP, "_attrs", lambda *a, **k: {0x1: _v(0)})
    out = CP.build_internet_protocol(None, 0, False, "24")
    assert out == '<InternetProtocol ConfigType="BOOTP"/>'


def test_manual_carries_the_address_block(monkeypatch):
    # IPAddress word stored little-endian -> rendered dotted-quad reversed.
    monkeypatch.setattr(
        CP, "_attrs", lambda *a, **k: {0x1: _v(1, bytes([1, 0, 0, 10]))})
    out = CP.build_internet_protocol(None, 0, False, "20")
    assert 'ConfigType="Manual"' in out
    assert 'IPAddress="10.0.0.1"' in out


def test_unknown_code_is_omitted(monkeypatch):
    monkeypatch.setattr(CP, "_attrs", lambda *a, **k: {0x1: _v(2)})
    assert CP.build_internet_protocol(None, 0, False, "20") == ""


def test_bootp_still_gated_by_major_rev(monkeypatch):
    # The element is only emitted on firmware major <= 24, BOOTP included.
    monkeypatch.setattr(CP, "_attrs", lambda *a, **k: {0x1: _v(0)})
    assert CP.build_internet_protocol(None, 0, False, "32") == ""
