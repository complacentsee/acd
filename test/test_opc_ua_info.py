"""Unit tests for the controller <OpcUaInfo> block.

Presence = a live OPCUA comp under RxControllerCollection; EnabledPorts="" is
reproduced only when the comp's 0x1 ext-attr has an all-zero enabled-ports tail
(a nonzero tail is unobserved, so the block is omitted -- fail closed).
"""
import acd.l5x.controller_ports as CP


def test_emitted_for_all_zero_tail(monkeypatch):
    v = bytes.fromhex("0100000001000000") + b"\x00" * 24  # 32 bytes, zero tail
    monkeypatch.setattr(CP, "_attrs", lambda *a, **k: {0x1: v})
    assert CP.build_opc_ua_info(None, 0, False) == '<OpcUaInfo EnabledPorts=""/>'


def test_omitted_when_no_opcua_comp(monkeypatch):
    monkeypatch.setattr(CP, "_attrs", lambda *a, **k: None)
    assert CP.build_opc_ua_info(None, 0, False) == ""


def test_omitted_for_nonzero_tail(monkeypatch):
    v = bytes.fromhex("0100000001000000") + b"\x00" * 23 + b"\x01"
    monkeypatch.setattr(CP, "_attrs", lambda *a, **k: {0x1: v})
    assert CP.build_opc_ua_info(None, 0, False) == ""
