"""Render the ``<Data Format="Axis">`` block for an AXIS_CIP_DRIVE tag.

The axis config image (attr 0x01 of the cip-0x6a backing, body_mode) is a flat
fixed-offset struct keyed by its byte length. This renders the length-5965
generation, reverse-engineered and validated byte-exact against the OEM export
on every 5965 CIP axis of two independent test pools (see
acd/docs/motion-axis-data-status.md and the tracer round-trip).

Three data-driven parts, all in ``axis_cip_data.json``:
  * per-attribute VALUE decode (offset + kind + enum/token/list vocab), plus the
    documented derivations (MotorUnit/Feedback1Unit follow the motor's
    rotary/linear type; two feedback/test fields are corpus-constant);
  * the EMIT-SET: which attributes a given axis emits, read from the config's
    capability bitmap in the blob (bits that gate feature groups) plus
    content-presence for the variable-length list, keyed on AxisConfiguration;
  * the global emit ORDER.

Fail-closed: any unrecognised length, AxisConfiguration, enum code, unresolved
MotionModule, or ambiguous derivation returns None, so the tag keeps its prior
no-<Data> output (element_missing) rather than emit a wrong (net-worse) block.
"""
import html
import json
import os
import struct
from typing import Dict, Union

from acd.l5x import tag_value as _tag_value

_DATA = None
_INT = {1: "B", 2: "<H", 4: "<I"}


def _load():
    global _DATA
    if _DATA is None:
        with open(os.path.join(os.path.dirname(__file__), "axis_cip_data.json")) as fh:
            d = json.load(fh)
        d["enum_vocab"] = {a: {int(k): v for k, v in voc.items()}
                           for a, voc in d["enum_vocab"].items()}
        d["tok_vocab"] = {a: {int(k): v for k, v in voc.items()}
                          for a, voc in d["tok_vocab"].items()}
        d["list_vocab"] = {a: {int(k): v for k, v in voc.items()}
                           for a, voc in d["list_vocab"].items()}
        d["motor_unit_map"] = {k: v for k, v in d["motor_unit_map"].items()}
        _DATA = d
    return _DATA


def _render_attr(a, b, D, group_name, modid_to_name):
    """Render one attribute value string, or None if unreconstructable."""
    if a == "MotionGroup":
        return group_name
    if a == "MotionModule":
        p = D["attrs"][a]
        modid = struct.unpack_from(_INT[p["id_w"]], b, p["id_off"])[0]
        name = modid_to_name.get(modid)
        if not name:
            return None
        chan = b[p["chan_off"]] if p.get("chan_off") is not None else None
        return "%s:Ch%d" % (name, chan) if chan is not None else name
    p = D["attrs"].get(a)
    if p is None:
        return None
    k = p.get("render")
    try:
        if k == "float":
            return _tag_value._fmt_real_decorated(struct.unpack_from("<f", b, p["off"])[0])
        if k == "int":
            return str(struct.unpack_from(_INT[p["w"]], b, p["off"])[0])
        if k == "hex":
            w = p.get("w", 4)
            return _tag_value._format_int_radix({2: "UINT", 4: "UDINT"}[w],
                                                struct.unpack_from(_INT[w], b, p["off"])[0], w, "Hex")
        if k == "enum":
            return D["enum_vocab"].get(a, {}).get(
                struct.unpack_from(_INT[p["w"]], b, p["off"])[0])
        if k == "const":
            return p["value"]
        if k == "derive_motor_unit":
            mt_off = D["motortype_off"]
            if mt_off is None:
                return None
            mt = D["enum_vocab"].get("MotorType", {}).get(b[mt_off])
            us = D["motor_unit_map"].get(mt)
            return us[0] if us and len(us) == 1 else None
        if k == "ascii":
            ln = struct.unpack_from("<H", b, p["lenoff"])[0]
            return b[p["off"]:p["off"] + ln].decode("latin1")
        if k == "farr":
            return " ".join(_tag_value._fmt_real_decorated(x)
                            for x in struct.unpack_from("<%df" % p["K"], b, p["off"]))
        if k == "decarr":
            return " ".join(str(x) for x in b[p["off"]:p["off"] + p["K"]])
        if k == "tokarr":
            voc = D["tok_vocab"].get(a, {})
            out = []
            for j in range(p["K"]):
                t = voc.get(b[p["off"] + j])
                if t is None:
                    return None
                out.append(t)
            return " ".join(out)
        if k == "u16list":
            n = struct.unpack_from("<H", b, p["countoff"])[0]
            codes = struct.unpack_from("<%dH" % n, b, p["codesoff"]) if n else ()
            voc = D["list_vocab"].get(a, {})
            out = []
            for c in codes:
                t = voc.get(c)
                if t is None:
                    return None
                out.append(t)
            return " ".join(out)
    except Exception:
        return None
    return None


def _emit_set(b, D, cfg_model):
    """The ordered set of attributes this axis emits, per the capability bitmap
    + content presence. Returns a set of attr names."""
    out = set(cfg_model["always"])
    for a, off in cfg_model["content"].items():
        if struct.unpack_from("<H", b, off)[0] > 0:
            out.add(a)
    for repr_a, gs in cfg_model["groups"].items():
        g = gs["gate"]
        if not g:
            continue
        if g[0] == "const":
            v = bool(g[1])
        else:
            _, off, bit, neg = g
            v = bool((b[off] >> bit) & 1) ^ bool(neg)
        if v:
            out.update(gs["attrs"])
    return out


def render_axis_cip_drive(blob, group_name, modid_to_name):
    """Full ``<Data Format="Axis">`` block for a CIP-drive axis, or None.

    None on any unrecognised/unreconstructable condition, so the caller keeps
    the tag's prior no-<Data> output (0-worse).
    """
    try:
        D = _load()
        b = bytes(blob)
        if len(b) != D["len"]:
            return None
        acfg = D["enum_vocab"].get("AxisConfiguration", {}).get(
            struct.unpack_from(_INT[D["attrs"]["AxisConfiguration"]["w"]], b,
                               D["attrs"]["AxisConfiguration"]["off"])[0])
        cfg_model = D["emitset"].get(acfg)
        if cfg_model is None:
            return None
        emit = _emit_set(b, D, cfg_model)
        parts = []
        for a in D["order"]:
            if a not in emit:
                continue
            val = _render_attr(a, b, D, group_name, modid_to_name)
            if val is None:
                return None      # gate: any unreconstructable attr -> withhold
            parts.append('%s="%s"' % (a, html.escape(val, quote=True)))
        if not parts:
            return None
        joined = ""
        for i, part in enumerate(parts):
            if i:
                joined += "\n " if i % 11 == 0 else " "
            joined += part
        return '<Data Format="Axis">\n<AxisParameters ' + joined + '/>\n</Data>'
    except Exception:
        return None
