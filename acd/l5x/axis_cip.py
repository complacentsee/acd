"""Render the ``<Data>`` blocks for motion tags (drive axes and motion groups).

The axis config image (attr 0x01 of the cip-0x6a backing, body_mode) is a flat
fixed-offset struct keyed by its byte length and SHARED across axis datatypes
(the datatype only decides which attributes the L5X emits). Every supported
length was reverse-engineered from the pool differentials plus the tracer
round-trip and validated byte-exact against the OEM export on every in-pool
instance before being added here (see acd/docs/motion-axis-data-status.md).

Everything is data-driven from ``axis_cip_data.json``, keyed by blob length:
  * per-attribute VALUE decode (offset + kind + per-length enum/token/list
    vocab — code spaces differ across firmware generations), plus documented
    derivations (MotorUnit/Feedback1Unit follow the motor's rotary/linear
    type) and corpus-constant fields (uniform across every instance of two
    independent pools, emitted only under the fail-closed gates below);
  * the EMIT-SET: which attributes a given axis emits — capability bits and
    content-presence fields read from the blob, grouped per datatype and
    keyed on a profile attribute (AxisConfiguration for CIP drives,
    ServoLoopConfiguration for servo drives), with optional ``require``
    gates for sub-profiles that are only valid in a proven state;
  * the per-length global emit ORDER;
  * a small separate schema for MOTION_GROUP ``<MotionGroupParameters>``.

Fail-closed: any unrecognised length, datatype, profile value, gate kind,
enum code, unresolved MotionModule, or ambiguous derivation returns None, so
the tag keeps its prior no-<Data> output (element_missing) rather than emit a
wrong (net-worse) block.
"""
import html
import json
import os
import struct
from typing import Dict, Union

from acd.l5x import tag_value as _tag_value

_DATA = None
_INT = {1: "B", 2: "<H", 4: "<I"}


def _intkeys(voc):
    return {int(k): v for k, v in voc.items()}


def _load():
    global _DATA
    if _DATA is None:
        with open(os.path.join(os.path.dirname(__file__), "axis_cip_data.json")) as fh:
            d = json.load(fh)
        for e in d["lengths"].values():
            for tbl in ("enum_vocab", "tok_vocab", "list_vocab"):
                e[tbl] = {a: _intkeys(voc) for a, voc in e.get(tbl, {}).items()}
        for m in d.get("motion_group", {}).get("lengths", {}).values():
            for p in m["attrs"].values():
                if "vocab" in p:
                    p["vocab"] = _intkeys(p["vocab"])
        _DATA = d
    return _DATA


def _gate(b, g):
    """Evaluate one emit-gate expression against the blob.

    True/False per the gate; None for an unknown kind (callers fail closed).
    """
    k = g[0]
    if k == "const":
        return bool(g[1])
    if k == "bit":
        _, off, bit, neg = g
        return bool((b[off] >> bit) & 1) ^ bool(neg)
    if k == "u8nz":
        return b[g[1]] != 0
    if k == "u8eq":
        return b[g[1]] == g[2]
    if k == "u16nz":
        return struct.unpack_from("<H", b, g[1])[0] != 0
    if k == "u16eq":
        return struct.unpack_from("<H", b, g[1])[0] == g[2]
    if k == "u32nz":
        return struct.unpack_from("<I", b, g[1])[0] != 0
    if k == "f32nz":
        return struct.unpack_from("<f", b, g[1])[0] != 0.0
    return None


def _render_attr(a, b, E, group_name, modid_to_name):
    """Render one attribute value string, or None if unreconstructable."""
    if a == "MotionGroup":
        return group_name or None
    p = E["attrs"].get(a)
    if p is None:
        return None
    if a == "MotionModule":
        modid = struct.unpack_from(_INT[p["id_w"]], b, p["id_off"])[0]
        if modid == 0 and p.get("id0_renders"):
            return p["id0_renders"]
        name = modid_to_name.get(modid)
        if not name:
            return None
        chan = b[p["chan_off"]] if p.get("chan_off") is not None else None
        return "%s:Ch%d" % (name, chan) if chan is not None else name
    k = p.get("render")
    try:
        if k == "float":
            return _tag_value._fmt_real_decorated(struct.unpack_from("<f", b, p["off"])[0])
        if k == "float_negzero":
            v = struct.unpack_from("<f", b, p["off"])[0]
            if v == 0.0:
                v = 0.0      # normalize -0.0 (the stored form) to the emitted 0
            return _tag_value._fmt_real_decorated(v)
        if k == "int":
            return str(struct.unpack_from(_INT[p["w"]], b, p["off"])[0])
        if k == "hex":
            w = p.get("w", 4)
            return _tag_value._format_int_radix({2: "UINT", 4: "UDINT"}[w],
                                                struct.unpack_from(_INT[w], b, p["off"])[0], w, "Hex")
        if k == "enum":
            return E["enum_vocab"].get(a, {}).get(
                struct.unpack_from(_INT[p["w"]], b, p["off"])[0])
        if k == "const":
            return p["value"]
        if k == "derive_motor_unit":
            mt_off = E.get("motortype_off")
            if mt_off is None:
                return None
            mt = E["enum_vocab"].get("MotorType", {}).get(b[mt_off])
            us = E.get("motor_unit_map", {}).get(mt)
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
            voc = E["tok_vocab"].get(a, {})
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
            voc = E["list_vocab"].get(a, {})
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


def _emit_set(b, model):
    """The set of attributes this axis emits, per the model's content-presence
    fields and gated capability groups. None if a gate kind is unknown."""
    out = set(model["always"])
    for a, off in model.get("content", {}).items():
        if struct.unpack_from("<H", b, off)[0] > 0:
            out.add(a)
    for gs in model.get("groups", {}).values():
        g = gs.get("gate")
        if not g:
            continue
        v = _gate(b, g)
        if v is None:
            return None
        if v:
            out.update(gs["attrs"])
    return out


def render_axis_cip_drive(blob, group_name, modid_to_name,
                          data_type="AXIS_CIP_DRIVE"):
    """Full ``<Data Format="Axis">`` block for a drive axis, or None.

    None on any unrecognised/unreconstructable condition, so the caller keeps
    the tag's prior no-<Data> output (0-worse).
    """
    try:
        D = _load()
        b = bytes(blob)
        E = D["lengths"].get(str(len(b)))
        if E is None:
            return None
        dt_models = E.get("emitset", {}).get(data_type)
        if dt_models is None:
            return None
        key_attr = E.get("emitset_key", {}).get(data_type)
        if key_attr:
            profile = E["enum_vocab"].get(key_attr, {}).get(
                struct.unpack_from(_INT[E["attrs"][key_attr]["w"]], b,
                                   E["attrs"][key_attr]["off"])[0])
            cfg_model = dt_models.get(profile) if profile is not None else None
        else:
            cfg_model = dt_models.get("default")
        if cfg_model is None:
            return None
        for g in cfg_model.get("require", []):
            if _gate(b, g) is not True:
                return None
        emit = _emit_set(b, cfg_model)
        if emit is None:
            return None
        parts = []
        for a in E["order"]:
            if a not in emit:
                continue
            val = _render_attr(a, b, E, group_name, modid_to_name)
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


def render_motion_group(blob):
    """Full ``<Data Format="MotionGroup">`` block for a MOTION_GROUP tag, or
    None (same fail-closed contract as the axis renderer)."""
    try:
        D = _load()
        b = bytes(blob)
        M = D.get("motion_group", {}).get("lengths", {}).get(str(len(b)))
        if M is None:
            return None
        parts = []
        for a in M["emit"]:
            p = M["attrs"].get(a)
            if p is None:
                return None
            k = p.get("render")
            if k == "int":
                val = str(struct.unpack_from(_INT[p["w"]], b, p["off"])[0])
            elif k == "enum":
                val = p.get("vocab", {}).get(
                    struct.unpack_from(_INT[p["w"]], b, p["off"])[0])
            elif k == "const":
                val = p["value"]
            else:
                return None
            if val is None:
                return None
            parts.append('%s="%s"' % (a, html.escape(val, quote=True)))
        if not parts:
            return None
        return ('<Data Format="MotionGroup">\n<MotionGroupParameters '
                + " ".join(parts) + '/>\n</Data>')
    except Exception:
        return None
