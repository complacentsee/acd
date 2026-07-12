"""Alarm domain: ALARM_DIGITAL tag data and V33+ embedded alarm conditions.

``_render_alarm_digital_data`` renders an ALARM_DIGITAL tag's parameter data
block from its nameless value record; ``_build_alarm_conditions`` /
``_render_alarm_conditions`` recover the V33+ tag-embedded <AlarmConditions>
from RxConfiguredAlarmCollection children; ``_alarm_definitions_xml`` emits
the controller-level <AlarmDefinitions> section from
RxAlarmConditionDefinitionCollection.
"""
import html
import re
import struct
from typing import Dict, List

from acd.record.comps import CompsRecord


# Boolean <AlarmCondition> attributes the reference always emits "false" (none of
# the ~1500 pool conditions has any of these set). Severity-bit fields cover only
# Used/AlarmSet*/AckRequired (see _build_alarm_conditions).
# AlarmDigitalParameters boolean attributes in OEM order; bit i of the backing
# AlarmControlFlags word (V20/21 short-header form, 20 bits).
_ADP_BITS = (
    "EnableIn", "In", "InFault", "Condition", "AckRequired", "Latched",
    "ProgAck", "OperAck", "ProgReset", "OperReset", "ProgSuppress", "OperSuppress",
    "ProgUnsuppress", "OperUnsuppress", "ProgDisable", "OperDisable", "ProgEnable",
    "OperEnable", "AlarmCountReset", "UseProgTime",
)


def _render_alarm_digital_data(cur, short_header, dti):
    """Render an ALARM_DIGITAL tag's <Data Format="Alarm"> block, or None.

    The configuration lives in the tag's cip-0x6a data-table backing (object id ==
    data_table_instance): ext-attr 0x01 carries a 20-bit AlarmControlFlags word at
    offset 141, Severity (DINT @145), MinDurationPRE (DINT @149), and a u16 message
    join key (@0) that joins into the alarm_messages side table. V20/21 short-header
    form only. Returns None on any failure so the tag keeps its prior no-<Data>.
    """
    try:
        if not dti:
            return None
        e1 = CompsRecord.record_attrs(cur, dti, short_header).get(0x01, b"")
        if len(e1) < 153:
            return None
        flags = struct.unpack_from("<I", e1, 141)[0]
        severity = struct.unpack_from("<i", e1, 145)[0]
        min_dur = struct.unpack_from("<i", e1, 149)[0]
        joinkey = struct.unpack_from("<H", e1, 0)[0]
        attrs = [f'Severity="{severity}"', f'MinDurationPRE="{min_dur}"',
                 'ProgTime="DT#1970-01-01-00:00:00.000000Z"']
        for i, name in enumerate(_ADP_BITS):
            attrs.append(f'{name}="{"true" if (flags >> i) & 1 else "false"}"')
        adp = "<AlarmDigitalParameters " + " ".join(attrs) + " />"
        mrow = cur.execute(
            "SELECT mtype, text FROM alarm_messages WHERE joinkey=?",
            (joinkey,)).fetchone()
        if mrow and mrow[1]:
            msg = (f'<Messages>\n<Message Type="{html.escape(mrow[0], quote=True)}">\n'
                   f'<Text Lang="en-US">\n{html.escape(mrow[1])}\n</Text>\n'
                   f'</Message>\n</Messages>')
        else:
            msg = "<Messages />"
        return f'<Data Format="Alarm">\n{adp}\n<AlarmConfig>\n{msg}\n</AlarmConfig>\n</Data>'
    except Exception:
        return None


_ALARM_FALSE_BOOLS = (
    "InFault", "Latched", "ProgAck", "OperAck", "ProgReset", "OperReset",
    "ProgSuppress", "OperSuppress", "ProgUnsuppress", "OperUnsuppress",
    "OperShelve", "ProgUnshelve", "OperUnshelve", "ProgDisable", "OperDisable",
    "ProgEnable", "OperEnable", "AlarmCountReset",
)


_ALARM_CT_EXPR = {"TRIP": "= 1", "LO": "<=", "HI": ">="}


def _alarm_f32(rec, off):
    """Render an alarm f32 field the way OEM spells it (x.0 for whole values)."""
    v = struct.unpack_from("<f", rec, off)[0]
    return f"{v:.1f}" if v == int(v) else repr(v)


def _resolve_alarm_hex(s, oid2name):
    """Replace @hex@ object-id tokens with their comp_names; first token = owner.

    Returns (resolved_text, owner_oid, owner_name); owner_oid is None and
    owner_name "" when the string carries no token.
    """
    owner = None
    owner_name = ""
    out = []
    for i, p in enumerate(re.split(r"@([0-9A-Fa-f]+)@", s)):
        if i % 2 == 1:
            nm = oid2name.get(int(p, 16), "")
            if owner is None:
                owner_name = nm
                owner = int(p, 16)
            out.append(nm)
        else:
            out.append(p)
    return "".join(out), owner, owner_name


def _alarm_common_fields(rec, base):
    """The Limit..Deadband field block shared by _CA condition and _AD
    definition records (the two layouts differ only by where it starts)."""
    return {
        "Limit": _alarm_f32(rec, base),
        "Severity": str(struct.unpack_from("<H", rec, base + 4)[0]),
        "OnDelay": str(struct.unpack_from("<I", rec, base + 8)[0]),
        "OffDelay": str(struct.unpack_from("<I", rec, base + 12)[0]),
        "ShelveDuration": str(struct.unpack_from("<I", rec, base + 16)[0]),
        "MaxShelveDuration": str(struct.unpack_from("<I", rec, base + 20)[0]),
        "Deadband": _alarm_f32(rec, base + 24),
    }


def _build_alarm_conditions(cur, short_header):
    """Build per-tag <AlarmConditions> blocks from RxConfiguredAlarmCollection.

    Returns {owner_tag_object_id: rendered_<AlarmConditions>_xml}. The owning tag
    is the first @hex@ object-id token of the instance's Input reference (ext-attr
    0x6a); keying by object id (not name) is scope- and collision-safe.

    A tag's block is emitted ONLY when every one of its conditions decodes cleanly
    AND all condition Names within the block are DISTINCT -- duplicate names are
    matched by occurrence position in the comparator, so authored order (which is
    not recoverable) would matter; such blocks (and any partially-decoding tag) are
    omitted, leaving them as element_missing (never net-worse).
    """
    cur.execute("SELECT object_id FROM comps WHERE comp_name='RxConfiguredAlarmCollection'")
    row = cur.fetchone()
    if row is None:
        return {}
    coll = row[0]
    cur.execute("SELECT object_id, comp_name FROM comps")
    oid2name = {o: n for o, n in cur.fetchall()}
    # Definition suffix set (instances whose suffix matches emit AlarmConditionDefinition).
    def_suffixes = set()
    cur.execute("SELECT object_id FROM comps WHERE comp_name='RxAlarmConditionDefinitionCollection'")
    drow = cur.fetchone()
    if drow is not None:
        cur.execute("SELECT comp_name FROM comps WHERE parent_id=?", (drow[0],))
        for (n,) in cur.fetchall():
            m = re.match(r"_AD[0-9A-Fa-f]{8}_(.+)$", n)
            if m:
                def_suffixes.add(m.group(1))

    cur.execute(
        "SELECT comp_name, object_id, record FROM comps WHERE parent_id=? ORDER BY seq_number",
        (coll,))
    by_owner = {}  # owner_oid -> list of (cond_dict, ok_bool)
    for cname, oid, rec in cur.fetchall():
        rec = bytes(rec)
        ok = True
        try:
            nlen = struct.unpack_from("<H", rec, 0x5a)[0]
            name = rec[0x5c:0x5c + nlen].decode("ascii")
            ctlen = struct.unpack_from("<H", rec, 0x84)[0]
            ct = rec[0x86:0x86 + ctlen].decode("ascii")
            attrs = CompsRecord.record_attrs(cur, oid, short_header)
            in_s = attrs.get(0x6a, b"").decode("utf-16-le", errors="ignore").split("\x00")[0]
            inp, owner_oid, owner_name = _resolve_alarm_hex(in_s, oid2name)
            if owner_name and inp.startswith(owner_name):
                inp = inp[len(owner_name):]
            if inp == "":
                inp = "."
            assoc = None
            a66 = attrs.get(0x66, b"").decode("utf-16-le", errors="ignore").split("\x00")[0]
            if a66:
                ar, _, _ = _resolve_alarm_hex(a66, oid2name)
                if owner_name and ar.startswith(owner_name):
                    ar = ar[len(owner_name):]
                assoc = ar if ar else "."
            expr = _ALARM_CT_EXPR.get(ct)
            if owner_oid is None or expr is None or not name:
                ok = False
            flagA = struct.unpack_from("<H", rec, 0x196)[0]
            flagB = struct.unpack_from("<H", rec, 0x19a)[0]
            suf = re.match(r"_CA[0-9A-Fa-f]{8}_(.+)$", cname)
            acd = suf.group(1) if (suf and suf.group(1) in def_suffixes) else None
            jk = struct.unpack_from("<I", rec, 0x0a)[0]
            cam = cac = None
            cur.execute(
                "SELECT tag_reference, record_string FROM comments WHERE parent=? AND record_type=4",
                (jk,))
            for tr, rs in cur.fetchall():
                if tr == "CAM":
                    cam = rs
                elif tr == "CAC":
                    cac = rs
            cond = {
                "Name": name, "AlarmConditionDefinition": acd, "Input": inp,
                "ConditionType": ct,
                **_alarm_common_fields(rec, 0x19c),
                "Used": "true" if flagB & 1 else "false",
                "AlarmSetOperIncluded": "true" if flagB & 2 else "false",
                "AlarmSetRollupIncluded": "true" if flagB & 4 else "false",
                "AckRequired": "true" if flagA & 4 else "false",
                "EvaluationPeriod": "500 millisecond", "Expression": expr,
                "AssocTag1": assoc, "_cam": cam, "_cac": cac,
            }
        except Exception:
            owner_oid, cond, ok = None, None, False
        by_owner.setdefault(owner_oid, []).append((cond, ok))

    out = {}
    for owner_oid, conds in by_owner.items():
        if owner_oid is None:
            continue
        if not all(ok for _c, ok in conds):
            continue
        names = [c["Name"] for c, _ in conds]
        if len(names) != len(set(names)):  # duplicate names -> ordering matters; skip
            continue
        out[owner_oid] = _render_alarm_conditions([c for c, _ in conds])
    return out


def _render_alarm_conditions(conds):
    """Render a list of decoded condition dicts into an <AlarmConditions> block."""
    def _esc(v):
        return html.escape(v, quote=True)
    parts = ["<AlarmConditions>"]
    for c in conds:
        a = [f'Name="{_esc(c["Name"])}"']
        if c["AlarmConditionDefinition"] is not None:
            a.append(f'AlarmConditionDefinition="{_esc(c["AlarmConditionDefinition"])}"')
        a.append(f'Input="{_esc(c["Input"])}"')
        for k in ("ConditionType", "Limit", "Severity", "OnDelay", "OffDelay",
                  "ShelveDuration", "MaxShelveDuration", "Deadband", "Used",
                  "AlarmSetOperIncluded", "AlarmSetRollupIncluded"):
            a.append(f'{k}="{_esc(c[k])}"')
        a.append('InFault="false"')
        a.append(f'AckRequired="{c["AckRequired"]}"')
        for k in _ALARM_FALSE_BOOLS[1:]:  # skip InFault (already emitted)
            a.append(f'{k}="false"')
        a.append(f'EvaluationPeriod="{c["EvaluationPeriod"]}"')
        a.append(f'Expression="{_esc(c["Expression"])}"')
        if c["AssocTag1"] is not None:
            a.append(f'AssocTag1="{_esc(c["AssocTag1"])}"')
        cam, cac = c["_cam"], c["_cac"]
        if cam is None and cac is None:
            cfg = "<AlarmConfig/>"
        else:
            cfg = "<AlarmConfig>"
            if cam is not None:
                cfg += ('<Messages><Message Type="CAM"><Text Lang="en-US">\n'
                        f"<![CDATA[{cam}]]>\n</Text></Message></Messages>")
            if cac is not None:
                cfg += f"<AlarmClass>\n<![CDATA[{cac}]]>\n</AlarmClass>"
            cfg += "</AlarmConfig>"
        parts.append(f'<AlarmCondition {" ".join(a)}>{cfg}</AlarmCondition>')
    parts.append("</AlarmConditions>")
    return "".join(parts)


def _alarm_definitions_xml(cur, short_header):
    """The <AlarmDefinitions> element (per-datatype member alarm definitions),
    recovered from the _AD<hex>_<member> children of the controller's
    RxAlarmConditionDefinitionCollection; "" when the project defines none (so
    nothing is emitted -> 0 false-positive). Each member's fixed fields come from
    the raw comps record; Input (attr 0x6a) and AssocTag1 (attr 0x66) from the
    decrypted ext-attrs, with embedded @hex@ object_id tokens resolved to names and
    the owning-datatype prefix stripped. ADM message / ADC alarm-class text join via
    the comments table (record_type 4, keyed by the record's u32 @ 0x0a)."""
    row = cur.execute(
        "SELECT object_id FROM comps WHERE comp_name='RxAlarmConditionDefinitionCollection'"
    ).fetchone()
    if not row:
        return ""
    coll = row[0]
    oid2name = {o: n for o, n in cur.execute(
        "SELECT object_id, comp_name FROM comps").fetchall()}

    bydt: Dict[str, list] = {}
    dt_order: List[str] = []
    for cname, oid, rec in cur.execute(
            "SELECT comp_name, object_id, record FROM comps WHERE parent_id=? "
            "ORDER BY seq_number", (coll,)).fetchall():
        m = re.match(r'_AD[0-9A-Fa-f]{8}_(.+)$', cname)
        if not m:
            continue
        rec = bytes(rec)
        nlen = struct.unpack_from("<H", rec, 0x5a)[0]
        nm = rec[0x5c:0x5c + nlen].decode("ascii", "replace")
        ctlen = struct.unpack_from("<H", rec, 0x84)[0]
        ct = rec[0x86:0x86 + ctlen].decode("ascii", "replace")
        attrs = CompsRecord.record_attrs(cur, oid, short_header)
        ins = attrs.get(0x6a, b"").decode("utf-16-le", "ignore").split("\x00")[0]
        inp, _, ownn = _resolve_alarm_hex(ins, oid2name)
        if ownn and inp.startswith(ownn):
            inp = inp[len(ownn):]
        a66 = attrs.get(0x66, b"").decode("utf-16-le", "ignore").split("\x00")[0]
        assoc = None
        if a66:
            ar, _, _ = _resolve_alarm_hex(a66, oid2name)
            if ownn and ar.startswith(ownn):
                ar = ar[len(ownn):]
            assoc = ar if ar else "."
        flag_a = struct.unpack_from("<H", rec, 0x18e)[0]
        flag_b = struct.unpack_from("<H", rec, 0x192)[0]
        jk = struct.unpack_from("<I", rec, 0x0a)[0]
        adm = adc = None
        for tr, rs in cur.execute(
                "SELECT tag_reference, record_string FROM comments "
                "WHERE parent=? AND record_type=4", (jk,)).fetchall():
            txt, _, _ = _resolve_alarm_hex(rs, oid2name)
            if ownn:
                txt = txt.replace(ownn, "")
            if tr == "ADM":
                adm = txt
            elif tr == "ADC":
                adc = txt
        d = {
            "Name": nm, "Input": inp, "ConditionType": ct,
            **_alarm_common_fields(rec, 0x194),
            "Required": "true" if flag_b & 1 else "false",
            "AlarmSetOperIncluded": "true" if flag_b & 2 else "false",
            "AlarmSetRollupIncluded": "true" if flag_b & 4 else "false",
            "AckRequired": "true" if flag_a & 4 else "false",
            "Latched": "true" if flag_a & 8 else "false",
            "AssocTag1": assoc, "_adm": adm, "_adc": adc,
        }
        if ownn not in bydt:
            bydt[ownn] = []
            dt_order.append(ownn)
        bydt[ownn].append(d)
    if not dt_order:
        return ""

    def esc(v):
        return html.escape(v, quote=True)
    parts = ["<AlarmDefinitions>"]
    for dt in dt_order:
        parts.append(f'<DatatypeAlarmDefinition Name="{esc(dt)}">')
        for c in bydt[dt]:
            a = [f'Name="{esc(c["Name"])}"', f'Input="{esc(c["Input"])}"']
            for k in ("ConditionType", "Limit", "Severity", "OnDelay", "OffDelay",
                      "ShelveDuration", "MaxShelveDuration", "Deadband", "Required",
                      "AlarmSetOperIncluded", "AlarmSetRollupIncluded", "AckRequired",
                      "Latched"):
                a.append(f'{k}="{esc(c[k])}"')
            a.append('EvaluationPeriod="500 millisecond"')
            a.append('Expression="= 1"')
            if c["AssocTag1"] is not None:
                a.append(f'AssocTag1="{esc(c["AssocTag1"])}"')
            line = "<MemberAlarmDefinition " + " ".join(a)
            if c["_adm"] is None and c["_adc"] is None:
                parts.append(line + "/>")
            else:
                parts.append(line + ">")
                parts.append("<AlarmConfig>")
                if c["_adm"] is not None:
                    parts.extend(["<Messages>", '<Message Type="ADM">',
                                  '<Text Lang="en-US">', f'<![CDATA[{c["_adm"]}]]>',
                                  "</Text>", "</Message>", "</Messages>"])
                if c["_adc"] is not None:
                    parts.extend(["<AlarmClass>", f'<![CDATA[{c["_adc"]}]]>',
                                  "</AlarmClass>"])
                parts.append("</AlarmConfig>")
                parts.append("</MemberAlarmDefinition>")
        parts.append("</DatatypeAlarmDefinition>")
    parts.append("</AlarmDefinitions>")
    return "\n".join(parts)
