"""Decode an SFC (Sequential Function Chart) routine's ``<SFCContent>`` block.

An SFC routine's graphical content lives in the routine's ``nameless`` subtree --
the SAME storage ST routines use (see ``_st_content_lines`` in ``elements.py``).
Each subtree record self-links by object_id at record[12:16] and carries a u16
"kind" discriminator at record[16:18]. The SFC property-graph is:

  * 1003 Step (X/Y, operand, DescBox ref, flags, optional Preset expr, Action
    group ref), 1006 Transition (X/Y, operand, condition body), 1021 Stop,
  * 1005 Action (qualifier, operand, ST body), grouped under a 1004 action group,
  * 1017/1018 diverge/converge Selection Branch and 1019/1020 diverge/converge
    Simultaneous Branch (same layout, no Priority word), whose legs (1013/1014
    Selection, 1015/1016 Simultaneous) come from a 1012 leg-group's trailing
    hash array, 1007 DirectedLink (from/to hashes + Show),
  * 130 DescBox (DescX/DescY), 129 TextBox, 136 Attachment,
  * ST bodies: a 2003 container -> 2002 (ordered line-hash array) -> 2001 line
    records (FF FE FF + UTF-16LE text); operands use the shared ``@<hex>@`` ->
    comps.comp_name resolution (incl. the recursive ``&<parentHex><suffix>`` rule).

A per-record base shift ``d`` (0 for V33-era, -4 for V20-era) is auto-detected
from the Step->DescBox reference so the same offsets work across firmware.

L5X element IDs are assigned in order (steps+their actions, transitions,
branches+legs, stops, textboxes); links/attachments reference them by hash.
The document emits Stops AFTER the Branch elements (matching the reference)
even though Stop IDs precede the TextBox range. Branches sort by Y; a shared
Y is ordered by the per-element creation counter modern-layout (d == 0)
records persist at offset 20, or -- for old-layout (d == -4) files that store
no counter -- by replaying the exporter's unstable introsort over the whole
language-element collection (see ``sfc_order``). TextBoxes sort by (X, Y).

Fail-closed: any unrecognised record, an unresolved operand, a hash that does not
map to an emitted element, or an ambiguous base shift returns None, so the
routine keeps its prior empty ``<Routine>`` (element_missing) rather than emit a
wrong graph.

SHEET ATTRIBUTES: SheetSize/SheetOrientation are not yet located in the loaded
streams. This decoder emits the "Letter - 8.5 x 11 in"/"Landscape" default ONLY
when the routine carries no TextBox/Attachment/hidden DirectedLink (the empirical
correlate of a default sheet, 0 counterexamples across the pools); any other
routine fails closed. A non-default-sheet chart therefore stays element_missing
rather than risk a wrong SheetSize.
"""
import struct
import re
from xml.sax.saxutils import escape

from acd.l5x.sfc_order import Elem as _Elem, order_branches as _order_branches

_MARK = b"\xff\xfe\xff"
_AT = re.compile(r"@([0-9a-fA-F]+)@")
_QUALIFIER = {1: "NonStored", 5: "TimeDelayed", 7: "PulseRisingEdge", 8: "PulseFallingEdge"}
_STEP_MASK = 0x33
_SHEET = ('Letter - 8.5 x 11 in', 'Landscape')


def decode_sfc(cur, routine_oid, _prove_sheet=None, textbox_text=None,
               textbox_text_v20=None):
    try:
        def kids(oid):
            return [o for (o,) in cur.execute(
                "SELECT object_id FROM nameless WHERE parent_id=?", (oid,)).fetchall()]

        def disc(r):
            return struct.unpack_from("<H", r, 16)[0] if r and len(r) >= 18 else None

        def selfhash(r):
            return r[12:16]

        def deref(oid, depth=0):
            if depth > 6:
                return None
            row = cur.execute("SELECT comp_name FROM comps WHERE object_id=?", (oid,)).fetchone()
            if not row or not row[0]:
                return None
            nm = row[0]
            m = re.match(r"^&([0-9a-fA-F]+)(.*)$", nm)
            if m:
                p = deref(int(m.group(1), 16), depth + 1)
                return (p + m.group(2)) if p is not None else None
            return nm

        def read_text(r):
            j = r.find(_MARK)
            if j < 0:
                return None
            n = r[j + 3]
            p = j + 4
            if n == 0xFF:
                n = struct.unpack_from("<H", r, j + 4)[0]
                p = j + 6
            if len(r) < p + 2 * n:
                return None
            t = r[p:p + 2 * n].decode("utf-16-le")
            return _AT.sub(lambda mo: deref(int(mo.group(1), 16)) or "\x00FAIL\x00", t)

        def trailing_op(r):
            j = r.rfind(_MARK)
            if j < 0:
                return None
            return read_text(r[j:])

        subtree = {}
        byhash = {}
        frontier = [routine_oid]
        seen = set()
        while frontier:
            nx = []
            for pid in frontier:
                for coid, crec in cur.execute(
                        "SELECT object_id, record FROM nameless WHERE parent_id=?", (pid,)).fetchall():
                    if coid in seen:
                        continue
                    seen.add(coid)
                    nx.append(coid)
                    crec = bytes(crec)
                    subtree[coid] = crec
                    if len(crec) >= 16:
                        byhash[bytes(crec[12:16])] = coid
            frontier = nx

        def by_h(h):
            o = byhash.get(bytes(h))
            return subtree.get(o) if o is not None else None

        step_recs = [(o, r) for o, r in subtree.items() if disc(r) == 1003]
        if not step_recs:
            return None
        d = None
        for cand in (0, -4):
            ok = True
            for _, r in step_recs:
                off = 36 + cand
                if len(r) < off + 4:
                    ok = False
                    break
                db = by_h(r[off:off + 4])
                if db is None or disc(db) != 130:
                    ok = False
                    break
            if ok:
                if d is not None:
                    return None
                d = cand
        if d is None:
            return None

        def u32(r, off):
            return struct.unpack_from("<I", r, off)[0]

        def read_lines(block_oid_or_rec):
            r = block_oid_or_rec if isinstance(block_oid_or_rec, (bytes, bytearray)) else subtree.get(block_oid_or_rec)
            if r is None:
                return None
            bhash = selfhash(r)
            boid = byhash.get(bytes(bhash))
            cont = None
            for c in kids(boid):
                if disc(subtree.get(c)) == 2002:
                    cont = c
                    break
            if cont is None:
                return None
            cr = subtree[cont]
            co = 24 + d
            if len(cr) < co + 2:
                return None
            count = struct.unpack_from("<H", cr, co)[0]
            ao = co + 2
            if len(cr) < ao + 4 * count:
                return None
            order = [cr[ao + 4 * i:ao + 4 * i + 4] for i in range(count)]
            line_by = {}
            for c in kids(cont):
                cc = subtree.get(c)
                if disc(cc) == 2001:
                    t = read_text(cc)
                    if t is None or "\x00FAIL\x00" in t:
                        return None
                    line_by[bytes(selfhash(cc))] = t
            out = []
            for h in order:
                if bytes(h) not in line_by:
                    return None
                out.append(line_by[bytes(h)])
            return out

        def descbox(ref):
            r = by_h(ref)
            if r is None or disc(r) != 130:
                return None
            if len(r) != 32 + d:
                return None
            return u32(r, 24 + d), u32(r, 28 + d), 0

        steps = []
        transitions = []
        stops = []
        div_b = []
        conv_b = []
        sdiv_b = []
        sconv_b = []
        textboxes = []
        attachments = []
        for oid, r in subtree.items():
            dd = disc(r)
            if dd == 1003:
                steps.append((oid, r))
            elif dd == 1006:
                transitions.append((oid, r))
            elif dd == 1021:
                stops.append((oid, r))
            elif dd == 1017:
                div_b.append((oid, r))
            elif dd == 1018:
                conv_b.append((oid, r))
            elif dd == 1019:
                sdiv_b.append((oid, r))
            elif dd == 1020:
                sconv_b.append((oid, r))
            elif dd == 129:
                textboxes.append((oid, r))
            elif dd == 136:
                attachments.append((oid, r))

        def parse_action(oid, r):
            if len(r) < 36 + d:
                return None
            qual = _QUALIFIER.get(u32(r, 32 + d))
            if qual is None:
                return None
            op = trailing_op(r)
            if not op or "\x00" in op:
                return None
            body = None
            for c in kids(oid):
                cc = subtree.get(c)
                if disc(cc) == 2003 and len(cc) >= 28 + d and u32(cc, 24 + d) == 2:
                    if body is not None:
                        return None
                    body = cc
            if body is None:
                return None
            lines = read_lines(body)
            if lines is None:
                return None
            return dict(op=op, qual=qual, lines=lines)

        def parse_step(oid, r):
            if len(r) < 60 + d:
                return None
            X = u32(r, 24 + d)
            Y = u32(r, 28 + d)
            flags = u32(r, 40 + d)
            if flags & ~_STEP_MASK:
                return None
            op = trailing_op(r)
            if not op or "\x00" in op:
                return None
            db = descbox(r[36 + d:40 + d])
            if db is None:
                return None
            PresetExpr = bool(flags & 0x20)
            preset = None
            if PresetExpr:
                pr = by_h(r[44 + d:48 + d])
                if pr is None:
                    return None
                preset = read_lines(pr)
                if preset is None:
                    return None
            agr = by_h(r[56 + d:60 + d])
            acts = []
            if agr is not None and disc(agr) == 1004:
                ago = byhash.get(bytes(selfhash(agr)))
                for c in kids(ago):
                    cc = subtree.get(c)
                    if disc(cc) == 1005:
                        a = parse_action(c, cc)
                        if a is None:
                            return None
                        acts.append(a)
            return dict(hash=bytes(selfhash(r)), X=X, Y=Y, op=op, db=db,
                        Initial=bool(flags & 0x02), Show=bool(flags & 0x10),
                        PresetExpr=PresetExpr, preset=preset, actions=acts)

        def parse_trans(oid, r):
            if len(r) < 48 + d:
                return None
            if r[32 + d:36 + d] != b"\x00\x00\x00\x00":
                return None
            X = u32(r, 24 + d)
            Y = u32(r, 28 + d)
            op = trailing_op(r)
            if not op or "\x00" in op:
                return None
            db = descbox(r[36 + d:40 + d])
            if db is None:
                return None
            co = by_h(r[40 + d:44 + d])
            if co is None:
                return None
            lines = read_lines(co)
            if lines is None:
                return None
            return dict(hash=bytes(selfhash(r)), X=X, Y=Y, op=op, db=db, cond=lines)

        def parse_stop(oid, r):
            if len(r) < 44 + d:
                return None
            if r[32 + d:36 + d] != b"\x00\x00\x00\x00":
                return None
            X = u32(r, 24 + d)
            Y = u32(r, 28 + d)
            op = trailing_op(r)
            if not op or "\x00" in op:
                return None
            db = descbox(r[36 + d:40 + d])
            if db is None:
                return None
            return dict(hash=bytes(selfhash(r)), X=X, Y=Y, op=op, db=db)

        def leg_hashes(grp_ref):
            r = by_h(grp_ref)
            if r is None or disc(r) != 1012:
                return None
            co = 24 + d
            if len(r) < co + 2:
                return None
            cnt = struct.unpack_from("<H", r, co)[0]
            ao = co + 2
            if cnt < 1 or len(r) < ao + 4 * cnt:
                return None
            return [bytes(r[ao + 4 * i:ao + 4 * i + 4]) for i in range(cnt)]

        _LEG_KIND = {("Selection", "Diverge"): 1013, ("Selection", "Converge"): 1014,
                     ("Simultaneous", "Diverge"): 1015, ("Simultaneous", "Converge"): 1016}

        def parse_branch(r, flow, btype):
            # only a Selection Diverge carries the trailing Priority word
            has_prio = (flow == "Diverge" and btype == "Selection")
            need = (40 if has_prio else 36) + d
            if len(r) < need:
                return None
            Y = u32(r, 28 + d)
            priority = None
            if has_prio:
                if r[36 + d:40 + d] != b"\x01\x00\x00\x00":
                    return None
                priority = "Default"
            legs = leg_hashes(r[32 + d:36 + d])
            if legs is None:
                return None
            want = _LEG_KIND[(btype, flow)]
            for lh in legs:
                lr = by_h(lh)
                if lr is None or disc(lr) != want:
                    return None
            return dict(hash=bytes(selfhash(r)), Y=Y, flow=flow, btype=btype,
                        priority=priority, legs=legs)

        def parse_textbox(r):
            if len(r) != 32:
                return None
            X = u32(r, 24 + d)
            Y = u32(r, 28 + d)
            if d == 0:
                # modern: record[20:24] is the global md id linking the MD_ text
                md = u32(r, 20 + d)
            else:
                # V20: record[28:32] is the FO text index (0xFFFFFFFF = no text),
                # the layout slot the modern md occupied is X here.
                raw = u32(r, 28)
                md = None if raw == 0xFFFFFFFF else raw
            return dict(hash=bytes(selfhash(r)), X=X, Y=Y, md=md)

        def parse_attachment(r):
            if len(r) < 32 + d:
                return None
            return (bytes(r[24 + d:28 + d]), bytes(r[28 + d:32 + d]))

        S = []
        for oid, r in steps:
            p = parse_step(oid, r)
            if p is None:
                return None
            S.append(p)
        T = []
        for oid, r in transitions:
            p = parse_trans(oid, r)
            if p is None:
                return None
            T.append(p)
        P = []
        for oid, r in stops:
            p = parse_stop(oid, r)
            if p is None:
                return None
            P.append(p)
        B = []
        for lst, flow, btype in ((div_b, "Diverge", "Selection"),
                                 (conv_b, "Converge", "Selection"),
                                 (sdiv_b, "Diverge", "Simultaneous"),
                                 (sconv_b, "Converge", "Simultaneous")):
            for oid, r in lst:
                p = parse_branch(r, flow, btype)
                if p is None:
                    return None
                B.append(p)
        TB = []
        for oid, r in textboxes:
            p = parse_textbox(r)
            if p is None:
                return None
            TB.append(p)
        AT = []
        for oid, r in attachments:
            p = parse_attachment(r)
            if p is None:
                return None
            AT.append(p)
        if not S and not T and not P:
            return None

        if _prove_sheet is None:
            if TB or AT or any(
                    disc(r) == 1007 and u32(r, len(r) - 4) != 0 for r in subtree.values()):
                return None
            sheet = _SHEET
        else:
            sheet = _prove_sheet

        S.sort(key=lambda s: s["op"])
        T.sort(key=lambda t: t["op"])
        P.sort(key=lambda p: p["op"])
        # Branch bars can legitimately share a Y (side-by-side parallel
        # structures), and the exporter's order for a tied group differs by
        # firmware layout:
        #   * modern layout (d == 0) persists a per-element creation counter in
        #     the u32 at offset 20 -- the field whose presence IS the d shift --
        #     and the reference orders same-Y bars by it, ascending.
        #   * old layout (d == -4) stores no such counter; the tie order is the
        #     emergent result of the exporter running the routine's whole
        #     language-element collection through an unstable introsort. We
        #     replay that byte-exact (sfc_order), keyed on the record self-hash
        #     enumeration order -- see acd/l5x/sfc_order.py.
        if d == 0:
            by_y = {}
            for b in B:
                by_y.setdefault(b["Y"], []).append(b)
            ordered = []
            for y in sorted(by_y):
                grp = by_y[y]
                if len(grp) > 1:
                    uids = [u32(subtree[bo], 20) for bo in
                            (byhash[b["hash"]] for b in grp)]
                    if len(set(uids)) != len(uids):
                        return None
                    grp = [b for _u, b in
                           sorted(zip(uids, grp), key=lambda t: t[0])]
                ordered.extend(grp)
            B = ordered
        else:
            elems = [_Elem(1003, s["hash"], s["X"], s["Y"], s["op"], s) for s in S]
            elems += [_Elem(1006, t["hash"], t["X"], t["Y"], t["op"], t) for t in T]
            elems += [_Elem(1021, p["hash"], p["X"], p["Y"], p["op"], p) for p in P]
            elems += [_Elem(1017, b["hash"], 0, b["Y"], "", b) for b in B]
            B = _order_branches(elems)
        if len({(t["X"], t["Y"]) for t in TB}) != len(TB):
            return None
        TB.sort(key=lambda t: (t["X"], t["Y"]))
        nid = 0
        id_by_hash = {}
        for s in S:
            s["id"] = nid
            id_by_hash[s["hash"]] = nid
            nid += 1
            for a in sorted(s["actions"], key=lambda a: a["op"]):
                a["id"] = nid
                nid += 1
        for t in T:
            t["id"] = nid
            id_by_hash[t["hash"]] = nid
            nid += 1
        for b in B:
            b["id"] = nid
            id_by_hash[b["hash"]] = nid
            nid += 1
            b["legids"] = []
            for lh in b["legs"]:
                id_by_hash[lh] = nid
                b["legids"].append(nid)
                nid += 1
        for p in P:
            p["id"] = nid
            id_by_hash[p["hash"]] = nid
            nid += 1
        for t in TB:
            t["id"] = nid
            id_by_hash[t["hash"]] = nid
            nid += 1

        links = []
        for r in subtree.values():
            if disc(r) == 1007:
                if len(r) < 36 + d:
                    return None
                if u32(r, 28 + d) != 1:
                    return None
                fh = bytes(r[24 + d:28 + d])
                th = bytes(r[32 + d:36 + d])
                if fh not in id_by_hash or th not in id_by_hash:
                    return None
                show = "false" if u32(r, len(r) - 4) != 0 else "true"
                links.append((id_by_hash[fh], id_by_hash[th], show))
        links.sort(key=lambda x: (x[0], x[1]))

        atts = []
        for fh, th in AT:
            if fh not in id_by_hash or th not in id_by_hash:
                return None
            atts.append((id_by_hash[fh], id_by_hash[th]))
        atts.sort()

        def stcontent(lines):
            o = ['<STContent>']
            for i, ln in enumerate(lines):
                o.append('<Line Number="%d"><![CDATA[%s]]></Line>' % (i, ln))
            o.append('</STContent>')
            return o

        out = ['<SFCContent SheetSize="%s" SheetOrientation="%s">' % (sheet[0], sheet[1])]
        for s in S:
            dx, dy, dw = s["db"]
            attrs = ('ID="%d" X="%d" Y="%d" Operand="%s" '
                     'HideDesc="false" DescX="%d" DescY="%d" DescWidth="%d" '
                     'InitialStep="%s" PresetUsesExpr="%s" '
                     'LimitHighUsesExpr="false" LimitLowUsesExpr="false" ShowActions="%s"'
                     % (s["id"], s["X"], s["Y"], escape(s["op"]), dx, dy, dw,
                        str(s["Initial"]).lower(), str(s["PresetExpr"]).lower(),
                        str(s["Show"]).lower()))
            body = []
            if s["PresetExpr"]:
                body.append('<Preset>')
                body += stcontent(s["preset"])
                body.append('</Preset>')
            for a in sorted(s["actions"], key=lambda a: a["id"]):
                body.append('<Action ID="%d" Operand="%s" Qualifier="%s" '
                            'IsBoolean="false" PresetUsesExpr="false">'
                            % (a["id"], escape(a["op"]), a["qual"]))
                body.append('<Body>')
                body += stcontent(a["lines"])
                body.append('</Body>')
                body.append('</Action>')
            if body:
                out.append('<Step %s>' % attrs)
                out += body
                out.append('</Step>')
            else:
                out.append('<Step %s/>' % attrs)
        for t in T:
            dx, dy, dw = t["db"]
            out.append('<Transition ID="%d" X="%d" Y="%d" Operand="%s" '
                       'HideDesc="false" DescX="%d" DescY="%d" DescWidth="%d">'
                       % (t["id"], t["X"], t["Y"], escape(t["op"]), dx, dy, dw))
            out.append('<Condition>')
            out += stcontent(t["cond"])
            out.append('</Condition>')
            out.append('</Transition>')
        for b in B:
            if b["priority"] is not None:
                out.append('<Branch ID="%d" Y="%d" BranchType="%s" '
                           'BranchFlow="Diverge" Priority="%s">'
                           % (b["id"], b["Y"], b["btype"], b["priority"]))
            else:
                out.append('<Branch ID="%d" Y="%d" BranchType="%s" '
                           'BranchFlow="%s">'
                           % (b["id"], b["Y"], b["btype"], b["flow"]))
            for lid in b["legids"]:
                out.append('<Leg ID="%d"/>' % lid)
            out.append('</Branch>')
        # the reference emits Stops after the Branch elements (their IDs
        # already follow the branch/leg range)
        for p in P:
            dx, dy, dw = p["db"]
            out.append('<Stop ID="%d" X="%d" Y="%d" Operand="%s" '
                       'HideDesc="false" DescX="%d" DescY="%d" DescWidth="%d"/>'
                       % (p["id"], p["X"], p["Y"], escape(p["op"]), dx, dy, dw))
        for fr, to, show in links:
            out.append('<DirectedLink FromID="%d" ToID="%d" Show="%s"/>' % (fr, to, show))
        # modern textboxes resolve text by global md id; V20 (old-layout)
        # textboxes resolve by the FO index carried in record[28:32]. A file is
        # exclusively one layout, so the two maps never overlap.
        _tbmap = textbox_text if d == 0 else textbox_text_v20
        for t in TB:
            txt = None if t["md"] is None else (_tbmap or {}).get(t["md"])
            if txt is None:
                out.append('<TextBox ID="%d" X="%d" Y="%d" Width="0"/>'
                           % (t["id"], t["X"], t["Y"]))
            else:
                out.append('<TextBox ID="%d" X="%d" Y="%d" Width="0">'
                           '<Text><![CDATA[%s]]></Text></TextBox>'
                           % (t["id"], t["X"], t["Y"], txt))
        for fr, to in atts:
            out.append('<Attachment FromID="%d" ToID="%d"/>' % (fr, to))
        out.append('</SFCContent>')
        return "\n".join(out)
    except Exception:
        return None
