"""MESSAGE tag <Data Format="Message"> generation for the L5X exporter.

Decodes a MESSAGE tag's configuration struct (ext-attr 0x1 of its cip-0x6a
backing record) and resolves its CIP ConnectionPath against the module
topology; ``_render_message_data`` is the single entry point.
"""
import html
import re
import xml.etree.ElementTree as ET
from typing import Dict

from acd.generated.comps.message_config import MessageConfig
from acd.record.comps import CompsRecord


# --------------------------------------------------------------------------- #
# MESSAGE tag <Data Format="Message"> generator                               #
# --------------------------------------------------------------------------- #
# A MESSAGE tag's configuration is ext-attr 0x1 (a 354-byte struct) of its
# cip-0x6a backing record (object_id == the tag's data_table_instance). The
# struct trailer encodes the MessageType family (byte 353) and a service code
# (u16 @330); RequestedLength is u16 @139, ConnectedFlag is byte 143, and the
# CIP ConnectionPath is an EPATH (size u16 @144, bytes @146..) resolved against
# the module topology to a "Module, port, addr" string. LocalElement(0x65),
# DestinationTag(0x70) and RemoteElement(0x67) are UTF-16 member references.
# Only configurations decoded with full confidence are emitted; anything
# uncertain returns None so the tag keeps its prior no-<Data> output (the
# converter must never emit a wrong block -- that would score worse than the
# missing element it replaces).
_MSG_IPRE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _msg_route_segment(m) -> bytes:
    """The EPATH segment from a module's parent down to the module.

    Port byte = parent_mod_port_id (the parent port facing this module). The
    address comes from the module's UPSTREAM port (the rendered Upstream="true"
    port): an IP address yields an extended-link segment (0x10|port, len, ascii
    padded to even), a slot yields a 1-byte address. The module's own
    _ip_address must NOT be used directly -- a backplane-upstream bridge also
    carries a downstream-port IP that would mis-encode the segment.
    """
    ppid = m.parent_mod_port_id & 0xFF
    # Parse the ports as XML (works for both the RxDataCollection override and
    # the catalog-derived form) rather than regexing the rendered string, so
    # the lookup does not depend on the renderer's attribute order.
    up = None
    try:
        for port in ET.fromstring(m._build_ports_xml()).iter("Port"):
            if port.get("Upstream") == "true":
                up = port
                break
    except Exception:
        up = None
    if up is not None:
        addr = up.get("Address")
        if addr and _MSG_IPRE.match(addr):
            a = addr.encode("ascii", "replace")
            if len(a) % 2:
                a = a + b"\x00"
            return bytes([0x10 | ppid, len(addr)]) + a
        if addr:
            try:
                return bytes([ppid, int(addr) & 0xFF])
            except Exception:
                pass
    slot = m._slot if m._slot != 0xFFFFFFFF else 0
    return bytes([ppid, slot & 0xFF])


def _msg_build_module_routes(modules):
    """Return (name->route bytes, {route: count}, set(module IPs)).

    A module's route is the concatenation of its ParentModule-chain segments
    (the root's route is empty). A bare backplane slot-0 route is dropped from
    the name map: slot 0 is the controller's own slot, never an addressable hop.
    """
    by_name = {}
    for m in modules:
        by_name.setdefault(m.name, m)
    cache: Dict[int, object] = {}

    def route(m, seen):
        k = id(m)
        if k in cache:
            return cache[k]
        if getattr(m, "_is_root", False) or m.parent_module == m.name:
            cache[k] = b""
            return b""
        p = by_name.get(m.parent_module)
        if p is None or m.name in seen:
            cache[k] = None
            return None
        pr = route(p, seen | {m.name})
        if pr is None:
            cache[k] = None
            return None
        r = pr + _msg_route_segment(m)
        cache[k] = r
        return r

    nr: Dict[str, bytes] = {}
    for m in modules:
        if m.name == "?":
            continue
        r = route(m, set())
        if r:
            nr.setdefault(m.name, r)
    route_count: Dict[bytes, int] = {}
    for r in nr.values():
        route_count[r] = route_count.get(r, 0) + 1
    module_ips = {m._ip_address for m in modules if m._ip_address}
    return nr, route_count, module_ips


def _epath_ascii(seg):
    """Decode a CIP EPATH port-segment link address (a counted ASCII string).

    The address is NUL-terminated/padded within its length byte, so trim at the
    first NUL. Otherwise a padding terminator leaks a raw ``\\x00`` into the
    ConnectionPath and then into an XML attribute, which is not well-formed
    (XML 1.0 cannot represent NUL at all). Same intent as the ``rstrip("\\x00")``
    on the UTF-16 tag-token decode below.
    """
    return seg.decode("ascii", "replace").split("\x00", 1)[0]


def _msg_seg_list(b):
    """Split EPATH bytes into [(port_byte, addr, is_ip)] segments (lenient)."""
    out = []
    i = 0
    n = len(b)
    while i < n:
        p = b[i]
        i += 1
        if p & 0x10:
            if i >= n:
                break
            L = b[i]
            i += 1
            if i + L > n:
                break
            out.append((p, _epath_ascii(b[i:i + L]), True))
            i += L + (L & 1)
        else:
            if i >= n:
                break
            out.append((p, b[i], False))
            i += 1
    return out


def _msg_decode_tokens(b):
    """Decode EPATH bytes into ["port","addr",...] tokens, or None if malformed
    or it contains an extended-port (low nibble 0x0f) segment we do not model."""
    toks = []
    i = 0
    n = len(b)
    while i < n:
        p = b[i]
        i += 1
        port = p & 0x0F
        if port == 0x0F:
            return None
        toks.append(str(port))
        if p & 0x10:
            if i >= n:
                return None
            L = b[i]
            i += 1
            if i + L > n:
                return None
            toks.append(_epath_ascii(b[i:i + L]))
            i += L + (L & 1)
        else:
            if i >= n:
                return None
            toks.append(str(b[i]))
            i += 1
    return toks


def _msg_resolve_cp(epath, nr, route_count, module_ips):
    """Resolve a message EPATH to (connection_path_str | None, unsafe bool).

    Longest module-route prefix -> that module's name, then the remaining
    segments decode to "port, addr" tokens. ``unsafe`` is True when the result
    may differ from what Logix writes (an ambiguous route shared by several
    modules, a path that traverses a modeled module by IP, or a mid-path
    slot/node hop into a remote module that Logix would name) -- the caller then
    emits nothing rather than risk a wrong ConnectionPath.
    """
    best = None
    bl = -1
    best_route = b""
    for name, r in nr.items():
        lr = len(r)
        if r == b"\x01\x00":
            continue
        if lr <= len(epath) and epath[:lr] == r and lr > bl:
            best = name
            bl = lr
            best_route = r
    rem = epath[bl:] if best is not None else epath
    if best is None and rem[:1] and (rem[0] & 0x0F) == 0x0F:
        return "THIS", False
    toks = _msg_decode_tokens(rem)
    if toks is None:
        return None, True
    unsafe = False
    if best is not None and route_count.get(best_route, 0) > 1:
        unsafe = True
    segs = _msg_seg_list(rem)
    if any(is_ip and addr in module_ips for _p, addr, is_ip in segs):
        unsafe = True
    if best is not None and any(not is_ip for _p, _a, is_ip in segs[:-1]):
        unsafe = True
    cp = ", ".join(([best] if best is not None else []) + toks)
    return cp, unsafe


def _msg_res_tok(raw, oid2name):
    """Decode a UTF-16 @hex@-chain member reference to a friendly string, or None.

    Each @hex@ token is a comps object_id resolved to its comp_name; a name of
    the form ``&<objhex>:rest`` (a module I/O element) is further dereferenced
    to ``<moduleName>:rest`` (e.g. ``&5eefcfac:11:I`` -> ``Local:11:I``).
    """
    if not raw:
        return None
    s = raw.decode("utf-16-le", "replace").rstrip("\x00")
    if not s:
        return None
    out = []
    for i, p in enumerate(re.split(r"@([0-9A-Fa-f ]+)@", s)):
        if i % 2 == 1:
            try:
                nm = oid2name.get(int(p.replace(" ", ""), 16), "?")
            except Exception:
                nm = "?"
            mm = re.match(r"^&([0-9a-fA-F]+)(:.*)$", nm)
            if mm:
                mod = oid2name.get(int(mm.group(1), 16))
                if mod:
                    nm = mod + mm.group(2)
            out.append(nm)
        else:
            out.append(p)
    return "".join(out)


def _render_message_data(cur, short_header, dti, oid2name, nr, route_count, module_ips):
    """Return the ``<Data Format="Message">`` block for a MESSAGE tag, or None.

    None is returned for every configuration not decoded with full confidence
    (a non-354-byte/safety config, an unresolved or ambiguous ConnectionPath, or
    an unresolved member reference), so the tag keeps its prior no-<Data> output
    and nothing wrong is ever emitted.
    """
    try:
        if not dti:
            return None
        attrs = CompsRecord.record_attrs(cur, dti, short_header)
        a1 = attrs.get(0x1)
        if not a1 or len(a1) != 354:
            return None
        # The exact-354 gate above guarantees every MessageConfig field is
        # present (the grammar's size guards exist for robustness only).
        mc = MessageConfig.from_bytes(a1)
        fam = mc.family
        # MessageType family is the struct-trailer byte 353; the sub-type is the
        # service byte 330 (the low byte of the CIP setup struct's ServiceCode).
        svc = mc.service_byte
        if fam == 1:
            mt = "CIP Generic"
        elif fam == 2:
            mt = {76: "CIP Data Table Read", 77: "CIP Data Table Write"}.get(svc)
        elif fam == 4:
            mt = {162: "SLC Typed Read", 170: "SLC Typed Write"}.get(svc)
        elif fam == 6:
            mt = {0: "PLC5 Word Range Write", 1: "PLC5 Word Range Read",
                  104: "PLC5 Typed Read"}.get(svc)
        elif fam == 7:
            mt = "Module Reconfigure"
        elif fam == 0:
            mt = "Unconfigured"
        else:
            mt = None
        if mt is None:
            return None
        req = mc.requested_length
        cf = mc.connected_flag
        epath = mc.epath if mc.epath is not None else b""
        has_cp = bool(epath)
        cp = None
        if has_cp:
            cp, unsafe = _msg_resolve_cp(epath, nr, route_count, module_ips)
            if cp is None or unsafe:
                return None
        le = _msg_res_tok(attrs.get(0x65), oid2name)
        dt = _msg_res_tok(attrs.get(0x70), oid2name)
        re_el = _msg_res_tok(attrs.get(0x67), oid2name)
        if (le and ("&" in le or "@" in le)) or (dt and ("&" in dt or "@" in dt)):
            return None
        P = [("MessageType", mt)]

        def add_cp():
            if has_cp:
                P.append(("ConnectionPath", cp))

        if mt == "CIP Generic":
            P += [("RequestedLength", str(req)), ("ConnectedFlag", str(cf))]
            add_cp()
            P += [("CommTypeCode", "0"),
                  ("ServiceCode", "16#%04x" % mc.service_code),
                  ("ObjectType", "16#%04x" % mc.object_type),
                  ("TargetObject", str(mc.target_object)),
                  ("AttributeNumber", "16#%04x" % mc.attribute_number),
                  ("LocalIndex", "0")]
            if le:
                P.append(("LocalElement", le))
            if dt:
                P.append(("DestinationTag", dt))
            if cf == 1:
                P.append(("CacheConnections", "TRUE"))
            lpu = "true" if (mc.large_packet_flags & 0x02) else "false"
            P.append(("LargePacketUsage", lpu))
        elif mt in ("CIP Data Table Read", "CIP Data Table Write"):
            if re_el is None or le is None:
                return None
            P += [("RemoteElement", re_el), ("RequestedLength", str(req)),
                  ("ConnectedFlag", str(cf))]
            add_cp()
            P += [("CommTypeCode", "0"), ("LocalIndex", "0"), ("LocalElement", le)]
            if cf == 1:
                P.append(("CacheConnections", "TRUE"))
        elif mt in ("SLC Typed Read", "SLC Typed Write",
                    "PLC5 Word Range Write", "PLC5 Word Range Read", "PLC5 Typed Read"):
            # RemoteElement is a PLC data address (e.g. N20:0); LocalElement a tag.
            # These families render no ConnectedFlag. SLC carries CacheConnections
            # only on a connected (cf==1) message and its value is not derivable
            # from a single pool sample, so that lone case is skipped (safe).
            if re_el is None or le is None:
                return None
            if mt.startswith("SLC") and cf == 1:
                return None
            P += [("RemoteElement", re_el), ("RequestedLength", str(req))]
            add_cp()
            P += [("CommTypeCode", "0"), ("LocalIndex", "0"), ("LocalElement", le)]
        elif mt == "Module Reconfigure":
            P += [("RequestedLength", str(req))]
            add_cp()
            P += [("CommTypeCode", "0"), ("LocalIndex", "0")]
        elif mt == "Unconfigured":
            P += [("RequestedLength", str(req)), ("CommTypeCode", "0"), ("LocalIndex", "0")]
        else:
            return None
        params = " ".join('%s="%s"' % (k, html.escape(str(v), quote=True)) for k, v in P)
        return '<Data Format="Message">\n<MessageParameters ' + params + '/>\n</Data>'
    except Exception:
        return None
