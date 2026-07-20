"""Controller-level <QuickWatchLists> and <ParameterConnections> renderers.

Both are stored as nameless FAFA records (class u32 @ 0x10) whose bodies carry
FF-FE-FF-framed counted UTF-16 strings. QuickWatchLists (class 0x1089e) hold a
list name, an entry count, and per-entry a '@<hex-oid>@' watch-tag reference plus
a 12-byte tail whose leading u16 is the scope marker ('k' controller / 'h'
program). ParameterConnections (class 0x1089f) hold a direction word, the scope
program oid, and two '@oid@[.@oid@...]' endpoint operand paths.

Both renderers are fail-closed: any unresolved reference drops the whole block
(a missing block is safer than a wrong one).
"""
from __future__ import annotations

import html
import re
import struct
from typing import List, Optional, Tuple

_QWL_CLASS = 0x0001089E
_PC_CLASS = 0x0001089F
_MARK_CTRL = 0x006B  # 'k' -- controller scope
_MARK_PROG = 0x0068  # 'h' -- program scope
_STR_MAGIC = b"\xff\xfe\xff"
_REF_RE = re.compile(r"@([0-9a-fA-F]+)@")


def _read_cstr(rec: bytes, off: int) -> Tuple[str, int]:
    """A FF-FE-FF-framed counted UTF-16-LE string at rec[off:]; (text, next_off).

    Raises on a bad frame so the caller can fail closed.
    """
    if rec[off:off + 3] != _STR_MAGIC:
        raise ValueError("bad string frame")
    n = rec[off + 3]
    end = off + 4 + 2 * n
    return rec[off + 4:end].decode("utf-16-le"), end


def _name_of(cur, oid: int) -> Optional[str]:
    r = cur.execute("SELECT comp_name FROM comps WHERE object_id=?", (oid,)).fetchone()
    return r[0] if r and r[0] else None


def _program_scope(cur, oid: int) -> Optional[str]:
    """The RxProgramCollection-child program name that owns comp `oid`, or None."""
    seen = set()
    while oid and oid not in seen:
        seen.add(oid)
        r = cur.execute("SELECT parent_id FROM comps WHERE object_id=?", (oid,)).fetchone()
        if not r:
            return None
        pid = r[0]
        gp = cur.execute("SELECT parent_id FROM comps WHERE object_id=?", (pid,)).fetchone()
        if gp:
            gpn = _name_of(cur, gp[0])
            if gpn == "RxProgramCollection":
                return _name_of(cur, pid)
        oid = pid
    return None


def _records(cur, cls: int) -> List[bytes]:
    """Every nameless record of the given class, in stored (insertion) order."""
    out = []
    for (rec,) in cur.execute("SELECT record FROM nameless").fetchall():
        rec = bytes(rec)
        if len(rec) >= 20 and struct.unpack_from("<I", rec, 16)[0] == cls:
            out.append(rec)
    return out


def _attr(v: str) -> str:
    return html.escape(v, quote=True)


def build_quick_watch_lists(cur) -> str:
    """<QuickWatchLists> or "" when the controller has none / a ref does not
    resolve. Lists are emitted alphabetically by name; within a list the
    controller-scope watch tags are alphabetical, then the program-scope ones in
    stored order."""
    try:
        recs = _records(cur, _QWL_CLASS)
        if not recs:
            return ""
        lists: List[Tuple[str, List[Tuple[str, str]]]] = []
        for rec in recs:
            name, off = _read_cstr(rec, 0x14)
            count = struct.unpack_from("<I", rec, off)[0]
            off += 4
            ctrl: List[str] = []
            prog: List[Tuple[str, str]] = []
            for _ in range(count):
                ref, off = _read_cstr(rec, off)
                marker = struct.unpack_from("<H", rec, off)[0]
                off += 12
                m = _REF_RE.fullmatch(ref)
                if not m:
                    return ""
                spec = _name_of(cur, int(m.group(1), 16))
                if spec is None:
                    return ""
                if marker == _MARK_CTRL:
                    ctrl.append(spec)
                elif marker == _MARK_PROG:
                    scope = _program_scope(cur, int(m.group(1), 16))
                    if scope is None:
                        return ""
                    prog.append((spec, scope))
                else:
                    return ""
            entries = [(s, "") for s in sorted(ctrl)] + prog
            lists.append((name, entries))
        parts = ["<QuickWatchLists>"]
        for name, entries in sorted(lists, key=lambda t: t[0]):
            parts.append(f'<QuickWatchList Name="{_attr(name)}">')
            for spec, scope in entries:
                parts.append(
                    f'<WatchTag Specifier="{_attr(spec)}" Scope="{_attr(scope)}"/>')
            parts.append("</QuickWatchList>")
        parts.append("</QuickWatchLists>")
        return "".join(parts)
    except Exception:
        return ""


def _endpoint(cur, s: str, scope_oid: int) -> Optional[str]:
    """An endpoint operand path: a single @oid@ is a program-scoped parameter
    ("\\Program.name"); a multi-oid chain is a controller-scope dotted path."""
    oids = [int(x, 16) for x in _REF_RE.findall(s)]
    if not oids:
        return None
    if len(oids) == 1:
        prog = _name_of(cur, scope_oid)
        leaf = _name_of(cur, oids[0])
        if prog is None or leaf is None:
            return None
        return f"\\{prog}.{leaf}"
    names = [_name_of(cur, o) for o in oids]
    if any(n is None for n in names):
        return None
    return ".".join(names)


def build_parameter_connections(cur) -> str:
    """<ParameterConnections> or "" when the controller has none / a ref does not
    resolve. Producer (direction 3) connections emit in stored order, then
    consumer (direction 2) connections in reversed stored order."""
    try:
        recs = _records(cur, _PC_CLASS)
        if not recs:
            return ""
        parsed: List[Tuple[int, str, str]] = []
        for rec in recs:
            direction = struct.unpack_from("<I", rec, 0x18)[0]
            scope = struct.unpack_from("<I", rec, 0x1C)[0]
            s1, off = _read_cstr(rec, 0x20)
            s2, _ = _read_cstr(rec, off)
            ep1 = _endpoint(cur, s1, scope)
            ep2 = _endpoint(cur, s2, scope)
            if ep1 is None or ep2 is None or direction not in (2, 3):
                return ""
            parsed.append((direction, ep1, ep2))
        ordered = ([p for p in parsed if p[0] == 3]
                   + [p for p in reversed(parsed) if p[0] == 2])
        parts = ["<ParameterConnections>"]
        for _d, ep1, ep2 in ordered:
            parts.append(
                f'<ParameterConnection EndPoint1="{_attr(ep1)}" '
                f'EndPoint2="{_attr(ep2)}"/>')
        parts.append("</ParameterConnections>")
        return "".join(parts)
    except Exception:
        return ""
