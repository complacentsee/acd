"""Reproduce Logix v20's SFC language-element export order (byte-exact).

When RSLogix 5000 v20 exports an SFC routine it gathers the routine's
RxLanguageElementCollection (Steps + Transitions + Branches + Stops), copies
every member into a ``std::vector`` in *persistent-object iterator* order, runs
the MSVC-2010 ``std::sort`` (introsort -- UNSTABLE) with
``RxLanguageElementTemplateProperty::operator()`` as the predicate, and finally
buckets the sorted vector into the ``<Step>``/``<Transition>``/``<Branch>``/
``<Stop>`` XML sections.  Two branch bars with the same Y are comparator-equal,
so their emitted order is whatever the unstable introsort happens to leave -- it
is not any per-branch key, it is an emergent property of the whole-array sort.
This was reverse-engineered from ``Umbrella.dll``
(``L5kTraverseOrderedNamelessChildren::VisitOrderedChildren`` and the sort at
``FUN_10031970``/``FUN_1002c3f0``); the two data-dependent facts, both validated
against every v20 same-Y tie group in the reference corpus, are:

  * PO input order = collection members ascending by the object's 4-byte
    self-hash (nameless record bytes ``[12:16]``) compared as raw big-endian
    bytes -- the Nameless index (B-tree) key order.
  * predicate = (1) element-type rank Step<Transition<Branch<Stop; (2) the
    Operand string (empty for a Branch) by ordinal compare; (3) the drawing
    location, with X forced to 0 for a Branch so branches order by Y alone.

``Elem`` carries the fields the predicate needs plus an opaque ``ref`` the
caller uses to map results back to its own records.
"""

_LANGELEM_TYPE = {
    1003: 1,   # Step
    1006: 2,   # Transition
    1017: 3, 1018: 3, 1019: 3, 1020: 3,   # Branch (selection/simultaneous)
    1021: 5,   # Stop
}
_BRANCH_KINDS = frozenset((1017, 1018, 1019, 1020))


class Elem:
    __slots__ = ("kind", "hash", "x", "y", "operand", "ref")

    def __init__(self, kind, hash, x, y, operand, ref):
        self.kind = kind
        self.hash = hash          # raw 4 bytes = record[12:16]
        self.x = x
        self.y = y
        self.operand = operand or ""
        self.ref = ref


def _lt(a, b):
    ta = _LANGELEM_TYPE[a.kind]
    tb = _LANGELEM_TYPE[b.kind]
    if ta != tb:                                   # (1) type rank
        return ta < tb
    la = "" if ta == 3 else a.operand              # (2) Operand label
    lb = "" if tb == 3 else b.operand
    if la != lb:
        return la < lb
    ax, ay, bx, by = a.x, a.y, b.x, b.y            # (3) location
    if ta == 3:                                    # branch: ignore X
        ax = bx = 0
    if ax != bx:
        return ax < bx
    if ay != by:
        return ay < by
    return False                                   # comparator-equal


# ---- exact MSVC-2010 std::sort (introsort), transcribed from Umbrella.dll ----
def _introsort(A):
    def P(i, j):
        return _lt(A[i], A[j])

    def med3(a, b, c):
        if P(b, a):
            A[a], A[b] = A[b], A[a]
        if P(c, b):
            A[b], A[c] = A[c], A[b]
            if P(b, a):
                A[a], A[b] = A[b], A[a]

    def median(first, mid, last):          # last inclusive
        if last - first > 40:
            s = (last - first + 1) // 8
            med3(first, first + s, first + 2 * s)
            med3(mid - s, mid, mid + s)
            med3(last - 2 * s, last - s, last)
            med3(first + s, mid, last - s)
        else:
            med3(first, mid, last)

    def partition(first, last):
        p8 = first + (last - first) // 2
        median(first, p8, last - 1)
        p6 = p8 + 1
        if first < p8:
            while True:
                if P(p8 - 1, p8) or P(p8, p8 - 1):
                    break
                p8 -= 1
                if p8 <= first:
                    break
        local18 = p7 = p6
        p9 = p8
        if p6 < last:
            while True:
                b = P(p6, p8)
                local18 = p7 = p6
                if b or P(p8, p6):
                    break
                p6 += 1
                local18 = p7 = p6
                if last <= p6:
                    break
        while True:
            p4, p10 = p7, p9
            do_bottom = last <= p4
            if not do_bottom:
                b = P(p9, p4)
                p7 = p6
                if not b:
                    if P(p4, p9):
                        do_bottom = True
                    else:
                        p7 = local18 + 1
                        local18 = p7
                        if A[p6] is not A[p4]:
                            A[p6], A[p4] = A[p4], A[p6]
                if not do_bottom:
                    p6 = p7
                    p7 = p4 + 1
                    continue
            while first < p8:
                if not P(p8 - 1, p10):
                    if P(p10, p8 - 1):
                        break
                    p10 -= 1
                    if A[p10] is not A[p8 - 1]:
                        A[p10], A[p8 - 1] = A[p8 - 1], A[p10]
                p8 -= 1
            if p8 == first:
                if p4 == last:
                    return p10, p6
                if p6 != p4 and A[p10] is not A[p6]:
                    A[p10], A[p6] = A[p6], A[p10]
                p6 += 1
                p9 = p10 + 1
                local18 = p6
                p7 = p4 + 1
                if A[p10] is not A[p4]:
                    A[p10], A[p4] = A[p4], A[p10]
            else:
                p8 -= 1
                if p4 == last:
                    p9 = p10 - 1
                    if p8 != p9 and A[p8] is not A[p9]:
                        A[p8], A[p9] = A[p9], A[p8]
                    p6 -= 1
                    local18 = p6
                    p7 = p4
                    if A[p9] is not A[p6]:
                        A[p9], A[p6] = A[p6], A[p9]
                else:
                    if A[p4] is not A[p8]:
                        A[p4], A[p8] = A[p8], A[p4]
                    p7 = p4 + 1
                    p9 = p10

    def insertion(first, last):
        if first == last:
            return
        nxt = first
        while True:
            nxt += 1
            if nxt == last:
                break
            val = A[nxt]
            if _lt(val, A[first]):
                j = nxt
                while j > first:
                    A[j] = A[j - 1]
                    j -= 1
                A[first] = val
            else:
                f1 = nxt
                while _lt(val, A[f1 - 1]):
                    A[f1] = A[f1 - 1]
                    f1 -= 1
                A[f1] = val

    def sort(first, last, ideal):
        while True:
            n = last - first
            if n < 33:
                if n > 1:
                    insertion(first, last)
                return
            if ideal < 1:
                # introsort's heapsort fallback -- never observed on any v20 SFC
                # routine; raise so the caller (decode_sfc) fails closed rather
                # than emit an unverified order.
                raise ValueError("sfc introsort heap fallback")
            pf, pl = partition(first, last)
            ideal = ideal // 2 + (ideal // 2) // 2
            if pf - first < last - pl:
                sort(first, pf, ideal)
                first = pl
            else:
                sort(pl, last, ideal)
                last = pf

    sort(0, len(A), len(A))
    return A


def order_branches(elems):
    """Return the Branch ``ref``s in exact Logix-v20 emit order.

    ``elems`` is an iterable of :class:`Elem`.  Raises ``ValueError`` on the
    (never-observed) heapsort fallback so the caller can fail closed.
    """
    A = [e for e in elems if e.kind in _LANGELEM_TYPE]
    A.sort(key=lambda e: e.hash)          # PO-iterator input order (index key)
    _introsort(A)
    return [e.ref for e in A if e.kind in _BRANCH_KINDS]
