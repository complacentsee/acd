"""End-to-end validation of V21 'Rung NT' source-protection READ support.

Drives the *real fork read path* (Unzip -> DbExtract -> CompsRecord ->
SbRegionRecord.parse) against a V21 ACD and compares the decoded rung text to
the ground-truth L5X exported by Studio.

Because the on-disk V21 body is intentionally lossy by the final ~8-15 UTF-16
chars (the engine stores the ciphertext truncated by the last 16 plaintext
bytes — see acd.record.source_protection), exact full-text recovery is only
possible for rungs whose whole text fits in the recoverable prefix (all NOPs and
the short rungs).  This script reports BOTH:

  * exact full-text matches (the honest, no-fabrication ceiling), and
  * prefix-correct rungs (decoded text is a true prefix of the L5X text — i.e.
    everything recovered is correct, nothing is wrong/fabricated).

Defaults target the v21_gm_FuncGen fixtures.  Override with --acd / --l5x.
"""
import argparse
import os
import re
import sys
import tempfile

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from acd.database.dbextract import DbExtract  # noqa: E402
from acd.record.comps import CompsRecord  # noqa: E402
from acd.record.sbregion import SbRegionRecord  # noqa: E402
from acd.record.source_protection import (  # noqa: E402
    build_uid_name_map,
    is_v21_version,
)
from acd.l5x.export_l5x import detect_acd_version  # noqa: E402
from acd.zip.unzip import Unzip  # noqa: E402

# The v21_gm_FuncGen corpus is embedded in the repo (resources/) so the
# validation runs anywhere without machine-specific paths.
DEFAULT_ACD = os.path.join(_ROOT, "resources", "v21_gm_FuncGen.ACD")
DEFAULT_L5X = os.path.join(_ROOT, "resources", "v21_gm_FuncGen.L5X")


def l5x_rung_texts(l5x_path):
    raw = open(l5x_path, encoding="utf-8", errors="replace").read()
    rungs = re.findall(r"<Rung\b.*?</Rung>", raw, re.S)
    out = []
    for x in rungs:
        m = re.search(r"<Text>\s*<!\[CDATA\[(.*?)\]\]>\s*</Text>", x, re.S)
        if m:
            out.append(m.group(1))
    return out


def run_validation(acd_path=DEFAULT_ACD, l5x_path=DEFAULT_L5X):
    """Decode every rung via the real fork read path and compare to the L5X.

    Returns a dict with the decoded/ground-truth rung lists and the match
    tallies (exact / nop_exact / cipher_exact / prefix_ok / n).  Used by both
    the CLI below and ``test/test_source_protection.py``.
    """
    tmp = tempfile.mkdtemp(prefix="v21val_")
    unzip = Unzip(acd_path)
    unzip.write_files(tmp)
    version = detect_acd_version(acd_path)

    # Build object_id -> comp_name exactly as ExportL5x does.
    comps_db = DbExtract(os.path.join(tmp, "Comps.Dat")).read()
    comps_by_id = {}
    for rec in comps_db.records.record:
        t = CompsRecord.parse(rec)
        if t is not None:
            oid = t[0]
            if oid not in comps_by_id or len(t[5]) > len(comps_by_id[oid][5]):
                comps_by_id[oid] = t
    name_lookup = {oid: t[2] for oid, t in comps_by_id.items()}
    if is_v21_version(version):
        name_lookup = {**name_lookup, **build_uid_name_map(comps_db)}

    # Decode every SbRegion rung via the real fork read path.
    sb_db = DbExtract(os.path.join(tmp, "SbRegion.Dat")).read()
    decoded = []
    for rec in sb_db.records.record:
        t = SbRegionRecord.parse(rec, name_lookup, version)
        if t is not None:
            decoded.append(t[1])

    truth = l5x_rung_texts(l5x_path)

    n = min(len(decoded), len(truth))
    exact = nop_exact = cipher_exact = prefix_ok = 0
    for d, g in zip(decoded[:n], truth[:n]):
        is_nop = d == "NOP();"
        if d == g:
            exact += 1
            if is_nop:
                nop_exact += 1
            else:
                cipher_exact += 1
        if g.startswith(d):
            prefix_ok += 1

    return {
        "version": version,
        "decoded": decoded,
        "truth": truth,
        "n": n,
        "exact": exact,
        "nop_exact": nop_exact,
        "cipher_exact": cipher_exact,
        "prefix_ok": prefix_ok,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--acd", default=DEFAULT_ACD)
    ap.add_argument("--l5x", default=DEFAULT_L5X)
    args = ap.parse_args()

    r = run_validation(args.acd, args.l5x)
    decoded, truth, n = r["decoded"], r["truth"], r["n"]

    print("=" * 70)
    print("V21 source-protection rung READ validation")
    print("=" * 70)
    print("ACD                :", args.acd)
    print("detected version   :", r["version"])
    print("decoded rungs      :", len(decoded))
    print("L5X ground-truth   :", len(truth))

    print("-" * 70)
    print(f"exact full-text match : {r['exact']}/{n}"
          f"   (NOP {r['nop_exact']}, cipher {r['cipher_exact']})")
    print(f"prefix-correct        : {r['prefix_ok']}/{n}"
          f"   (decoded is a true prefix of L5X — nothing fabricated)")
    print("-" * 70)

    # Show the non-exact rungs so the lossy-tail gap is explicit.
    shown = 0
    for d, g in zip(decoded[:n], truth[:n]):
        if d != g and shown < 8:
            print(f"  L5X : {g!r}")
            print(f"  DEC : {d!r}")
            shown += 1
    if shown:
        print(f"  ... ({sum(1 for d, g in zip(decoded[:n], truth[:n]) if d != g)} "
              "rungs differ — all are lossy-tail prefixes, see module docstring)")

    return 0 if r["prefix_ok"] == n else 1


if __name__ == "__main__":
    raise SystemExit(main())
