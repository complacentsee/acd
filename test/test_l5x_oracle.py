"""OEM-subtree content oracle for the L5X exporter.

Compares our generated L5X against Studio-exported ground truth
(resources/ACDTestsWithAOI.L5X, resources/ACDTestsEmptyRedundant.L5X) on
canonicalized subtrees, plus a byte-exact self-golden for CuteLogix.ACD.

The comparison is *manifest driven*: every region listed in a *_EXACT
manifest must stay canonically byte-identical to the OEM export, and every
OEM element must be accounted for either as MATCH or as a documented
KNOWN_DIFF (a real, currently-unfixed fidelity gap).  This is deliberately
strict in both directions:

* a refactor that changes any byte inside a matched region fails loudly;
* fixing a KNOWN_DIFF fails the accounting test, prompting promotion of
  that element into the MATCH manifest.

Full-file equality is intentionally NOT asserted -- known gaps (see the
KNOWN_DIFF tables below) make it unachievable, and the OEM fixtures were
exported with "NoRawData" while we emit the full DataTypes library.

Canonicalization: whitespace-only text/tails are stripped, then
xml.etree.ElementTree.canonicalize() renders C14N (sorted attributes,
normalized escaping).  Both sides pass through the same pipeline, so CDATA
vs. escaped text differences also normalize away.
"""

import difflib
import gzip
import re
from io import StringIO
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from acd.l5x.export_l5x import ExportL5x

_HERE = Path(__file__).resolve().parent
RESOURCES = _HERE.parent / "resources"
GOLDEN = _HERE / "golden"

# Attributes whose values depend on when/where the export ran, not on the ACD.
DYNAMIC_ROOT_ATTRS = {"ExportDate"}
# Known fidelity gaps in attribute values (present on both sides, values differ):
#   ContainsContext        -- we emit a constant "true"; these fixtures say "false"
#   ProjectCreationDate /
#   LastModifiedDate       -- we render the stored UTC timestamp; Studio renders local time
#   MatchProjectToController -- not yet decoded for this fixture family
KNOWN_DIFF_ROOT_ATTRS = {"ContainsContext"}
KNOWN_DIFF_CONTROLLER_ATTRS = {
    "ProjectCreationDate",
    "LastModifiedDate",
    "MatchProjectToController",
}

# ---------------------------------------------------------------------------
# Per-fixture manifests (empirically established 2026-07-09; every entry is a
# canonical byte-match against the Studio export of the same project).
# ---------------------------------------------------------------------------

# Direct children of <Controller> that match the OEM export byte-for-byte.
EMPTY_REDUNDANT_EXACT = [
    "Description",
    "RedundancyInfo",
    "Security",
    "SafetyInfo",
    "Modules",
    "AddOnInstructionDefinitions",
    "Tags",
    "Programs",
    "Tasks",
    "CST",
    "WallClockTime",
    "Trends",
    "DataLogs",
    "TimeSynchronize",
]
# DataTypes is excluded at subtree level for both fixtures: we emit the full
# type library while the OEM export lists user types only.  User-defined
# members are still compared one-by-one in test_user_datatypes_match.

WITHAOI_EXACT = [
    "Description",
    "RedundancyInfo",
    "Security",
    "SafetyInfo",
    "Modules",
    "Tasks",
    "CST",
    "WallClockTime",
    "Trends",
    "DataLogs",
    "TimeSynchronize",
    # EthernetPorts is a byte-exact pin (P6.9 C7). Its EthernetPort is an
    # FDFD-winner controller child (oid 1493048019, fafa_seen=0); controller_ports
    # reads it body-direct via record_attrs, which equals full_attrs only because
    # the C5 flip aligned comps.record to full[148:]. Pinning it exact turns a
    # silent D11@155 regression (or a revert of C5) into a test failure -- the
    # pool gauntlet cannot, since no in-pool FDFD winner sits under the controller.
    "EthernetPorts",
]
# Subtrees entirely missing from our export (probe-only, not implemented):
WITHAOI_KNOWN_MISSING_SUBTREES = set()
# Subtrees with documented content gaps (compared member-by-member instead):
#   AddOnInstructionDefinitions -- extra LocalTag DefaultData, missing NOP rung
WITHAOI_KNOWN_DIFF_SUBTREES = {"DataTypes", "AddOnInstructionDefinitions",
                               "Tags", "Programs"}

# Controller-scope <Tags> members (keyed by @Name).
WITHAOI_TAGS_MATCH = [
    "a5000_String32",
    "AliasTag5000String32",
    "Constant",
    "DINT",
    "INT",
    "NoAccess",
    "RadixBinary",
    "RadixFloat",
    "RadixHex",
    "ReadOnly",
    "UDINT",
    "UINT",
    "ULINT",
]
# Exotic radix renderings not yet byte-exact (DateTime/LTime/ASCII/Octal/
# Exponential families).
WITHAOI_TAGS_KNOWN_DIFF = {
    "DATETIME_RadixDateTime",
    "LDATETIME_RadixNanoSec",
    "LTIME_RadixLTime",
    "RadixASCII",
    "RadixExponential",
    "RadixOctal",
    "TIME32_RadixTime32",
    "TIME_RadixTimeUs",
}

# MainProgram <Tags> members.
WITHAOI_PROGTAGS_MATCH = [
    "AND_01",
    "BAND_01",
    "BOR_01",
    "MainProgramLocalTag",
    "MainProgramLocalTagNoAccess",
    "MainProgramLocalTagReadOnly",
    "Step_000",
    "Stop_000",
    "Tran_000",
]
# Program parameter rendering (Usage=Input/Output/Public) not yet byte-exact.
WITHAOI_PROGTAGS_KNOWN_DIFF = {
    "MainProgramInputParameter",
    "MainProgramOutputParameter",
    "MainProgramPublicParameters",
}

# MainProgram <Routines>: RLL main routine plus FBD/SFC/ST content gaps.
WITHAOI_ROUTINES_KNOWN_DIFF = {
    "FBDRoutine",
    "MainRoutine",
    "SequentialFunctionChart",
    "STRoutine",
}


def _canon(elem: ET.Element) -> str:
    """Canonical C14N string of a subtree, ignoring layout whitespace."""
    for e in elem.iter():
        if e.text is not None and not e.text.strip():
            e.text = None
        if e.tail is not None:
            e.tail = None
    out = StringIO()
    ET.canonicalize(ET.tostring(elem, encoding="unicode"), out=out)
    return out.getvalue()


def _assert_canon_equal(ours: ET.Element, oem: ET.Element, label: str) -> None:
    a, b = _canon(ours), _canon(oem)
    if a == b:
        return
    excerpt = "\n".join(
        line
        for line in difflib.unified_diff(
            b.splitlines(), a.splitlines(), "oem", "ours", lineterm="", n=1
        )
    )[:2000]
    pytest.fail(f"{label} no longer byte-matches the OEM export:\n{excerpt}")


def _by_name(parent: ET.Element, xpath: str) -> dict:
    return {c.get("Name"): c for c in parent.findall(xpath)}


def _convert(name: str, tmp_path_factory) -> ET.Element:
    build = tmp_path_factory.mktemp(f"oracle_{name}")
    export = ExportL5x(
        str(RESOURCES / f"{name}.ACD"), str(build), faithful=True
    )
    return ET.fromstring(export.project.to_xml())


@pytest.fixture(scope="module")
def withaoi(tmp_path_factory):
    ours = _convert("ACDTestsWithAOI", tmp_path_factory)
    oem = ET.parse(RESOURCES / "ACDTestsWithAOI.L5X").getroot()
    return ours, oem


@pytest.fixture(scope="module")
def emptyredundant(tmp_path_factory):
    ours = _convert("ACDTestsEmptyRedundant", tmp_path_factory)
    oem = ET.parse(RESOURCES / "ACDTestsEmptyRedundant.L5X").getroot()
    return ours, oem


@pytest.fixture(params=["withaoi", "emptyredundant"])
def pair(request):
    return request.getfixturevalue(request.param)


# ---------------------------------------------------------------------------
# Attribute oracles
# ---------------------------------------------------------------------------


def test_root_attributes(pair):
    ours, oem = pair
    skip = DYNAMIC_ROOT_ATTRS | KNOWN_DIFF_ROOT_ATTRS
    for key in set(ours.attrib) | set(oem.attrib):
        if key in skip:
            assert key in ours.attrib and key in oem.attrib
            continue
        assert ours.get(key) == oem.get(key), f"root @{key}"


def test_controller_attributes(pair):
    ours, oem = pair
    co, ce = ours.find("Controller"), oem.find("Controller")
    for key in set(co.attrib) | set(ce.attrib):
        if key in KNOWN_DIFF_CONTROLLER_ATTRS:
            assert key in co.attrib and key in ce.attrib
            continue
        assert co.get(key) == ce.get(key), f"Controller @{key}"


# ---------------------------------------------------------------------------
# Subtree oracles
# ---------------------------------------------------------------------------


def _controller_pair(pair):
    ours, oem = pair
    return ours.find("Controller"), oem.find("Controller")


def test_empty_redundant_exact_subtrees(emptyredundant):
    co, ce = _controller_pair(emptyredundant)
    for tag in EMPTY_REDUNDANT_EXACT:
        _assert_canon_equal(co.find(tag), ce.find(tag), f"Controller/{tag}")


def test_withaoi_exact_subtrees(withaoi):
    co, ce = _controller_pair(withaoi)
    for tag in WITHAOI_EXACT:
        _assert_canon_equal(co.find(tag), ce.find(tag), f"Controller/{tag}")


def test_all_oem_subtrees_accounted(pair):
    """Every direct OEM Controller child is either matched or a known gap."""
    co, ce = _controller_pair(pair)
    accounted = (
        set(EMPTY_REDUNDANT_EXACT)
        | set(WITHAOI_EXACT)
        | WITHAOI_KNOWN_DIFF_SUBTREES
        | WITHAOI_KNOWN_MISSING_SUBTREES
    )
    for child in ce:
        assert child.tag in accounted, (
            f"new OEM subtree Controller/{child.tag} is not covered by the "
            "oracle manifests -- classify it as EXACT or KNOWN_*"
        )
        if child.tag not in WITHAOI_KNOWN_MISSING_SUBTREES:
            assert co.find(child.tag) is not None, f"Controller/{child.tag}"


def test_user_datatypes_match(pair):
    """Every user DataType in the OEM export must byte-match ours (the
    subtree as a whole differs only because we emit the full library)."""
    co, ce = _controller_pair(pair)
    ours = _by_name(co, "DataTypes/DataType")
    for name, oem_dt in _by_name(ce, "DataTypes/DataType").items():
        assert name in ours, f"user DataType {name} missing from our export"
        _assert_canon_equal(ours[name], oem_dt, f"DataType {name}")


def _member_oracle(co, ce, xpath, match, known_diff, label):
    ours, oem = _by_name(co, xpath), _by_name(ce, xpath)
    for name, oem_el in oem.items():
        assert name in set(match) | known_diff, (
            f"{label} {name!r} is not covered by the oracle manifests -- "
            "classify it as MATCH or KNOWN_DIFF"
        )
        assert name in ours, f"{label} {name!r} missing from our export"
        if name in known_diff:
            continue
        _assert_canon_equal(ours[name], oem_el, f"{label} {name}")


def test_withaoi_controller_tags(withaoi):
    co, ce = _controller_pair(withaoi)
    _member_oracle(
        co, ce, "Tags/Tag",
        WITHAOI_TAGS_MATCH, WITHAOI_TAGS_KNOWN_DIFF, "controller Tag",
    )


def test_withaoi_mainprogram_tags(withaoi):
    co, ce = _controller_pair(withaoi)
    po = _by_name(co, "Programs/Program")["MainProgram"]
    pe = _by_name(ce, "Programs/Program")["MainProgram"]
    _member_oracle(
        po, pe, "Tags/Tag",
        WITHAOI_PROGTAGS_MATCH, WITHAOI_PROGTAGS_KNOWN_DIFF, "MainProgram Tag",
    )


def test_withaoi_mainprogram_routines(withaoi):
    co, ce = _controller_pair(withaoi)
    po = _by_name(co, "Programs/Program")["MainProgram"]
    pe = _by_name(ce, "Programs/Program")["MainProgram"]
    _member_oracle(
        po, pe, "Routines/Routine",
        [], WITHAOI_ROUTINES_KNOWN_DIFF, "MainProgram Routine",
    )


def test_withaoi_aoi_accounted(withaoi):
    """The AOI definition itself is a KNOWN_DIFF (extra LocalTag DefaultData,
    missing NOP rung) but must exist and keep its identity attributes."""
    co, ce = _controller_pair(withaoi)
    ours = _by_name(co, "AddOnInstructionDefinitions/AddOnInstructionDefinition")
    for name, oem_el in _by_name(
        ce, "AddOnInstructionDefinitions/AddOnInstructionDefinition"
    ).items():
        assert name in ours, f"AOI {name} missing from our export"
        assert ours[name].get("Revision") == oem_el.get("Revision")


# ---------------------------------------------------------------------------
# CuteLogix self-golden
# ---------------------------------------------------------------------------

_GOLDEN_FILE = GOLDEN / "CuteLogix.L5X.gz"


def _normalize(xml_text: str) -> str:
    return re.sub(r'ExportDate="[^"]*"', 'ExportDate="GOLDEN"', xml_text)


def test_cutelogix_golden(tmp_path):
    """Byte-exact golden of the full CuteLogix export (unformatted string,
    ExportDate normalized).  To update after a REVIEWED behavior change:

        python - <<'PY'
        import gzip, re
        from acd.l5x.export_l5x import ExportL5x
        xml = ExportL5x("resources/CuteLogix.ACD", "build").project.to_xml()
        xml = re.sub(r'ExportDate="[^"]*"', 'ExportDate="GOLDEN"', xml)
        with open("test/golden/CuteLogix.L5X.gz", "wb") as fh:
            fh.write(gzip.compress(xml.encode("utf-8"), mtime=0))
        PY
    """
    export = ExportL5x(
        str(RESOURCES / "CuteLogix.ACD"), str(tmp_path / "build")
    )
    actual = _normalize(export.project.to_xml())
    golden = gzip.decompress(_GOLDEN_FILE.read_bytes()).decode("utf-8")
    if actual == golden:
        return
    saved = tmp_path / "CuteLogix.actual.L5X"
    saved.write_text(actual)
    excerpt = "\n".join(
        line
        for line in difflib.unified_diff(
            golden.splitlines(), actual.splitlines(),
            "golden", "actual", lineterm="", n=1,
        )
    )[:3000]
    pytest.fail(
        f"CuteLogix export no longer matches the golden.  Actual output "
        f"saved to {saved}.  If the change is intended and reviewed, "
        f"regenerate per the docstring.\n{excerpt}"
    )
