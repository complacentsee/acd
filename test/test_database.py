import os

import pytest

from acd.database.dbextract import DbExtract
from acd.l5x.export_l5x import ExportL5x
from acd.zip.unzip import Unzip

from loguru import logger as log

_HERE = os.path.dirname(os.path.abspath(__file__))
CUTELOGIX = os.path.join(_HERE, "..", "resources", "CuteLogix.ACD")
BUILD = os.path.join(_HERE, "build")


@pytest.fixture()
async def sample_acd():
    unzip = Unzip(CUTELOGIX).write_files(BUILD)
    yield unzip


@pytest.fixture()
async def sbregion_dat():
    db = DbExtract(os.path.join(BUILD, "SbRegion.Dat"))
    yield db


@pytest.fixture()
async def comps_dat():
    db = DbExtract(os.path.join(BUILD, "Comps.Dat")).read()
    yield db


@pytest.fixture(scope="module")
def controller():
    log.level("DEBUG")
    yield ExportL5x(CUTELOGIX, BUILD).controller


def test_open_file(sample_acd, sbregion_dat):
    assert sbregion_dat


def test_parse_rungs_dat(controller):
    # Verify the B002_Timers routine (last routine of last program) contains
    # the expected rungs. Use content search rather than positional index since
    # rung ordering is controlled by region_map.unknown (canonical display order).
    rungs = controller.programs[-1].routines[-1].rungs
    assert any("XIO(b_Timer[0].DN)TON(b_Timer[0],?,?);" in r for r in rungs), (
        f"Expected TON rung not found in {rungs}"
    )


def test_parse_datatypes_dat(controller):
    # Look up by name rather than position — list order may vary across parser versions
    string20 = next((dt for dt in controller.data_types if dt.name == "STRING20"), None)
    assert string20 is not None, "STRING20 data type not found"
    data_member = next((m for m in string20.members if m.name == "DATA"), None)
    assert data_member is not None, "DATA member not found in STRING20"


def test_parse_tags_dat(controller):
    # Look up by name rather than index — index may shift across parser versions
    toggle = next((t for t in controller.tags if t.name == "Toggle"), None)
    assert toggle is not None, "Toggle tag not found"
    assert toggle.data_type == "BOOL"


def test_parse_comments_dat(sample_acd):
    dat = DbExtract(os.path.join(BUILD, "Comments.Dat")).read()
    assert len(dat.records.record) > 0


def test_parse_nameless_dat(sample_acd):
    dat = DbExtract(os.path.join(BUILD, "Nameless.Dat")).read()
    assert len(dat.records.record) > 0
