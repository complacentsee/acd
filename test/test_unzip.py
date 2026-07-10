import os

import pytest

from acd.zip.unzip import Unzip

_HERE = os.path.dirname(os.path.abspath(__file__))
CUTELOGIX = os.path.join(_HERE, "..", "resources", "CuteLogix.ACD")
BUILD = os.path.join(_HERE, "build")


@pytest.fixture()
async def sample_acd():
    unzip = Unzip(CUTELOGIX)
    yield unzip


def test_open_file(sample_acd):
    assert sample_acd


def test_file_count(sample_acd):
    assert sample_acd.header.no_files == 25


def test_header_offset(sample_acd):
    assert sample_acd.header.record_offset == 2027550


def test_record_count(sample_acd):
    assert len(sample_acd.records) == 25


def test_filename(sample_acd):
    assert sample_acd.records[0].filename == "Version.Log"


def test_write_files(sample_acd):
    sample_acd.write_files(BUILD)
