import os
from pathlib import Path
from xml.dom import minidom

from acd.api import (
    ImportProjectFromFile,
    RSLogix5000Content,
    Extract,
    ExtractAcdDatabase,
    DumpCompsRecordsToFile,
)

_HERE = Path(__file__).resolve().parent
CUTELOGIX = _HERE.parent / "resources" / "CuteLogix.ACD"
BUILD = _HERE / "build"


def test_import_from_file():
    importer = ImportProjectFromFile(CUTELOGIX)
    project: RSLogix5000Content = importer.import_project()
    assert project is not None


def test_extract_database_files():
    extractor: Extract = ExtractAcdDatabase(CUTELOGIX, BUILD)
    extractor.extract()


def test_dump_to_files():
    DumpCompsRecordsToFile(str(CUTELOGIX), str(BUILD)).extract()


def test_to_xml():
    importer = ImportProjectFromFile(CUTELOGIX)
    project: RSLogix5000Content = importer.import_project()
    unformatted_string = project.to_xml()
    xmlstr = minidom.parseString(unformatted_string).toprettyxml(indent="   ")
    with open(os.path.join(BUILD, "CuteLogix.L5X"), "w") as out_file:
        out_file.write(xmlstr)
