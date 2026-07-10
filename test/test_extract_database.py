from pathlib import Path

from acd.api import ExtractAcdDatabaseRecordsToFiles

_HERE = Path(__file__).resolve().parent


def test_dump_database():
    database = ExtractAcdDatabaseRecordsToFiles(
        _HERE.parent / "resources" / "CuteLogix.ACD",
        _HERE / "build",
    )
    database.extract()
