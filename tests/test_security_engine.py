"""Tests for the Security Engine and Detection Rules — Windows Amcache Analyzer.

Rule-level tests exercise each detection rule as a pure function against
synthetic entry dicts. Engine-level tests build a REAL, byte-accurate REGF
registry hive on disk (see tests/hive_builder.py) and drive it through the
real `python-registry`-backed parsing code path in
`app.security_engine.ScanEngine` — nothing about hive-opening or navigation
is mocked.
"""
import os
import sys
import tempfile
import shutil
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine, open_hive, parse_hive_entries, parse_link_date, HiveParseError
from app.detection_rules import (
    rule_unsigned_suspicious_location,
    rule_extension_spoofing,
    rule_future_link_date,
    rule_duplicate_basename_multiple_paths,
    rule_missing_hash,
    rule_invalid_hive_format,
    ALL_RULES,
)
from tests.hive_builder import build_amcache_hive


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_unsigned_suspicious_location_flags_empty_publisher_in_temp():
    entry = {"path": "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe", "publisher": ""}
    result = rule_unsigned_suspicious_location(entry, {})
    assert result is not None
    assert result["rule_id"] == "WAM-001"
    assert result["severity"] == "high"


def test_rule_unsigned_suspicious_location_ignores_signed_binary():
    entry = {"path": "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe", "publisher": "Contoso Ltd"}
    assert rule_unsigned_suspicious_location(entry, {}) is None


def test_rule_unsigned_suspicious_location_ignores_normal_location():
    entry = {"path": "C:\\Program Files\\Contoso\\app.exe", "publisher": ""}
    assert rule_unsigned_suspicious_location(entry, {}) is None


def test_rule_extension_spoofing_detects_double_extension():
    entry = {"path": "C:\\Users\\bob\\Downloads\\invoice.pdf.exe"}
    result = rule_extension_spoofing(entry, {})
    assert result is not None
    assert result["rule_id"] == "WAM-002"


def test_rule_extension_spoofing_ignores_normal_exe():
    entry = {"path": "C:\\Program Files\\Contoso\\app.exe"}
    assert rule_extension_spoofing(entry, {}) is None


def test_rule_future_link_date_detects_anomaly():
    hive_mtime = datetime(2024, 1, 1).timestamp()
    entry = {
        "path": "C:\\Windows\\weird.exe",
        "_link_date_parsed": datetime(2030, 1, 1),
        "_hive_mtime": hive_mtime,
    }
    result = rule_future_link_date(entry, {})
    assert result is not None
    assert result["rule_id"] == "WAM-003"


def test_rule_future_link_date_ignores_normal_date():
    hive_mtime = datetime(2024, 1, 1).timestamp()
    entry = {
        "path": "C:\\Windows\\normal.exe",
        "_link_date_parsed": datetime(2020, 1, 1),
        "_hive_mtime": hive_mtime,
    }
    assert rule_future_link_date(entry, {}) is None


def test_rule_duplicate_basename_multiple_paths():
    entries = [
        (None, None, {"path": "C:\\Windows\\svchost.exe"}),
        (None, None, {"path": "C:\\Users\\Public\\svchost.exe"}),
    ]
    context = {"all_entries": entries}
    result = rule_duplicate_basename_multiple_paths(entries[1][2], context)
    assert result is not None
    assert result["rule_id"] == "WAM-004"


def test_rule_duplicate_basename_no_duplicate():
    entries = [(None, None, {"path": "C:\\Windows\\unique.exe"})]
    context = {"all_entries": entries}
    assert rule_duplicate_basename_multiple_paths(entries[0][2], context) is None


def test_rule_missing_hash_flags_absent_sha1():
    entry = {"path": "C:\\Windows\\nosum.exe", "sha1": None}
    result = rule_missing_hash(entry, {})
    assert result is not None
    assert result["rule_id"] == "WAM-005"


def test_rule_missing_hash_ignores_present_sha1():
    entry = {"path": "C:\\Windows\\hassum.exe", "sha1": "a" * 40}
    assert rule_missing_hash(entry, {}) is None


def test_rule_invalid_hive_format_produces_note():
    result = rule_invalid_hive_format("/tmp/corrupt.hve", "Invalid REGF ID")
    assert result["rule_id"] == "WAM-006"


def test_parse_link_date_handles_standard_format():
    dt = parse_link_date("06/15/2019 14:30:00")
    assert dt.year == 2019 and dt.month == 6 and dt.day == 15


def test_parse_link_date_handles_missing():
    assert parse_link_date(None) is None
    assert parse_link_date("") is None


def test_all_rules_registered():
    assert len(ALL_RULES) == 6


# ---------------------------------------------------------------------------
# Engine-level tests against a REAL, hand-built REGF hive on disk
# ---------------------------------------------------------------------------

def test_open_hive_real_minimal_hive_reads_back_correctly():
    """The core hive-opening function is exercised against real bytes built
    by tests/hive_builder.py — no mocking of Registry.Registry."""
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Windows\\real.exe", "publisher": "Microsoft",
             "sha1": "a" * 40, "link_date": "01/01/2020 00:00:00"},
        ])
        hive = open_hive(path)
        entries = parse_hive_entries(hive)
        assert len(entries) == 1
        assert entries[0]["path"] == "C:\\Windows\\real.exe"
        assert entries[0]["publisher"] == "Microsoft"
        assert entries[0]["sha1"] == "a" * 40
    finally:
        shutil.rmtree(tmpdir)


def test_open_hive_rejects_corrupt_file():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "corrupt.hve")
        with open(path, "wb") as fh:
            fh.write(b"NOT A REAL HIVE FILE" + b"\x00" * 100)
        try:
            open_hive(path)
            assert False, "expected HiveParseError"
        except HiveParseError:
            pass
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_single_hive_file_produces_real_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {
                "name": "0001",
                "path": "C:\\Users\\Public\\evil.exe",
                "publisher": "",
                "sha1": "b" * 40,
                "link_date": "01/01/2020 00:00:00",
            },
        ])
        engine = ScanEngine(path)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WAM-001" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_detects_extension_spoofing():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Downloads\\invoice.pdf.exe", "publisher": "Contoso",
             "sha1": "c" * 40, "link_date": "01/01/2020 00:00:00"},
        ])
        engine = ScanEngine(path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WAM-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_detects_missing_hash():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Program Files\\App\\app.exe", "publisher": "Contoso",
             "sha1": None, "link_date": "01/01/2020 00:00:00"},
        ])
        engine = ScanEngine(path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WAM-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_detects_duplicate_basename_across_paths():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Windows\\svchost.exe", "publisher": "Microsoft",
             "sha1": "d" * 40, "link_date": "01/01/2020 00:00:00"},
            {"name": "0002", "path": "C:\\Users\\Public\\svchost.exe", "publisher": "Microsoft",
             "sha1": "e" * 40, "link_date": "01/01/2020 00:00:00"},
        ])
        engine = ScanEngine(path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WAM-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_detects_future_link_date():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        future_date = (datetime.utcnow() + timedelta(days=3650)).strftime("%m/%d/%Y %H:%M:%S")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Program Files\\App\\app.exe", "publisher": "Contoso",
             "sha1": "f" * 40, "link_date": future_date},
        ])
        engine = ScanEngine(path)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WAM-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_clean_entry_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Program Files\\Contoso\\app.exe", "publisher": "Contoso Ltd",
             "sha1": "1" * 40, "link_date": "01/01/2020 00:00:00"},
        ])
        engine = ScanEngine(path)
        result = engine.run()
        assert result["findings"] == []
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_legacy_file_key_layout_is_parsed():
    tmpdir = tempfile.mkdtemp()
    try:
        path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(path, entries=[], legacy_entries=[
            {"name": "0001", "path": "C:\\Windows\\legacy.exe", "publisher": "Microsoft",
             "sha1": "2" * 40, "link_date": "01/01/2015 00:00:00"},
        ])
        engine = ScanEngine(path)
        result = engine.run()
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_directory_discovers_hive_files():
    tmpdir = tempfile.mkdtemp()
    try:
        subdir = os.path.join(tmpdir, "triage", "C", "Windows", "AppCompat", "Programs")
        os.makedirs(subdir)
        path = os.path.join(subdir, "Amcache.hve")
        build_amcache_hive(path, entries=[
            {"name": "0001", "path": "C:\\Program Files\\App\\app.exe", "publisher": "Contoso",
             "sha1": "3" * 40, "link_date": "01/01/2020 00:00:00"},
        ])
        engine = ScanEngine(tmpdir)
        result = engine.run()
        assert result["files_scanned"] == 1
        assert result["dirs_scanned"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_reports_invalid_hive_as_finding_not_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        bad_path = os.path.join(tmpdir, "Amcache.hve")
        with open(bad_path, "wb") as fh:
            fh.write(b"totally not a hive")

        engine = ScanEngine(bad_path)
        result = engine.run()
        assert result["errors_count"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WAM-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_scan_engine_nonexistent_path_does_not_crash():
    engine = ScanEngine("/this/path/does/not/exist/at/all")
    result = engine.run()
    assert result["files_scanned"] == 0
    assert isinstance(result["findings"], list)
