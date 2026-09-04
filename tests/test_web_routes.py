import os
import shutil
import tempfile

from tests.hive_builder import build_amcache_hive


def test_full_scan_alert_incident_workflow(registered_client):
    # Real-build a real Amcache.hve on disk with an entry that trips a real
    # detection rule (empty publisher + suspicious execution directory).
    tmpdir = tempfile.mkdtemp()
    try:
        hive_path = os.path.join(tmpdir, "Amcache.hve")
        build_amcache_hive(hive_path, entries=[
            {
                "name": "0001",
                "path": "C:\\Users\\Public\\evil.exe",
                "publisher": "",
                "sha1": "a" * 40,
                "link_date": "01/01/2020 00:00:00",
            },
        ])

        resp = registered_client.post("/scan/run", data={"target_path": hive_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert hive_path.encode() in resp.data

        # Alerts page should load and contain the real WAM-001 alert
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp/Amcache.hve",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp/Amcache.hve" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
