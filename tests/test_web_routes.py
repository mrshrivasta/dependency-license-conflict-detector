import json
import os
import shutil
import tempfile


def _make_mit_vs_gpl_project():
    """Real temp project dir: package.json declares MIT, package-lock.json
    has one dependency declared GPL-3.0 -> triggers a real DLC-001 finding."""
    tmpdir = tempfile.mkdtemp()
    with open(os.path.join(tmpdir, "package.json"), "w") as f:
        json.dump({"name": "web-test-app", "version": "1.0.0", "license": "MIT"}, f)
    lockfile = {
        "packages": {
            "": {"name": "web-test-app"},
            "node_modules/left-pad": {"version": "1.3.0", "license": "MIT"},
            "node_modules/gpl-utils": {"version": "2.0.0", "license": "GPL-3.0"},
        }
    }
    with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
        json.dump(lockfile, f)
    return tmpdir


def test_full_scan_alert_incident_workflow(registered_client):
    project_dir = _make_mit_vs_gpl_project()
    try:
        resp = registered_client.post("/scan/run", data={"target_path": project_dir}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert project_dir.encode() in resp.data

        # Alerts page should load and contain a real DLC-001 alert (critical
        # severity meets the default "medium" alert threshold)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200
        assert b"DLC-001" in resp.data

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json
        data = resp.get_json()
        assert "critical" in data["severity_breakdown"]

        # Reports CSV export works and contains the real finding
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")
        assert b"DLC-001" in resp.data
    finally:
        shutil.rmtree(project_dir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404
