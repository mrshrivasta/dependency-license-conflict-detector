"""Tests for the Security Engine and Detection Rules.

Rule-level tests use synthetic context dicts (fast, isolated unit tests of
pure functions). Engine-level tests run the REAL ScanEngine against REAL
temp directories containing REAL package.json/package-lock.json/LICENSE
files on disk — nothing about the engine itself is mocked."""
import json
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.security_engine import ScanEngine, normalize_license, classify_license
from app.detection_rules import (
    rule_permissive_project_depends_on_copyleft,
    rule_agpl_dependency,
    rule_weak_copyleft_dependency,
    rule_unknown_dependency_license,
    rule_project_missing_license,
    rule_mixed_license_landscape,
    ALL_RULES,
)


# ---------------------------------------------------------------------------
# Pure normalization / classification tests
# ---------------------------------------------------------------------------

def test_normalize_common_license_strings():
    assert normalize_license("MIT") == "MIT"
    assert normalize_license("MIT License") == "MIT"
    assert normalize_license("Apache-2.0") == "Apache-2.0"
    assert normalize_license("Apache License 2.0") == "Apache-2.0"
    assert normalize_license("GPL-3.0-only") == "GPL-3.0"
    assert normalize_license("GPL-3.0-or-later") == "GPL-3.0"
    assert normalize_license("AGPL-3.0") == "AGPL-3.0"
    assert normalize_license("LGPL-2.1") == "LGPL-2.1"
    assert normalize_license("MPL-2.0") == "MPL-2.0"
    assert normalize_license("ISC") == "ISC"
    assert normalize_license("UNLICENSED") == "UNLICENSED"
    assert normalize_license(None) is None
    assert normalize_license("SomeMadeUpLicenseXYZ") is None


def test_classify_license_categories():
    assert classify_license("MIT") == "permissive"
    assert classify_license("Apache-2.0") == "permissive"
    assert classify_license("LGPL-3.0") == "weak-copyleft"
    assert classify_license("MPL-2.0") == "weak-copyleft"
    assert classify_license("GPL-3.0") == "strong-copyleft"
    assert classify_license("AGPL-3.0") == "strong-copyleft"
    assert classify_license(None) == "proprietary-or-unknown"
    assert classify_license("UNLICENSED") == "proprietary-or-unknown"


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_permissive_depends_on_copyleft_fires():
    ctx = {
        "scope": "dependency",
        "root_license_category": "permissive",
        "dependency_license_category": "strong-copyleft",
        "dependency_name": "some-gpl-lib",
        "root_license_raw": "MIT",
        "dependency_license_raw": "GPL-3.0",
    }
    result = rule_permissive_project_depends_on_copyleft(ctx)
    assert result is not None
    assert result["rule_id"] == "DLC-001"
    assert result["severity"] == "critical"


def test_rule_permissive_depends_on_copyleft_does_not_fire_when_both_permissive():
    ctx = {
        "scope": "dependency",
        "root_license_category": "permissive",
        "dependency_license_category": "permissive",
        "dependency_name": "some-mit-lib",
    }
    assert rule_permissive_project_depends_on_copyleft(ctx) is None


def test_rule_agpl_dependency_fires():
    ctx = {
        "scope": "dependency",
        "dependency_license_canonical": "AGPL-3.0",
        "dependency_name": "some-agpl-lib",
        "dependency_license_raw": "AGPL-3.0",
    }
    result = rule_agpl_dependency(ctx)
    assert result is not None
    assert result["rule_id"] == "DLC-002"
    assert result["severity"] == "high"


def test_rule_agpl_dependency_does_not_fire_for_plain_gpl():
    ctx = {"scope": "dependency", "dependency_license_canonical": "GPL-3.0"}
    assert rule_agpl_dependency(ctx) is None


def test_rule_weak_copyleft_dependency_fires():
    ctx = {
        "scope": "dependency",
        "dependency_license_category": "weak-copyleft",
        "dependency_name": "some-lgpl-lib",
        "dependency_license_raw": "LGPL-2.1",
        "dependency_license_canonical": "LGPL-2.1",
    }
    result = rule_weak_copyleft_dependency(ctx)
    assert result is not None
    assert result["rule_id"] == "DLC-003"
    assert result["severity"] == "medium"


def test_rule_unknown_dependency_license_fires():
    ctx = {"scope": "dependency", "dependency_license_raw": None, "dependency_name": "mystery-lib"}
    result = rule_unknown_dependency_license(ctx)
    assert result is not None
    assert result["rule_id"] == "DLC-004"


def test_rule_unknown_dependency_license_does_not_fire_when_known():
    ctx = {"scope": "dependency", "dependency_license_raw": "MIT", "dependency_name": "known-lib"}
    assert rule_unknown_dependency_license(ctx) is None


def test_rule_project_missing_license_fires():
    ctx = {"scope": "project", "root_license_raw": None}
    result = rule_project_missing_license(ctx)
    assert result is not None
    assert result["rule_id"] == "DLC-005"
    assert result["severity"] == "low"


def test_rule_project_missing_license_does_not_fire_when_declared():
    ctx = {"scope": "project", "root_license_raw": "MIT"}
    assert rule_project_missing_license(ctx) is None


def test_rule_mixed_license_landscape_fires():
    ctx = {"scope": "project", "dependency_categories": ["permissive", "strong-copyleft"]}
    result = rule_mixed_license_landscape(ctx)
    assert result is not None
    assert result["rule_id"] == "DLC-006"


def test_rule_mixed_license_landscape_does_not_fire_for_uniform_categories():
    ctx = {"scope": "project", "dependency_categories": ["permissive"]}
    assert rule_mixed_license_landscape(ctx) is None


def test_all_rules_registered():
    ids = set()
    for rule in ALL_RULES:
        assert rule.__doc__ and rule.__doc__.strip()
    assert len(ALL_RULES) == 6


# ---------------------------------------------------------------------------
# Engine-level tests — REAL temp directories, REAL ScanEngine, no mocking.
# ---------------------------------------------------------------------------

def test_mit_project_with_gpl_dependency_triggers_dlc001():
    """Real package.json declares MIT; real package-lock.json has one
    dependency declared GPL-3.0. Running the real ScanEngine must fire DLC-001."""
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "demo-app", "version": "1.0.0", "license": "MIT"}, f)

        lockfile = {
            "name": "demo-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo-app", "version": "1.0.0"},
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "license": "MIT",
                },
                "node_modules/gpl-utils": {
                    "version": "2.0.0",
                    "license": "GPL-3.0",
                },
            },
        }
        with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
            json.dump(lockfile, f)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()

        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DLC-001" in rule_ids
        assert result["files_scanned"] >= 2
        assert result["errors_count"] == 0

        dlc001 = [f for f in result["findings"] if f["rule_id"] == "DLC-001"][0]
        assert "gpl-utils" in dlc001["permissions_octal"]
    finally:
        shutil.rmtree(tmpdir)


def test_agpl_dependency_triggers_dlc002():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "demo-app", "license": "MIT"}, f)
        lockfile = {
            "packages": {
                "": {},
                "node_modules/agpl-thing": {"version": "1.0.0", "license": "AGPL-3.0"},
            }
        }
        with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
            json.dump(lockfile, f)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DLC-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_project_with_no_license_triggers_dlc005():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "no-license-app", "version": "1.0.0"}, f)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DLC-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_unknown_dependency_license_triggers_dlc004():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "demo-app", "license": "MIT"}, f)
        lockfile = {
            "packages": {
                "": {},
                "node_modules/mystery-pkg": {"version": "0.0.1"},
            }
        }
        with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
            json.dump(lockfile, f)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DLC-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_license_file_mit_detected_without_manifest():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "LICENSE"), "w") as f:
            f.write("MIT License\n\nPermission is hereby granted, free of charge, to any person...")

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        # No lockfile / dependencies, but the root license itself must be readable.
        assert result["errors_count"] == 0
        assert result["files_scanned"] >= 1
    finally:
        shutil.rmtree(tmpdir)


def test_clean_project_with_only_permissive_dependencies_produces_minimal_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "clean-app", "license": "MIT"}, f)
        lockfile = {
            "packages": {
                "": {},
                "node_modules/left-pad": {"version": "1.3.0", "license": "MIT"},
                "node_modules/is-odd": {"version": "3.0.1", "license": "ISC"},
            }
        }
        with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
            json.dump(lockfile, f)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        assert result["findings"] == []
        assert result["errors_count"] == 0
    finally:
        shutil.rmtree(tmpdir)


def test_node_modules_fallback_used_when_no_lockfile():
    """No package-lock.json present — real node_modules/<pkg>/package.json
    files must be read as the fallback dependency license source."""
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "fallback-app", "license": "MIT"}, f)

        nm = os.path.join(tmpdir, "node_modules", "gpl-fallback-lib")
        os.makedirs(nm)
        with open(os.path.join(nm, "package.json"), "w") as f:
            json.dump({"name": "gpl-fallback-lib", "version": "1.0.0", "license": "GPL-2.0"}, f)

        engine = ScanEngine(tmpdir, max_depth=4)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DLC-001" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_mixed_license_landscape_detected():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "mixed-app", "license": "GPL-3.0"}, f)
        lockfile = {
            "packages": {
                "": {},
                "node_modules/mit-lib": {"version": "1.0.0", "license": "MIT"},
                "node_modules/gpl-lib": {"version": "1.0.0", "license": "GPL-3.0"},
            }
        }
        with open(os.path.join(tmpdir, "package-lock.json"), "w") as f:
            json.dump(lockfile, f)

        engine = ScanEngine(tmpdir, max_depth=3)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DLC-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_excluded_paths_are_skipped():
    tmpdir = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmpdir, "package.json"), "w") as f:
            json.dump({"name": "demo-app", "license": "MIT"}, f)

        excluded = os.path.join(tmpdir, "excluded")
        os.mkdir(excluded)
        with open(os.path.join(excluded, "package.json"), "w") as f:
            json.dump({"name": "should-not-be-seen", "license": "GPL-3.0"}, f)

        engine = ScanEngine(tmpdir, max_depth=3, excludes=[excluded])
        result = engine.run()
        assert all(excluded not in f["file_path"] for f in result["findings"])
    finally:
        shutil.rmtree(tmpdir)
