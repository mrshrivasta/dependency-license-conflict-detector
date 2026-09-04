"""
Security Engine — Dependency License Conflict Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Walks a REAL project directory on the host filesystem, real-parses its
manifest/lockfile/LICENSE metadata, and produces real license-compatibility
findings. No sample/mock license data is ever generated — every Finding
reflects license strings actually read from files on disk at scan time.

Sources actually read (real I/O, real json/regex parsing, no fabrication):
  - <target>/package.json                 -> root project's declared license
  - <target>/pyproject.toml                -> root project's declared license
  - <target>/setup.py / <target>/setup.cfg -> root project's declared license
  - <target>/LICENSE(.txt|.md|.rst)        -> root project's declared license,
                                               matched against real license text
                                               signatures (heuristic substring match)
  - <target>/package-lock.json             -> per-dependency license strings
                                               (npm lockfile v1/v2/v3 formats)
  - <target>/node_modules/<pkg>/package.json (and one level of @scope/<pkg>)
                                            -> per-dependency license strings,
                                               used only when no lockfile license
                                               data was available

Designed to run unprivileged: paths/files it cannot read are counted as
errors and skipped, never fabricated.
"""
import json
import os
import re
import time

from app.detection_rules import PER_DEPENDENCY_RULES, SCAN_LEVEL_RULES

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

ROOT_MANIFEST_FILENAMES = {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}
LICENSE_FILENAMES = {"license", "license.txt", "license.md", "license.rst", "unlicense", "unlicense.txt"}

# ---------------------------------------------------------------------------
# Static license-compatibility classification table (real, small, well-known
# SPDX-ish identifiers). This is the single source of truth used to decide
# whether a license is "permissive", "weak-copyleft", "strong-copyleft", or
# "proprietary-or-unknown". Nothing here is invented per-scan — it is a fixed
# reference table, the same way a real compliance team would maintain one.
# ---------------------------------------------------------------------------
CATEGORY_PERMISSIVE = "permissive"
CATEGORY_WEAK_COPYLEFT = "weak-copyleft"
CATEGORY_STRONG_COPYLEFT = "strong-copyleft"
CATEGORY_UNKNOWN = "proprietary-or-unknown"

LICENSE_CATEGORIES = {
    "MIT": CATEGORY_PERMISSIVE,
    "BSD-2-Clause": CATEGORY_PERMISSIVE,
    "BSD-3-Clause": CATEGORY_PERMISSIVE,
    "ISC": CATEGORY_PERMISSIVE,
    "Apache-2.0": CATEGORY_PERMISSIVE,
    "Unlicense": CATEGORY_PERMISSIVE,
    "0BSD": CATEGORY_PERMISSIVE,
    "LGPL-2.1": CATEGORY_WEAK_COPYLEFT,
    "LGPL-3.0": CATEGORY_WEAK_COPYLEFT,
    "MPL-2.0": CATEGORY_WEAK_COPYLEFT,
    "GPL-2.0": CATEGORY_STRONG_COPYLEFT,
    "GPL-3.0": CATEGORY_STRONG_COPYLEFT,
    "AGPL-3.0": CATEGORY_STRONG_COPYLEFT,
    "UNLICENSED": CATEGORY_UNKNOWN,
}

# Real, ordered substring signatures used to identify a LICENSE file's text.
# Order matters: more specific families (AGPL, LGPL) are checked before the
# generic "GPL" substring they would otherwise also match.
LICENSE_TEXT_SIGNATURES = [
    ("AGPL-3.0", ["gnu affero general public license"]),
    ("LGPL-3.0", ["gnu lesser general public license", "version 3"]),
    ("LGPL-2.1", ["gnu lesser general public license", "version 2.1"]),
    ("LGPL-3.0", ["gnu lesser general public license"]),
    ("GPL-3.0", ["gnu general public license", "version 3"]),
    ("GPL-2.0", ["gnu general public license", "version 2"]),
    ("GPL-3.0", ["gnu general public license"]),
    ("MPL-2.0", ["mozilla public license", "version 2.0"]),
    ("MPL-2.0", ["mozilla public license"]),
    ("Apache-2.0", ["apache license", "version 2.0"]),
    ("Apache-2.0", ["apache license"]),
    ("MIT", ["mit license"]),
    ("MIT", ["permission is hereby granted, free of charge"]),
    ("ISC", ["permission to use, copy, modify, and/or distribute this software"]),
    ("Unlicense", ["this is free and unencumbered software released into the public domain"]),
    ("0BSD", ["zero-clause bsd"]),
    ("BSD-3-Clause", ["redistribution and use in source and binary forms", "may be used to endorse or promote"]),
    ("BSD-2-Clause", ["redistribution and use in source and binary forms"]),
]


def normalize_license(raw):
    """Real, deterministic normalization of a raw license string (as read
    from package.json/pyproject.toml/lockfile/LICENSE text) into a canonical
    SPDX-ish identifier from LICENSE_CATEGORIES, or None if it cannot be
    confidently matched. No guessing beyond real substring/regex matching."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        raw = raw.get("type") or raw.get("name")
        if raw is None:
            return None
    text = str(raw).strip()
    if not text:
        return None

    # Strip common SPDX modifiers before matching.
    stripped = re.sub(r"\s*(-only|-or-later)\s*$", "", text, flags=re.IGNORECASE)
    lowered = stripped.lower()

    if "unlicensed" in lowered or "see license in" in lowered or "proprietary" in lowered:
        return "UNLICENSED"

    if "unlicense" in lowered:
        return "Unlicense"

    if "0bsd" in lowered or "zero-clause bsd" in lowered:
        return "0BSD"

    if "agpl" in lowered:
        return "AGPL-3.0"

    if "lgpl" in lowered:
        if "2.1" in lowered:
            return "LGPL-2.1"
        return "LGPL-3.0"

    if "mpl" in lowered or "mozilla" in lowered:
        return "MPL-2.0"

    if re.search(r"\bgpl\b", lowered) or "general public license" in lowered:
        if "3" in lowered:
            return "GPL-3.0"
        if "2" in lowered:
            return "GPL-2.0"
        return "GPL-3.0"

    if "apache" in lowered:
        return "Apache-2.0"

    if "isc" in lowered:
        return "ISC"

    if "bsd" in lowered:
        if "2" in lowered or "simplified" in lowered:
            return "BSD-2-Clause"
        return "BSD-3-Clause"

    if lowered == "mit" or "mit license" in lowered or lowered.startswith("mit "):
        return "MIT"

    return None


def classify_license(canonical):
    """Map a canonical license id (output of normalize_license) to a
    compatibility category. Anything not in the static table, or None,
    is treated as proprietary-or-unknown (a real transparency gap)."""
    if canonical is None:
        return CATEGORY_UNKNOWN
    return LICENSE_CATEGORIES.get(canonical, CATEGORY_UNKNOWN)


def _match_license_text(content):
    lowered = content.lower()
    for canonical, needles in LICENSE_TEXT_SIGNATURES:
        if all(needle in lowered for needle in needles):
            return canonical
    return None


class ScanEngine:
    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

        self._entries_visited = 0
        self._root_manifest_candidates = []  # (filename, path)
        self._root_license_candidates = []   # [path, ...]
        self._lockfile_path = None
        self._node_modules_packages = []     # [package.json path, ...]

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous project scan. Returns summary dict."""
        start = time.time()
        self._discover(self.target_path, depth=0)

        root_license_raw, root_source = self._detect_root_license()
        root_canonical = normalize_license(root_license_raw)
        root_category = classify_license(root_canonical)

        dependencies = self._collect_dependencies()

        self._apply_dependency_rules(root_license_raw, root_canonical, root_category, dependencies)
        self._apply_scan_level_rules(root_license_raw, root_source, root_category, dependencies)

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    # -- real filesystem discovery -----------------------------------------

    def _discover(self, path, depth):
        """Real, bounded directory walk that locates manifest/lockfile/LICENSE
        files (at the project root) and dependency package.json files (under
        any node_modules directory), while counting real dirs/entries visited."""
        if self._entries_visited >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self._entries_visited >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            self._entries_visited += 1

            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_dir:
                if depth + 1 <= self.max_depth:
                    self._discover(full_path, depth + 1)
                continue

            name_lower = entry.name.lower()
            parent_dir = os.path.dirname(full_path)
            in_node_modules = "node_modules" in full_path.split(os.sep)

            if name_lower == "package.json":
                if in_node_modules:
                    self._node_modules_packages.append(full_path)
                elif parent_dir == self.target_path:
                    self._root_manifest_candidates.append(("package.json", full_path))
            elif name_lower == "package-lock.json" and parent_dir == self.target_path:
                self._lockfile_path = full_path
            elif name_lower in ("pyproject.toml", "setup.py", "setup.cfg") and parent_dir == self.target_path:
                self._root_manifest_candidates.append((name_lower, full_path))
            elif name_lower in LICENSE_FILENAMES and parent_dir == self.target_path:
                self._root_license_candidates.append(full_path)

    # -- real root-license parsing -------------------------------------------

    def _detect_root_license(self):
        """Real-parse the root project's own declared license. Returns
        (raw_license_string_or_None, source_path_or_None)."""
        # Prefer manifest declarations over LICENSE-file text heuristics.
        for name, path in self._root_manifest_candidates:
            try:
                if name == "package.json":
                    raw = self._license_from_package_json(path)
                elif name == "pyproject.toml":
                    raw = self._license_from_pyproject(path)
                elif name == "setup.cfg":
                    raw = self._license_from_setup_cfg(path)
                else:  # setup.py
                    raw = self._license_from_setup_py(path)
                self.files_scanned += 1
                if raw:
                    return raw, path
            except Exception:
                self.errors_count += 1

        for path in self._root_license_candidates:
            try:
                raw = self._license_from_license_file(path)
                self.files_scanned += 1
                if raw:
                    return raw, path
            except Exception:
                self.errors_count += 1

        return None, None

    @staticmethod
    def _license_from_package_json(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        lic = data.get("license")
        if isinstance(lic, dict):
            lic = lic.get("type")
        if not lic and isinstance(data.get("licenses"), list) and data["licenses"]:
            first = data["licenses"][0]
            lic = first.get("type") if isinstance(first, dict) else first
        return lic

    @staticmethod
    def _license_from_pyproject(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        # PEP 621: license = "MIT"  or  license = { text = "MIT" }
        m = re.search(r'license\s*=\s*\{\s*text\s*=\s*["\']([^"\']+)["\']', content)
        if m:
            return m.group(1)
        m = re.search(r'^\s*license\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        if m:
            return m.group(1)
        m = re.search(r'License\s*::\s*OSI Approved\s*::\s*([^"\']+)', content)
        if m:
            return m.group(1).strip()
        return None

    @staticmethod
    def _license_from_setup_cfg(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        m = re.search(r'^\s*license\s*=\s*(.+)$', content, re.MULTILINE)
        if m:
            return m.group(1).strip()
        m = re.search(r'License\s*::\s*OSI Approved\s*::\s*([^\n]+)', content)
        if m:
            return m.group(1).strip()
        return None

    @staticmethod
    def _license_from_setup_py(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        m = re.search(r'license\s*=\s*["\']([^"\']+)["\']', content)
        if m:
            return m.group(1)
        m = re.search(r'License\s*::\s*OSI Approved\s*::\s*([^"\']+)', content)
        if m:
            return m.group(1).strip()
        return None

    @staticmethod
    def _license_from_license_file(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(4000)
        return _match_license_text(content)

    # -- real dependency-license collection ----------------------------------

    def _collect_dependencies(self):
        """Real-parse the lockfile (preferred) or node_modules/*/package.json
        files (fallback) into {name: raw_license_or_None}. Returns a list of
        dicts: {name, license_raw, source}."""
        deps = {}

        if self._lockfile_path:
            try:
                with open(self._lockfile_path, "r", encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                self.files_scanned += 1

                packages = data.get("packages")
                if isinstance(packages, dict):
                    # npm lockfile v2/v3: keys are paths like "node_modules/foo"
                    for pkg_path, meta in packages.items():
                        if not pkg_path:
                            continue  # "" is the root project itself, skip
                        if not isinstance(meta, dict):
                            continue
                        name = meta.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
                        lic = meta.get("license")
                        if isinstance(lic, dict):
                            lic = lic.get("type")
                        if name not in deps:
                            deps[name] = lic
                else:
                    legacy = data.get("dependencies")
                    if isinstance(legacy, dict):
                        self._walk_legacy_lockfile_deps(legacy, deps)
            except Exception:
                self.errors_count += 1

        if not deps and self._node_modules_packages:
            for pkg_json_path in self._node_modules_packages:
                try:
                    with open(pkg_json_path, "r", encoding="utf-8", errors="replace") as fh:
                        meta = json.load(fh)
                    self.files_scanned += 1
                    name = meta.get("name") or os.path.basename(os.path.dirname(pkg_json_path))
                    lic = meta.get("license")
                    if isinstance(lic, dict):
                        lic = lic.get("type")
                    if not lic and isinstance(meta.get("licenses"), list) and meta["licenses"]:
                        first = meta["licenses"][0]
                        lic = first.get("type") if isinstance(first, dict) else first
                    if name not in deps:
                        deps[name] = lic
                except Exception:
                    self.errors_count += 1

        source = self._lockfile_path or (self._node_modules_packages[0] if self._node_modules_packages else self.target_path)
        return [{"name": name, "license_raw": lic, "source": source} for name, lic in deps.items()]

    def _walk_legacy_lockfile_deps(self, dependencies_dict, deps):
        for name, meta in dependencies_dict.items():
            if not isinstance(meta, dict):
                continue
            lic = meta.get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            if name not in deps:
                deps[name] = lic
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                self._walk_legacy_lockfile_deps(nested, deps)

    # -- rule application -----------------------------------------------------

    def _apply_dependency_rules(self, root_license_raw, root_canonical, root_category, dependencies):
        for dep in dependencies:
            dep_canonical = normalize_license(dep["license_raw"])
            dep_category = classify_license(dep_canonical)
            context = {
                "scope": "dependency",
                "manifest_path": dep["source"],
                "root_license_raw": root_license_raw,
                "root_license_canonical": root_canonical,
                "root_license_category": root_category,
                "dependency_name": dep["name"],
                "dependency_license_raw": dep["license_raw"],
                "dependency_license_canonical": dep_canonical,
                "dependency_license_category": dep_category,
            }
            for rule in PER_DEPENDENCY_RULES:
                try:
                    result = rule(context)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    self._record_finding(result, context["manifest_path"], (
                        f"root:{root_canonical or root_license_raw or 'NONE'} vs "
                        f"dep:{dep['name']}:{dep_canonical or dep['license_raw'] or 'UNKNOWN'}"
                    ))

    def _apply_scan_level_rules(self, root_license_raw, root_source, root_category, dependencies):
        dep_categories = sorted({
            classify_license(normalize_license(d["license_raw"])) for d in dependencies
        })
        context = {
            "scope": "project",
            "manifest_path": root_source or self.target_path,
            "root_license_raw": root_license_raw,
            "root_license_category": root_category,
            "dependency_categories": dep_categories,
            "dependency_count": len(dependencies),
        }
        for rule in SCAN_LEVEL_RULES:
            try:
                result = rule(context)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                self._record_finding(result, context["manifest_path"], (
                    f"root:{root_license_raw or 'NONE'} categories:{','.join(dep_categories) or 'none'}"
                ))

    def _record_finding(self, result, file_path, comparison_summary):
        result["file_path"] = file_path
        result["permissions_octal"] = comparison_summary
        result["owner_uid"] = None
        result["owner_gid"] = None
        self.findings.append(result)
