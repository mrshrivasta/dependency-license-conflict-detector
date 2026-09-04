"""
Detection Rules — Dependency License Conflict Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL context dict built by the Security Engine from
real-parsed manifest/lockfile/LICENSE metadata and returns a Finding dict if
a real license-compatibility condition is met. Rules are intentionally
conservative, transparent, and documented so results can be independently
verified by reading the same manifest/lockfile files yourself.

Two kinds of context are produced by the engine:
  - scope == "dependency": one root-vs-one-dependency comparison
  - scope == "project": whole-project checks (root license presence, the
    overall mix of dependency license categories)

IMPORTANT: These rules flag informational license-compatibility SIGNALS
only. They are not legal advice — see README.md for the full disclaimer.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def rule_permissive_project_depends_on_copyleft(context):
    """DLC-001: The root project declares a PERMISSIVE license (e.g. MIT,
    Apache-2.0, BSD) but depends on a package under a STRONG-COPYLEFT license
    (GPL-2.0/GPL-3.0/AGPL-3.0). This is a real license-compliance risk:
    distributing the combined work may legally require the whole work to be
    relicensed under the copyleft terms. Critical severity because it can
    force a relicensing decision the project owner did not choose."""
    if context.get("scope") != "dependency":
        return None
    if (
        context.get("root_license_category") == "permissive"
        and context.get("dependency_license_category") == "strong-copyleft"
    ):
        return {
            "rule_id": "DLC-001",
            "rule_name": "Permissive Project Depends on Strong-Copyleft Package",
            "severity": SEVERITY_CRITICAL,
            "description": (
                f"Root project declares a permissive license "
                f"({context.get('root_license_raw') or context.get('root_license_canonical')}) "
                f"but depends on '{context.get('dependency_name')}', which declares "
                f"{context.get('dependency_license_raw') or context.get('dependency_license_canonical')} "
                f"(strong copyleft). Distributing the combined work may require "
                f"relicensing under the copyleft terms — consult a qualified attorney."
            ),
        }
    return None


def rule_agpl_dependency(context):
    """DLC-002: The root project depends on an AGPL-3.0-licensed package.
    Flagged separately from generic strong-copyleft because AGPL's network-use
    clause (Section 13) extends copyleft obligations to software offered over
    a network (SaaS), not just distributed binaries — an especially strong
    obligation for web-deployed software."""
    if context.get("scope") != "dependency":
        return None
    if context.get("dependency_license_canonical") == "AGPL-3.0":
        return {
            "rule_id": "DLC-002",
            "rule_name": "AGPL-3.0 Dependency (Network-Use Copyleft)",
            "severity": SEVERITY_HIGH,
            "description": (
                f"Dependency '{context.get('dependency_name')}' is licensed under AGPL-3.0 "
                f"(raw: {context.get('dependency_license_raw')}). AGPL's network-use clause "
                f"can require you to offer your combined work's source code to users who "
                f"interact with it over a network, even if you never distribute a binary. "
                f"Review carefully if this project is offered as a hosted/SaaS service."
            ),
        }
    return None


def rule_weak_copyleft_dependency(context):
    """DLC-003: The root project depends on a WEAK-COPYLEFT package
    (LGPL-2.1/LGPL-3.0/MPL-2.0). Lower risk than strong copyleft, but real
    compliance attention is still required — e.g. LGPL's dynamic-linking
    exception and MPL's file-level (not whole-work) copyleft both come with
    conditions that must be met."""
    if context.get("scope") != "dependency":
        return None
    if context.get("dependency_license_category") == "weak-copyleft":
        return {
            "rule_id": "DLC-003",
            "rule_name": "Weak-Copyleft Dependency",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"Dependency '{context.get('dependency_name')}' is licensed under "
                f"{context.get('dependency_license_raw') or context.get('dependency_license_canonical')} "
                f"(weak copyleft). Typically requires dynamic linking / keeping the "
                f"dependency's own files separate and its modifications open, rather "
                f"than relicensing your whole project. Verify your usage pattern complies."
            ),
        }
    return None


def rule_unknown_dependency_license(context):
    """DLC-004: A dependency's license could not be determined from any real
    available metadata (no license field in the lockfile entry or
    node_modules/<pkg>/package.json). This is a real transparency/compliance
    review gap, not a fabricated guess — it must be resolved manually before
    the project's overall license posture can be trusted."""
    if context.get("scope") != "dependency":
        return None
    if context.get("dependency_license_raw") in (None, ""):
        return {
            "rule_id": "DLC-004",
            "rule_name": "Dependency License Could Not Be Determined",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"No license metadata could be found for dependency "
                f"'{context.get('dependency_name')}' in the lockfile or its "
                f"package.json. This is a compliance-review gap — manually verify "
                f"this dependency's actual license before distribution."
            ),
        }
    return None


def rule_project_missing_license(context):
    """DLC-005: The root project itself declares NO license at all (no
    license field in package.json/pyproject.toml/setup.cfg/setup.py and no
    LICENSE file found). Informational: technically, default copyright
    applies and the project may not be legally usable, modifiable, or
    redistributable by anyone else at all."""
    if context.get("scope") != "project":
        return None
    if context.get("root_license_raw") in (None, ""):
        return {
            "rule_id": "DLC-005",
            "rule_name": "Root Project Declares No License",
            "severity": SEVERITY_LOW,
            "description": (
                "No license field or LICENSE file was found for this project. "
                "Under default copyright rules, nobody else may legally use, "
                "modify, or redistribute this code without permission. If this "
                "project is meant to be shared or open-sourced, add an explicit "
                "license."
            ),
        }
    return None


def rule_mixed_license_landscape(context):
    """DLC-006: Two or more dependencies fall into conflicting license
    category tiers relative to EACH OTHER (e.g. strong-copyleft mixed with
    permissive dependencies), independent of the root project's own license.
    A general 'mixed license landscape' signal worth a compliance review even
    before considering the root project's own terms."""
    if context.get("scope") != "project":
        return None
    categories = set(context.get("dependency_categories") or [])
    if "strong-copyleft" in categories and "permissive" in categories:
        return {
            "rule_id": "DLC-006",
            "rule_name": "Mixed License Landscape Across Dependencies",
            "severity": SEVERITY_LOW,
            "description": (
                f"This project's dependencies mix strong-copyleft and permissive "
                f"license categories together ({', '.join(sorted(categories))}). "
                f"Even independent of the root project's own license, combining "
                f"dependencies across these tiers is worth a compliance review."
            ),
        }
    return None


PER_DEPENDENCY_RULES = [
    rule_permissive_project_depends_on_copyleft,
    rule_agpl_dependency,
    rule_weak_copyleft_dependency,
    rule_unknown_dependency_license,
]

SCAN_LEVEL_RULES = [
    rule_project_missing_license,
    rule_mixed_license_landscape,
]

ALL_RULES = PER_DEPENDENCY_RULES + SCAN_LEVEL_RULES
