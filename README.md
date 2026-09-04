# Dependency License Conflict Detector

**A real, no-mock-data dependency license-compatibility scanner — CLI + Web App.**
Real-parses your project's own declared license (`package.json`, `pyproject.toml`, `setup.py`/`setup.cfg`, or a `LICENSE` file) together with your dependency lockfile or `node_modules` metadata, then flags real license-compatibility risks: permissive projects depending on GPL/AGPL packages, AGPL's network-use obligations, weak-copyleft dependencies, dependencies whose license can't be determined at all, projects with no declared license, and a mixed license landscape across dependencies.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ DISCLAIMER (READ BEFORE USE)

This software is provided **strictly for educational and informational compliance-awareness purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **NOT LEGAL ADVICE.** This tool provides **informational license-compatibility signals only**, derived from real-parsed manifest, lockfile, and LICENSE-file metadata. It does **not** constitute legal advice, and it is **not** a substitute for review by a qualified attorney. License compatibility is a legal question that depends on facts this tool cannot see (how code is linked, distributed, modified, or offered as a service). **Consult a qualified attorney before making any actual license-compliance decision.**
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including legal exposure, licensing disputes, business impact, or lost revenue — arising from the use, misuse, or inability to use this software.
- **Not a certified audit.** This tool is **not a substitute** for a professional legal license audit, a certified open-source compliance review (e.g. by an OSPO or outside counsel), or a review by a qualified intellectual-property attorney. Findings are heuristic string/metadata matches and may include false positives and false negatives.
- **No guaranteed detection.** Absence of findings does **not** mean a project's dependency licensing is safe or compliant. This tool checks a specific, limited set of license-metadata patterns only, and can only see what lockfiles/manifests/LICENSE files actually declare.
- **Read-only by design.** The Security Engine only reads manifest/lockfile/LICENSE files — it never modifies your project's files, dependencies, or licenses. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you need an authoritative answer on license compatibility for your project, **talk to a qualified attorney — do not rely on this tool alone.**

---

## Who should use this project

- Engineering leads and open-source maintainers who want an early, automated signal before a GPL/AGPL dependency quietly creeps into a permissively-licensed project.
- Legal/compliance-adjacent engineers and OSPO (Open Source Program Office) staff triaging dependency trees before a deeper manual/legal review.
- Anyone shipping software built on third-party npm/Python dependencies who wants visibility into what licenses those dependencies actually declare.
- CI/CD pipelines that want a license-hygiene gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from real-parsed `package.json`, `pyproject.toml`, `setup.py`/`setup.cfg`, `package-lock.json`, `node_modules/*/package.json`, and `LICENSE` files on disk. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`, driven by a small static license-classification table in `app/security_engine/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a scanner** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
dependency-license-conflict-detector/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real license-parsing/classification engine
│   ├── detection_rules/      # 6 documented detection rules (DLC-001..DLC-006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real temp-filesystem manifests/lockfiles
├── docs/                      # Additional documentation
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| DLC-001 | Permissive Project Depends on Strong-Copyleft Package | Critical | Root project is permissive (MIT/BSD/Apache/etc.) but depends on a GPL-2.0/GPL-3.0/AGPL-3.0 package |
| DLC-002 | AGPL-3.0 Dependency (Network-Use Copyleft) | High | Any dependency is AGPL-3.0 — flagged separately due to AGPL's network-use (SaaS) obligations |
| DLC-003 | Weak-Copyleft Dependency | Medium | Dependency is LGPL-2.1/LGPL-3.0/MPL-2.0 — lower risk but real compliance attention still required |
| DLC-004 | Dependency License Could Not Be Determined | Medium | No license metadata found for a dependency in the lockfile or its `package.json` — a transparency gap |
| DLC-005 | Root Project Declares No License | Low | No license field or LICENSE file found for the project itself — default copyright applies |
| DLC-006 | Mixed License Landscape Across Dependencies | Low | Dependencies mix strong-copyleft and permissive categories together, independent of the root project's own license |

---

## How license detection works (real parsing, no fabrication)

1. **Root project license** — checked in order: `package.json` `"license"` field, `pyproject.toml` (PEP 621 `license = "..."` or Poetry-style, or `License :: OSI Approved :: ...` classifiers), `setup.cfg`/`setup.py` `license=` argument or classifiers, then a `LICENSE`/`LICENSE.txt`/`LICENSE.md`/`LICENSE.rst` file matched against real license-text signatures (e.g. "MIT License", "GNU GENERAL PUBLIC LICENSE", "Apache License", "GNU AFFERO GENERAL PUBLIC LICENSE").
2. **Dependency licenses** — real-parsed from `package-lock.json` (npm lockfile v1/v2/v3 formats carry a `"license"` field per package in many cases), falling back to reading each `node_modules/<pkg>/package.json` `"license"` field directly off disk when no lockfile license data is available.
3. **Classification** — each raw license string is normalized (e.g. `"GPL-3.0-or-later"` → `GPL-3.0`, `"MIT License"` → `MIT`) and classified into `permissive`, `weak-copyleft`, `strong-copyleft`, or `proprietary-or-unknown` using a small static table in `app/security_engine/__init__.py`.
4. **Comparison** — the root project's category is compared against every dependency's category (and dependencies are compared against each other) to produce the findings above.

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS — the engine only reads text/JSON files (no OS-specific permission bits involved)

### Install

```bash
git clone <this-repository-url>
cd dependency-license-conflict-detector
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
DLC_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/dlc.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/your/project --depth 4
python3 cli/main.py scan /path/to/your/project --json
python3 cli/main.py scan /path/to/your/project --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI gate) and `0` if the target is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

31 tests: rule-level unit tests against synthetic context dicts, plus engine-level tests that write real `package.json`/`package-lock.json`/`LICENSE` files into real temp directories and run the real `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Dependency License Conflict Detector check?**
It real-parses your project's declared license and your dependency lockfile/`node_modules` metadata, then flags a permissive project depending on GPL/AGPL packages, AGPL dependencies specifically, weak-copyleft dependencies, dependencies with no discoverable license, a missing project license, and a mixed license landscape across dependencies.

**Who should use it?**
Engineering leads, open-source maintainers, compliance-adjacent engineers, and anyone shipping software built on third-party dependencies they haven't fully audited.

**Is it a substitute for legal advice?**
No. It provides informational license-compatibility signals only — see the Disclaimer section above. Consult a qualified attorney for actual compliance decisions.

**Does it modify my project?**
No. It only reads manifest, lockfile, and LICENSE files. It never writes to, deletes, or modifies your dependencies, licenses, or source code.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
