# Windows Amcache Analyzer

**A real, no-mock-data Windows `Amcache.hve` registry-hive execution-artifact analyzer — CLI + Web App.**
Real-opens a real `Amcache.hve` file with the `python-registry` library, real-walks the actual `Root\InventoryApplicationFile` (Windows 10+) and legacy `Root\File\{volume guid}\` (Windows 8/8.1) keys, and surfaces genuine digital-forensics anomalies: unsigned binaries executed from suspicious locations, extension-spoofing, future-dated PE timestamps, duplicate/masquerading binaries, and missing integrity hashes.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer (read before use)

This software is provided **strictly for educational, digital-forensics, and incident-response purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Analyze **only** Amcache.hve files, disk images, or media that you own or for which you have explicit, documented authorization to investigate. Analyzing systems or evidence without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction), evidentiary chain-of-custody requirements, and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, missed findings, mishandled evidence, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is **not a substitute** for a certified forensic suite (e.g. EnCase, X-Ways, Magnet AXIOM), a court-qualified forensic examiner, or expert witness testimony. Findings are heuristic and may include false positives and false negatives; they should be corroborated with other artifacts before being relied upon.
- **No guaranteed detection.** Absence of findings does **not** mean a system is clean. This tool checks a specific, limited set of Amcache-derived anomalies only, and Amcache itself is only one of many Windows execution-artifact sources (Prefetch, ShimCache, UserAssist, event logs, etc.).
- **Read-only by design.** The Security Engine only opens hive files in binary read mode — it never writes to, modifies, or repairs the hive it analyzes. Verify this yourself by reading `app/security_engine/__init__.py` before running it on evidentiary material.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given hive or system, **do not run this tool against it.**

---

## What is Amcache.hve, and how do you get a copy?

`Amcache.hve` is a real Windows registry hive at `%SystemRoot%\AppCompat\Programs\Amcache.hve` that Windows maintains as part of the Application Compatibility (AppCompat) subsystem. It records metadata about executables that have been present or run on the system — full path, publisher, file size, SHA-1 hash, and a PE `LinkDate` (compile/link timestamp) — making it one of the most valuable Windows program-execution artifacts for DFIR (Digital Forensics & Incident Response) work.

**Acquisition note:** on a live, running Windows system, `Amcache.hve` is locked by the OS and cannot simply be copied with Explorer. Analysts normally acquire it **offline** — from a forensic disk image, a volume shadow copy, or a live-triage tool (e.g. KAPE, FTK Imager, `reg save` from an elevated/offline context) — and then point this analyzer at the **already-extracted** file. This tool does not attempt to read a locked live hive; it operates on a real file you have already, legitimately, copied out.

---

## Who should use this project

- Digital Forensics & Incident Response (DFIR) analysts triaging Windows program-execution evidence.
- SOC / incident-response teams confirming what actually ran on a compromised host.
- Security students and self-learners studying Windows AppCompat/Amcache forensic artifacts.
- Anyone building a CI/triage pipeline that wants an automated Amcache anomaly gate (the CLI exits non-zero when findings exist).

## Why use this project

- **Real data only** — every result comes from real bytes real-parsed out of a real registry hive using `python-registry`. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box; every finding is independently verifiable with any other Amcache-aware tool (e.g. Eric Zimmerman's AmcacheParser).
- **Two interfaces, one engine** — the CLI (for terminals/triage pipelines) and the web app (for dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at scan time.

---

## Architecture

```
windows-amcache-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real python-registry-backed Amcache.hve parsing engine
│   ├── detection_rules/      # 6 documented detection rules (WAM-001..WAM-006)
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
├── tests/                     # pytest suite, including a real hand-built REGF hive (hive_builder.py)
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
| WAM-001 | Unsigned Binary in Suspicious Execution Location | High | Empty/missing `Publisher` for an entry whose path is in Temp, `Users\Public`, `ProgramData`, or Downloads |
| WAM-002 | Double-Extension / Icon Spoofing Pattern | Medium | Path shows a spoofing pattern like `.pdf.exe`, `.doc.scr`, `.jpg.exe` |
| WAM-003 | Future-Dated LinkDate (PE Timestamp Anomaly) | Low | Entry's `LinkDate` (PE compile timestamp) is later than the hive file's own filesystem mtime |
| WAM-004 | Duplicate Basename Across Multiple Paths | Medium | The same filename appears at 2+ distinct full paths across parsed entries |
| WAM-005 | Missing Hash — Integrity Verification Gap | Low | Entry has no `SHA1`/`FileId` value at all, so it can't be checked against hash-reputation sources |
| WAM-006 | Invalid or Corrupt Registry Hive | Low | Target file could not be opened as a valid REGF hive (reported as a parse-note, not a crash) |

---

## Setup & Run

### Requirements
- Python 3.9+
- `python-registry` (pure Python — no native/C dependency, works on any OS even though it parses Windows hives)

### Install

```bash
git clone <this-repository-url>
cd windows-amcache-analyzer
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
WAM_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1              # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/wam.db`. On the Dashboard, enter the real path to an `Amcache.hve` file you've already acquired (or a directory to search for `Amcache.hve`/`*.hve` files) and run a scan.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/Amcache.hve
python3 cli/main.py scan /path/to/triage_output --json
python3 cli/main.py scan /path/to/Amcache.hve --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a triage/CI gate) and `0` if the hive is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

The suite includes real rule-level unit tests plus genuine engine-level tests that hand-build a byte-accurate REGF registry hive on disk (`tests/hive_builder.py`, built with `struct` following the public REGF/HBIN/NK/VK cell format) and drive it through the real `python-registry`-backed parsing code in `app/security_engine` — nothing about hive opening or navigation is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows Amcache Analyzer check?**
It real-opens a Windows `Amcache.hve` registry hive with `python-registry`, real-walks the `InventoryApplicationFile` (and legacy `File`) keys, and flags unsigned binaries in suspicious locations, double-extension spoofing, future-dated `LinkDate` timestamps, duplicate basenames across paths, and entries missing a SHA-1 hash.

**Who should use it?**
DFIR analysts, SOC/incident-response teams, and security students studying Windows program-execution artifacts, working against hives/media they own or are explicitly authorized to investigate.

**Is it a replacement for a professional forensic examination?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify the hive file?**
No. It only opens the hive in binary read mode. It never writes to, repairs, or alters the file being analyzed.

**Where do I get an Amcache.hve file to analyze?**
From an offline forensic disk image, a volume shadow copy, or a live-triage acquisition tool — the hive is locked while Windows is running, so it must be acquired via imaging/triage rather than a direct live copy.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
