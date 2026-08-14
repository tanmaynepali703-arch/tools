# Authorized Vulnerability Assessment Toolkit

> **For local / lab use only. Authorized targets only.**
>
> This tool is designed for defensive security assessment on systems you own
> or have explicit written permission to test. Do not use it against any
> target without proper authorization.

---

## Overview

A lightweight, Python-based reconnaissance and reporting toolkit that:

- Enforces a **URL allowlist** before making any network request.
- Fetches pages and extracts **links, forms, and security headers**.
- Persists scans and findings in a local **SQLite database**.
- Generates remediation-focused **Markdown reports**.
- Provides a clean **CLI entrypoint** with clear safety guardrails.

---

## Project Structure

```
bug-bounty-assistant/
├── app/
│   ├── config.py      # Load .env and allowlist config
│   ├── scope.py       # Allowlist parsing and URL enforcement
│   ├── recon.py       # Page fetch and link/form extraction
│   ├── findings.py    # SQLite persistence
│   ├── report.py      # Markdown report generation
│   └── main.py        # CLI entrypoint
├── tests/
│   ├── test_scope.py  # Unit tests – allowlist enforcement
│   └── test_report.py # Unit tests – report rendering
├── data/
│   ├── allowlist.txt  # Approved targets (edit before use)
│   └── reports/       # Generated Markdown reports (auto-created)
├── .env.example       # Configuration template
├── requirements.txt
└── README.md
```

---

## Setup

### Requirements

- Python 3.9+
- pip

### Installation

```bash
cd bug-bounty-assistant

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and edit the environment config
cp .env.example .env
```

---

## Configuration

### 1. Allowlist (`data/allowlist.txt`)

Edit this file to list the domains or IP addresses you are **authorized** to
scan. Each line is one entry:

```
# Approved lab targets
localhost
127.0.0.1
192.168.56.101
lab.mycompany.internal
```

> ⚠️ The tool **will refuse** to scan any target not in this file.

### 2. Environment variables (`.env`)

| Variable          | Default                     | Description                         |
|-------------------|-----------------------------|-------------------------------------|
| `ALLOWLIST_PATH`  | `data/allowlist.txt`        | Path to the allowlist file          |
| `DB_PATH`         | `data/findings.db`          | SQLite database path                |
| `REPORTS_DIR`     | `data/reports`              | Directory for Markdown reports      |
| `REQUEST_TIMEOUT` | `10`                        | HTTP timeout in seconds             |
| `USER_AGENT`      | `AuthorizedLabScanner/1.0`  | User-Agent header for requests      |

---

## Usage

### Run a scan

```bash
python -m app.main http://localhost/
```

The tool will:
1. Verify the target is in the allowlist – **refuses** if not.
2. Fetch the page and extract links, forms, and headers.
3. Persist the scan and findings to SQLite.
4. Generate a Markdown report in `data/reports/`.

### Options

```
usage: vuln-assess [-h] [--allowlist ALLOWLIST] [--db DB]
                   [--reports-dir REPORTS_DIR] [--no-report]
                   target

positional arguments:
  target                URL to scan (must be in the approved allowlist).

options:
  -h, --help            show this help message and exit
  --allowlist ALLOWLIST Path to the allowlist file.
  --db DB               Path to the SQLite database.
  --reports-dir REPORTS_DIR
                        Directory for Markdown reports.
  --no-report           Skip saving the report to disk.
```

### Example

```bash
# Scan a local Flask app running on port 5000
python -m app.main http://localhost:5000/ --no-report
```

---

## Running Tests

```bash
pytest tests/ -v
```

Tests cover:
- Allowlist loading (missing file, comments, blank lines, case normalization).
- URL approval (exact hostname, IP, subdomain, URL prefix, evil-twin rejection).
- `TargetNotApprovedError` message clarity.
- Report rendering (structure, sorting by severity, disclaimer presence).
- Report file I/O (file creation, filename convention, directory auto-creation).

---

## Safety Limitations

| What this tool does NOT do                              |
|---------------------------------------------------------|
| Automated exploitation or payload injection             |
| Credential attacks or brute-force                       |
| Stealth / evasion techniques                            |
| Submission to bug bounty platforms                      |
| Scanning targets not explicitly listed in the allowlist |
| Any action against production systems by default        |

This toolkit is intentionally limited to **passive reconnaissance** on
approved targets in a local or lab environment. It is designed to help
developers identify and fix security issues on their own systems.

---

## Legal Notice

Unauthorized scanning of computer systems is illegal in most jurisdictions.
Only use this tool against systems you own or for which you have **explicit
written authorization**. The authors assume no responsibility for misuse.
