"""
main.py – CLI entrypoint for the authorized vulnerability assessment toolkit.

Usage
-----
    python -m app.main <target_url> [options]

All network requests are blocked unless <target_url> is present in the
configured allowlist.  See README.md for setup instructions.
"""

from __future__ import annotations

import argparse
import sys
import logging
from pathlib import Path

# Ensure the project root is on sys.path when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import app.config as config
from app.scope import load_allowlist, check_approved_or_raise, TargetNotApprovedError
from app.recon import fetch_page
from app.findings import init_db, save_scan, save_finding, get_findings_for_scan
from app.report import render_report, save_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger(__name__)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║   Authorized Vulnerability Assessment Toolkit               ║
║   For local / lab use only.  Authorized targets only.       ║
╚══════════════════════════════════════════════════════════════╝
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-assess",
        description=(
            "Safe, authorized vulnerability assessment tool. "
            "Only targets listed in the allowlist are permitted."
        ),
    )
    parser.add_argument(
        "target",
        help="URL to scan (must be in the approved allowlist).",
    )
    parser.add_argument(
        "--allowlist",
        default=config.ALLOWLIST_PATH,
        help="Path to the allowlist file (default: from .env or data/allowlist.txt).",
    )
    parser.add_argument(
        "--db",
        default=config.DB_PATH,
        help="Path to the SQLite database (default: from .env or data/findings.db).",
    )
    parser.add_argument(
        "--reports-dir",
        default=config.REPORTS_DIR,
        help="Directory for Markdown reports.",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip saving the report to disk.",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    """
    Main execution logic.

    Returns
    -------
    int
        Exit code (0 = success, 1 = error / target not approved).
    """
    print(BANNER)

    # ------------------------------------------------------------------
    # 1. Load allowlist
    # ------------------------------------------------------------------
    allowlist = load_allowlist(args.allowlist)
    if not allowlist:
        print(
            f"[ERROR] The allowlist at '{args.allowlist}' is empty or missing.\n"
            "        Add at least one approved target domain before scanning.\n"
            "        Example: echo 'localhost' >> data/allowlist.txt",
            file=sys.stderr,
        )
        return 1

    # ------------------------------------------------------------------
    # 2. Scope check – hard stop if target is not approved
    # ------------------------------------------------------------------
    try:
        check_approved_or_raise(args.target, allowlist)
    except TargetNotApprovedError as exc:
        print(f"[BLOCKED] {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] Target approved: {args.target}")

    # ------------------------------------------------------------------
    # 3. Initialise database
    # ------------------------------------------------------------------
    init_db(args.db)

    # ------------------------------------------------------------------
    # 4. Recon
    # ------------------------------------------------------------------
    print(f"[INFO] Starting recon on {args.target} …")
    result = fetch_page(
        url=args.target,
        allowlist=allowlist,
        timeout=config.REQUEST_TIMEOUT,
        user_agent=config.USER_AGENT,
    )

    # ------------------------------------------------------------------
    # 5. Persist scan
    # ------------------------------------------------------------------
    scan_id = save_scan(
        db_path=args.db,
        url=result.url,
        status_code=result.status_code if result.status_code else None,
        error=result.error,
    )
    logger.info("Scan persisted with id=%s", scan_id)

    # ------------------------------------------------------------------
    # 6. Persist findings
    # ------------------------------------------------------------------
    if result.error:
        save_finding(
            db_path=args.db,
            scan_id=scan_id,
            finding_type="scan_error",
            description=result.error,
            severity="info",
        )
    else:
        # Security-relevant response headers check
        _check_security_headers(args.db, scan_id, result.url, result.headers)

        # Forms
        for form in result.forms:
            save_finding(
                db_path=args.db,
                scan_id=scan_id,
                finding_type="form",
                description=(
                    f"Form found – action: {form.action}, "
                    f"method: {form.method}, "
                    f"inputs: {len(form.inputs)}"
                ),
                severity="info",
                url=form.action,
            )

        # Links (summarised to keep the DB tidy)
        if result.links:
            save_finding(
                db_path=args.db,
                scan_id=scan_id,
                finding_type="link",
                description=f"Discovered {len(result.links)} links on the page.",
                severity="info",
                url=result.url,
            )

    # ------------------------------------------------------------------
    # 7. Load findings and print summary
    # ------------------------------------------------------------------
    findings = get_findings_for_scan(args.db, scan_id)
    print(f"\n[RESULTS] Scan #{scan_id} – {len(findings)} finding(s) recorded.\n")
    for f in findings:
        sev = f.get("severity", "info").upper()
        ftype = f.get("finding_type", "")
        desc = f.get("description", "")
        print(f"  [{sev}] {ftype}: {desc}")

    # ------------------------------------------------------------------
    # 8. Generate report
    # ------------------------------------------------------------------
    scan_record = {
        "url": result.url,
        "scanned_at": "",
        "status_code": result.status_code,
        "error": result.error,
    }
    report_text = render_report(scan_record, findings)

    if not args.no_report:
        report_path = save_report(report_text, args.reports_dir, scan_id)
        print(f"\n[REPORT] Saved to: {report_path}")
    else:
        print("\n--- Report Preview ---")
        print(report_text[:1000] + (" …" if len(report_text) > 1000 else ""))

    return 0


def _check_security_headers(
    db_path: str,
    scan_id: int,
    url: str,
    headers: dict[str, str],
) -> None:
    """Flag missing security-relevant HTTP response headers."""
    wanted = {
        "Content-Security-Policy": (
            "Missing Content-Security-Policy header.  "
            "This header helps prevent XSS and data injection attacks."
        ),
        "X-Content-Type-Options": (
            "Missing X-Content-Type-Options header.  "
            "Set to 'nosniff' to prevent MIME-type sniffing."
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options header.  "
            "Prevents clickjacking by controlling framing of pages."
        ),
        "Strict-Transport-Security": (
            "Missing Strict-Transport-Security header.  "
            "Enforces HTTPS connections to the server."
        ),
    }
    header_keys_lower = {k.lower(): k for k in headers}
    for header, description in wanted.items():
        if header.lower() not in header_keys_lower:
            save_finding(
                db_path=db_path,
                scan_id=scan_id,
                finding_type="header",
                description=description,
                severity="low",
                url=url,
            )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
