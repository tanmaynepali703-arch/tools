"""
test_report.py – Unit tests for Markdown report generation.

No network calls are made.  Tests use synthetic scan/finding dicts.
"""

import pytest
from app.report import render_report, save_report


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def basic_scan():
    return {
        "url": "http://localhost/",
        "scanned_at": "2024-01-01T00:00:00+00:00",
        "status_code": 200,
        "error": None,
    }


@pytest.fixture
def sample_findings():
    return [
        {
            "finding_type": "header",
            "description": "Missing Content-Security-Policy header.",
            "severity": "low",
            "url": "http://localhost/",
        },
        {
            "finding_type": "form",
            "description": "Login form found – method: POST, inputs: 2",
            "severity": "info",
            "url": "http://localhost/login",
        },
        {
            "finding_type": "link",
            "description": "Discovered 5 links on the page.",
            "severity": "info",
            "url": "http://localhost/",
        },
    ]


# ---------------------------------------------------------------------------
# render_report tests
# ---------------------------------------------------------------------------

def test_render_report_contains_header(basic_scan, sample_findings):
    """The report must start with the expected title."""
    report = render_report(basic_scan, sample_findings)
    assert "# Vulnerability Assessment Report" in report


def test_render_report_contains_target_url(basic_scan, sample_findings):
    """The target URL must appear in the report."""
    report = render_report(basic_scan, sample_findings)
    assert "http://localhost/" in report


def test_render_report_contains_summary_table(basic_scan, sample_findings):
    """A summary table with severity counts must be present."""
    report = render_report(basic_scan, sample_findings)
    assert "## Summary" in report
    assert "| Severity | Count |" in report


def test_render_report_contains_findings_section(basic_scan, sample_findings):
    """The findings section must be present when findings exist."""
    report = render_report(basic_scan, sample_findings)
    assert "## Findings" in report


def test_render_report_no_findings(basic_scan):
    """When there are no findings the report should say so gracefully."""
    report = render_report(basic_scan, [])
    assert "No findings recorded" in report
    assert "## Findings" not in report


def test_render_report_error_shown(basic_scan):
    """A scan error must appear prominently in the report."""
    scan = {**basic_scan, "error": "Connection refused"}
    report = render_report(scan, [])
    assert "Connection refused" in report


def test_render_report_sorted_by_severity(basic_scan):
    """Higher-severity findings must appear before lower-severity ones."""
    findings = [
        {"finding_type": "link", "description": "Links found", "severity": "info", "url": ""},
        {"finding_type": "header", "description": "CSP missing", "severity": "high", "url": ""},
        {"finding_type": "form", "description": "Form found", "severity": "medium", "url": ""},
    ]
    report = render_report(basic_scan, findings)
    high_pos = report.find("High")
    medium_pos = report.find("Medium")
    info_pos = report.find("Info")
    assert high_pos < medium_pos < info_pos


def test_render_report_contains_disclaimer(basic_scan, sample_findings):
    """Every report must include the authorization disclaimer."""
    report = render_report(basic_scan, sample_findings)
    assert "## Disclaimer" in report
    assert "authorized" in report.lower()


def test_render_report_remediation_hints_present(basic_scan, sample_findings):
    """Remediation guidance must be present for each finding."""
    report = render_report(basic_scan, sample_findings)
    assert "Remediation" in report


def test_render_report_confidential_notice(basic_scan, sample_findings):
    """The CONFIDENTIAL notice must be in the report header."""
    report = render_report(basic_scan, sample_findings)
    assert "CONFIDENTIAL" in report


# ---------------------------------------------------------------------------
# save_report tests
# ---------------------------------------------------------------------------

def test_save_report_creates_file(tmp_path):
    """save_report must create a Markdown file in the specified directory."""
    path = save_report("# Test Report\n", str(tmp_path), scan_id=42)
    import os
    assert os.path.isfile(path)
    assert path.endswith(".md")
    with open(path, encoding="utf-8") as fh:
        assert "# Test Report" in fh.read()


def test_save_report_filename_contains_scan_id(tmp_path):
    """The report filename must include the scan id for easy identification."""
    path = save_report("content", str(tmp_path), scan_id=99)
    import os
    filename = os.path.basename(path)
    assert "scan99" in filename


def test_save_report_creates_directory_if_missing(tmp_path):
    """save_report must create the reports directory if it does not exist."""
    reports_dir = str(tmp_path / "nested" / "reports")
    path = save_report("# hello", reports_dir, scan_id=1)
    import os
    assert os.path.isfile(path)
