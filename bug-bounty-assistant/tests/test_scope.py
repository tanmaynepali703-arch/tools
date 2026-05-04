"""
test_scope.py – Unit tests for scope enforcement (allowlist checking).

These tests intentionally use no real network calls.
"""

import pytest
from app.scope import (
    load_allowlist,
    is_approved,
    check_approved_or_raise,
    TargetNotApprovedError,
)


# ---------------------------------------------------------------------------
# load_allowlist tests
# ---------------------------------------------------------------------------

def test_load_allowlist_missing_file(tmp_path):
    """A missing allowlist file returns an empty list."""
    result = load_allowlist(str(tmp_path / "nonexistent.txt"))
    assert result == []


def test_load_allowlist_empty_file(tmp_path):
    """An empty allowlist file returns an empty list."""
    f = tmp_path / "allowlist.txt"
    f.write_text("")
    assert load_allowlist(str(f)) == []


def test_load_allowlist_comment_lines_ignored(tmp_path):
    """Lines starting with # are treated as comments and excluded."""
    f = tmp_path / "allowlist.txt"
    f.write_text("# this is a comment\nlocalhost\n# another comment\n")
    result = load_allowlist(str(f))
    assert result == ["localhost"]


def test_load_allowlist_blank_lines_ignored(tmp_path):
    """Blank lines between entries are ignored."""
    f = tmp_path / "allowlist.txt"
    f.write_text("\n\nlocalhost\n\n127.0.0.1\n\n")
    result = load_allowlist(str(f))
    assert result == ["localhost", "127.0.0.1"]


def test_load_allowlist_lowercases_entries(tmp_path):
    """Entries are normalised to lowercase."""
    f = tmp_path / "allowlist.txt"
    f.write_text("LocalHost\nLAB.INTERNAL\n")
    result = load_allowlist(str(f))
    assert result == ["localhost", "lab.internal"]


# ---------------------------------------------------------------------------
# is_approved tests – approved cases
# ---------------------------------------------------------------------------

def test_is_approved_exact_hostname():
    assert is_approved("http://localhost/", ["localhost"]) is True


def test_is_approved_exact_ip():
    assert is_approved("http://127.0.0.1/path", ["127.0.0.1"]) is True


def test_is_approved_subdomain():
    """Sub-domains of an approved domain are also approved."""
    assert is_approved("http://sub.lab.internal/page", ["lab.internal"]) is True


def test_is_approved_full_url_prefix():
    """An allowlist entry that is a URL prefix matches URLs starting with it."""
    allowlist = ["http://lab.internal/api"]
    assert is_approved("http://lab.internal/api/v1/users", allowlist) is True


def test_is_approved_case_insensitive():
    assert is_approved("http://LOCALHOST/", ["localhost"]) is True


def test_is_approved_with_port():
    """Port number should not break host matching."""
    assert is_approved("http://localhost:8080/admin", ["localhost"]) is True


# ---------------------------------------------------------------------------
# is_approved tests – blocked cases
# ---------------------------------------------------------------------------

def test_is_not_approved_external_domain():
    assert is_approved("http://example.com/", ["localhost"]) is False


def test_is_not_approved_empty_allowlist():
    assert is_approved("http://localhost/", []) is False


def test_is_not_approved_partial_domain_not_suffix():
    """Partial match that is not a true suffix must not grant approval."""
    # "evilocalhost.com" should NOT match allowlist entry "localhost"
    assert is_approved("http://evilocalhost.com/", ["localhost"]) is False


def test_is_not_approved_different_tld():
    assert is_approved("http://lab.evil/", ["lab.internal"]) is False


# ---------------------------------------------------------------------------
# check_approved_or_raise tests
# ---------------------------------------------------------------------------

def test_check_approved_or_raise_passes_for_allowed():
    """Should not raise for an approved target."""
    check_approved_or_raise("http://localhost/", ["localhost"])  # no exception


def test_check_approved_or_raise_raises_for_blocked():
    """Should raise TargetNotApprovedError for a non-approved target."""
    with pytest.raises(TargetNotApprovedError) as exc_info:
        check_approved_or_raise("http://example.com/", ["localhost"])
    assert "example.com" in str(exc_info.value)
    assert exc_info.value.url == "http://example.com/"


def test_target_not_approved_error_message_is_instructive():
    """The error message must explain the problem and not just crash."""
    with pytest.raises(TargetNotApprovedError) as exc_info:
        check_approved_or_raise("http://evil.example/", ["localhost"])
    msg = str(exc_info.value)
    assert "NOT in the approved allowlist" in msg
    assert "authorization" in msg.lower()
