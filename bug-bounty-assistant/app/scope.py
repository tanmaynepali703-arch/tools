"""
scope.py – Parse and enforce the approved-target allowlist.

SAFETY GUARANTEE
----------------
No network request should ever be made without first calling
``is_approved(url)`` and verifying it returns True.  All other
modules in this project delegate that check to this module.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse
from typing import Iterable


# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------

def load_allowlist(path: str) -> list[str]:
    """
    Read the allowlist file and return a list of approved entries.

    Each non-blank line that does not start with ``#`` is treated as an
    approved domain or URL prefix.  Entries are stripped of whitespace and
    stored in lowercase for case-insensitive comparison.

    Parameters
    ----------
    path:
        Filesystem path to the allowlist text file.

    Returns
    -------
    list[str]
        Approved entries (may be empty if the file is missing or blank).
    """
    p = Path(path)
    if not p.exists():
        return []

    entries: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            entries.append(stripped.lower())
    return entries


def _extract_host(url: str) -> str:
    """Return the hostname (or IP) from *url*, lower-cased."""
    parsed = urlparse(url)
    # If there is no scheme the netloc will be empty; treat the whole string
    # as the host in that case (e.g. "localhost", "127.0.0.1").
    host = parsed.netloc or parsed.path
    # Strip port
    host = host.split(":")[0]
    return host.lower().strip()


def is_approved(url: str, allowlist: Iterable[str]) -> bool:
    """
    Return True only if *url* matches an entry in *allowlist*.

    Matching rules (applied in order):
    1. Exact full-URL prefix match (e.g. allowlist entry
       ``http://lab.internal/api`` approves any URL that starts with it).
    2. Hostname / domain suffix match – an entry such as ``example.lab``
       approves ``http://example.lab``, ``https://sub.example.lab/path``.

    Parameters
    ----------
    url:
        The candidate URL to check.
    allowlist:
        Iterable of approved entries as returned by :func:`load_allowlist`.

    Returns
    -------
    bool
    """
    url_lower = url.lower().strip()
    host = _extract_host(url_lower)

    for entry in allowlist:
        # 1. Prefix match (covers full URL entries in the allowlist)
        if url_lower.startswith(entry):
            return True
        # 2. Hostname / domain suffix match
        if host == entry or host.endswith("." + entry):
            return True

    return False


def check_approved_or_raise(url: str, allowlist: Iterable[str]) -> None:
    """
    Raise :class:`TargetNotApprovedError` if *url* is not in *allowlist*.

    This is the primary guard used by other modules before any network I/O.
    """
    if not is_approved(url, allowlist):
        raise TargetNotApprovedError(url)


class TargetNotApprovedError(Exception):
    """Raised when a requested target URL is not in the approved allowlist."""

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(
            f"Target '{url}' is NOT in the approved allowlist.\n"
            "Add it to your allowlist file only if you have explicit written "
            "authorization to assess this target.  Do not scan systems you do "
            "not own or have permission to test."
        )
