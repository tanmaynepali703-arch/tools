"""
recon.py – Fetch pages and extract links/forms from approved targets ONLY.

SAFETY GUARDRAIL
----------------
Every public function in this module calls ``check_approved_or_raise``
before making any network request.  The tool will refuse to run against
any target not explicitly listed in the allowlist.

Intended use: local / lab environments, your own infrastructure, or any
host for which you have explicit written authorization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from app.scope import check_approved_or_raise

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class FormInfo:
    """Minimal representation of an HTML form."""
    action: str
    method: str
    inputs: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ReconResult:
    """Results of a single-page reconnaissance pass."""
    url: str
    status_code: int
    links: list[str] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Core recon logic
# ---------------------------------------------------------------------------

def fetch_page(
    url: str,
    allowlist: Iterable[str],
    timeout: int = 10,
    user_agent: str = "AuthorizedLabScanner/1.0",
    session: requests.Session | None = None,
) -> ReconResult:
    """
    Fetch *url* and return a :class:`ReconResult`.

    Parameters
    ----------
    url:
        Target page URL.  Must be in the allowlist.
    allowlist:
        Approved entries from :func:`~app.scope.load_allowlist`.
    timeout:
        HTTP request timeout in seconds.
    user_agent:
        Value for the ``User-Agent`` request header.
    session:
        Optional :class:`requests.Session` to reuse (useful for testing).

    Returns
    -------
    ReconResult
    """
    # -----------------------------------------------------------------------
    # SCOPE CHECK – must pass before any network I/O
    # -----------------------------------------------------------------------
    check_approved_or_raise(url, allowlist)

    sess = session or requests.Session()
    headers = {"User-Agent": user_agent}

    result = ReconResult(url=url, status_code=0)

    try:
        response = sess.get(url, headers=headers, timeout=timeout)
        result.status_code = response.status_code
        result.headers = dict(response.headers)
        _parse_page(response.text, url, result)
        logger.info("Fetched %s – HTTP %s", url, response.status_code)
    except requests.RequestException as exc:
        result.error = str(exc)
        logger.error("Failed to fetch %s: %s", url, exc)

    return result


def _parse_page(html: str, base_url: str, result: ReconResult) -> None:
    """Populate *result* with links and forms extracted from *html*."""
    soup = BeautifulSoup(html, "html.parser")

    # Extract absolute links
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        absolute = urljoin(base_url, href)
        if _is_http(absolute):
            result.links.append(absolute)

    # Extract forms
    for form in soup.find_all("form"):
        action_raw = form.get("action", "") or ""
        action = urljoin(base_url, action_raw.strip())
        method = (form.get("method", "get") or "get").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append(
                {
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                }
            )
        result.forms.append(FormInfo(action=action, method=method, inputs=inputs))


def _is_http(url: str) -> bool:
    scheme = urlparse(url).scheme
    return scheme in ("http", "https")
