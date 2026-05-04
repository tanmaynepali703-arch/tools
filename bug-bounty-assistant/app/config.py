"""
config.py – Load environment variables and allowlist configuration.

All network activity is gated on the allowlist loaded here.
Never add real third-party targets to the allowlist without explicit
authorization.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (one level above app/)
_env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=_env_path, override=False)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DB_PATH: str = os.getenv(
    "DB_PATH",
    str(Path(__file__).parent.parent / "data" / "findings.db"),
)

# ---------------------------------------------------------------------------
# Reports output directory
# ---------------------------------------------------------------------------
REPORTS_DIR: str = os.getenv(
    "REPORTS_DIR",
    str(Path(__file__).parent.parent / "data" / "reports"),
)

# ---------------------------------------------------------------------------
# Approved target allowlist
#
# ALLOWLIST_PATH points to a plain-text file where each non-blank,
# non-comment line is an approved domain or URL prefix.
# Example entries (one per line):
#   localhost
#   127.0.0.1
#   http://lab.internal
# ---------------------------------------------------------------------------
ALLOWLIST_PATH: str = os.getenv(
    "ALLOWLIST_PATH",
    str(Path(__file__).parent.parent / "data" / "allowlist.txt"),
)

# ---------------------------------------------------------------------------
# HTTP request settings
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
USER_AGENT: str = os.getenv(
    "USER_AGENT",
    "AuthorizedLabScanner/1.0 (local assessment only)",
)
