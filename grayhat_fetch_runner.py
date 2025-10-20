"""Convenience entry point that preloads the Grayhat Warfare API key."""
from __future__ import annotations

import os
import sys
from typing import Sequence

import grayhat_fetch

DEFAULT_API_KEY = "4c4aebca1cbd5c543adbfb39c69d0e90"


def main(argv: Sequence[str] | None = None) -> int:
    """Ensure the Grayhat API key exists before delegating to grayhat_fetch."""
    os.environ.setdefault("GRAYHAT_API_KEY", DEFAULT_API_KEY)
    return grayhat_fetch.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
