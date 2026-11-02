"""Allow ``python -m phish_triage analyze file.eml``."""

from .cli import main

raise SystemExit(main())
