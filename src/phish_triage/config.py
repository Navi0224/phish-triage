"""Configuration loading.

All tunable values (rule weights, verdict thresholds, protected brands, keyword
lists) live in a JSON file instead of in the code. This keeps the scoring
transparent: an analyst can read the config and see exactly why an email scored
what it did, and tune it without touching Python.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

Config = dict[str, Any]


def load_default_config() -> Config:
    """Load the default config that ships inside the package."""
    text = resources.files("phish_triage").joinpath("default_config.json").read_text(encoding="utf-8")
    return json.loads(text)


def load_config(path: Path | None = None) -> Config:
    """Load the default config, then overlay a user config file if given.

    The user file only needs the keys it wants to change. Top-level keys are
    replaced, except ``weights`` and ``thresholds`` which are merged key by key
    so you can change a single weight without copying the whole table.
    """
    config = load_default_config()
    if path is None:
        return config

    user = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(user, dict):
        raise ValueError(f"Config file {path} must contain a JSON object")

    for key, value in user.items():
        if key in ("weights", "thresholds") and isinstance(value, dict):
            config[key] = {**config.get(key, {}), **value}
        else:
            config[key] = value
    return config
