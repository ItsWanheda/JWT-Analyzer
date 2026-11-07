"""Validated configuration loading for the public v2 API.

Precedence is defaults < config file < environment variables. Configuration
files are parsed with safe YAML loading and bounded before decoding.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .exceptions import ConfigurationError
from .policy import AssessmentPolicy, get_policy_profile

_MAX_CONFIG_BYTES = 1_048_576
_ALLOWED_ROOT_KEYS = frozenset({"policy", "policy_options", "max_batch_items", "wordlist_path", "fail_on_severity"})
_ALLOWED_POLICY_KEYS = frozenset(
    {
        "accepted_algorithms",
        "required_claims",
        "time_claims",
        "issuer",
        "audience",
        "require_issuer",
        "require_audience",
        "leeway_seconds",
        "max_future_iat_seconds",
    }
)


@dataclass(frozen=True)
class AnalyzerConfig:
    """Effective, validated runtime configuration."""

    policy: AssessmentPolicy
    max_batch_items: int = 10_000
    wordlist_path: Path | None = None
    fail_on_severity: str = "high"


def _positive_integer(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigurationError(f"{name} must be a positive integer")
    return int(value)


def _read_config_file(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError("configuration file could not be read") from exc
    if len(raw) > _MAX_CONFIG_BYTES:
        raise ConfigurationError("configuration file exceeds the 1 MiB limit")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("configuration file must be UTF-8") from exc

    try:
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise ConfigurationError("configuration file contains invalid JSON or YAML") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigurationError("configuration root must be an object")
    unknown = set(data).difference(_ALLOWED_ROOT_KEYS)
    if unknown:
        raise ConfigurationError("unknown configuration key(s): " + ", ".join(sorted(unknown)))
    return data


def load_config(
    path: str | os.PathLike[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> AnalyzerConfig:
    """Load defaults, then file values, then explicit environment overrides.

    Supported environment variables:
      JWT_ANALYZER_POLICY
      JWT_ANALYZER_MAX_BATCH_ITEMS
      JWT_ANALYZER_WORDLIST_PATH
      JWT_ANALYZER_FAIL_ON_SEVERITY
    """
    env = os.environ if environ is None else environ
    values: dict[str, Any] = {
        "policy": "baseline",
        "policy_options": {},
        "max_batch_items": 10_000,
        "wordlist_path": None,
        "fail_on_severity": "high",
    }
    if path is not None:
        values.update(_read_config_file(Path(path)))

    if "JWT_ANALYZER_POLICY" in env:
        values["policy"] = env["JWT_ANALYZER_POLICY"]
    if "JWT_ANALYZER_MAX_BATCH_ITEMS" in env:
        try:
            values["max_batch_items"] = int(env["JWT_ANALYZER_MAX_BATCH_ITEMS"])
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("JWT_ANALYZER_MAX_BATCH_ITEMS must be an integer") from exc
    if "JWT_ANALYZER_WORDLIST_PATH" in env:
        values["wordlist_path"] = env["JWT_ANALYZER_WORDLIST_PATH"]
    if "JWT_ANALYZER_FAIL_ON_SEVERITY" in env:
        values["fail_on_severity"] = env["JWT_ANALYZER_FAIL_ON_SEVERITY"]

    profile = values["policy"]
    if not isinstance(profile, str):
        raise ConfigurationError("policy must be a profile name")
    options = values["policy_options"]
    if not isinstance(options, dict):
        raise ConfigurationError("policy_options must be an object")
    unknown_policy = set(options).difference(_ALLOWED_POLICY_KEYS)
    if unknown_policy:
        raise ConfigurationError("unknown policy option(s): " + ", ".join(sorted(unknown_policy)))
    try:
        policy = get_policy_profile(profile, **options)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("policy configuration is invalid") from exc

    max_batch_items = _positive_integer("max_batch_items", values["max_batch_items"])
    wordlist = values["wordlist_path"]
    if wordlist is not None and (not isinstance(wordlist, str) or not wordlist.strip()):
        raise ConfigurationError("wordlist_path must be a non-empty path string or null")

    fail_on_severity = values["fail_on_severity"]
    allowed_thresholds = {"none", "info", "low", "medium", "high", "critical"}
    if not isinstance(fail_on_severity, str) or fail_on_severity not in allowed_thresholds:
        raise ConfigurationError(
            "fail_on_severity must be none, info, low, medium, high, or critical"
        )

    return AnalyzerConfig(
        policy=policy,
        max_batch_items=max_batch_items,
        wordlist_path=Path(wordlist).expanduser() if wordlist else None,
        fail_on_severity=fail_on_severity,
    )
