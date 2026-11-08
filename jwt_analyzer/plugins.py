"""Opt-in, versioned entry-point plugin contract for JWT Analyzer v2.

Plugins are trusted in-process Python code, not sandboxed extensions. Discovery
reads package metadata only; importing plugin code requires explicit enablement.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Protocol, Sequence, cast

from .models import Assessment, Finding

PLUGIN_API_VERSION = "1"
ENTRY_POINT_GROUP = "jwt_analyzer.plugins.v2"
_ALLOWED_CAPABILITIES = frozenset({"assessment.read"})
_PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")
_LOGGER = logging.getLogger("jwt_analyzer.plugins")


@dataclass(frozen=True)
class PluginManifest:
    """Metadata declared by a plugin before it is enabled."""

    plugin_id: str
    name: str
    version: str
    api_version: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.plugin_id, str) or not _PLUGIN_ID.fullmatch(self.plugin_id):
            raise ValueError("plugin_id must be a lowercase identifier of 2–64 characters")
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 120:
            raise ValueError("plugin name must be a non-empty string of at most 120 characters")
        if not isinstance(self.version, str) or not _SEMVER.fullmatch(self.version):
            raise ValueError("plugin version must use semantic version syntax")
        if self.api_version != PLUGIN_API_VERSION:
            raise ValueError("plugin API version is not supported")
        if not isinstance(self.capabilities, tuple) or not self.capabilities:
            raise ValueError("plugin capabilities must be a non-empty tuple")
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("plugin capabilities must not contain duplicates")
        unsupported = set(self.capabilities).difference(_ALLOWED_CAPABILITIES)
        if unsupported:
            raise ValueError("plugin requested unsupported capabilities")


class AssessmentPlugin(Protocol):
    """Required plugin shape; plugins receive assessments, never raw JWT strings."""

    manifest: PluginManifest

    def run(self, assessment: Assessment) -> Sequence[Finding]:
        """Return normalized findings derived from one assessment."""


@dataclass(frozen=True)
class PluginRun:
    """Result of one isolated plugin invocation."""

    plugin_id: str
    findings: tuple[Finding, ...]
    error_code: str | None = None


def _available_entry_points() -> tuple[EntryPoint, ...]:
    discovered: Any = entry_points()
    if hasattr(discovered, "select"):
        selected = discovered.select(group=ENTRY_POINT_GROUP)
    else:  # Python 3.9 importlib.metadata compatibility
        selected = discovered.get(ENTRY_POINT_GROUP, ())
    return tuple(sorted(selected, key=lambda item: item.name))


class PluginManager:
    """Discover metadata safely and load only explicitly enabled trusted plugins.

    This manager does not provide an OS sandbox. Enabled plugins execute inside
    the current Python process with the process user's permissions.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, AssessmentPlugin] = {}

    def discover(self) -> tuple[str, ...]:
        """Return sorted plugin entry-point names without importing their code."""
        names = [point.name for point in _available_entry_points()]
        if len(names) != len(set(names)):
            raise ValueError("duplicate plugin entry-point names were discovered")
        return tuple(names)

    def load_enabled(self, plugin_ids: Sequence[str]) -> tuple[str, ...]:
        """Load only named entry points after the caller explicitly opts in."""
        if isinstance(plugin_ids, (str, bytes)):
            raise TypeError("plugin_ids must be a sequence of plugin identifiers")
        requested = tuple(plugin_ids)
        if len(requested) != len(set(requested)):
            raise ValueError("plugin_ids must not contain duplicates")
        if any(not isinstance(item, str) or not _PLUGIN_ID.fullmatch(item) for item in requested):
            raise ValueError("plugin_ids contains an invalid identifier")

        available = {point.name: point for point in _available_entry_points()}
        missing = set(requested).difference(available)
        if missing:
            raise ValueError("requested plugin entry point was not found")

        loaded: dict[str, AssessmentPlugin] = {}
        for plugin_id in sorted(requested):
            point = available[plugin_id]
            candidate = point.load()()
            manifest = getattr(candidate, "manifest", None)
            runner = getattr(candidate, "run", None)
            if not isinstance(manifest, PluginManifest) or not callable(runner):
                raise ValueError("plugin does not implement the v2 plugin contract")
            if manifest.plugin_id != plugin_id:
                raise ValueError("plugin manifest ID does not match its entry point")
            loaded[plugin_id] = cast(AssessmentPlugin, candidate)

        self._plugins = loaded
        return tuple(self._plugins)

    def run(self, assessment: Assessment) -> tuple[PluginRun, ...]:
        """Run enabled plugins in stable ID order and isolate plugin exceptions."""
        if not isinstance(assessment, Assessment):
            raise TypeError("assessment must be an Assessment")
        results: list[PluginRun] = []
        for plugin_id in sorted(self._plugins):
            plugin = self._plugins[plugin_id]
            try:
                findings = tuple(plugin.run(assessment))
                if any(not isinstance(item, Finding) for item in findings):
                    raise TypeError("plugin results must contain Finding objects")
                if any(not item.id.startswith(f"plugin.{plugin_id}.") for item in findings):
                    raise ValueError("plugin finding IDs must use the plugin namespace")
                if len({item.id for item in findings}) != len(findings):
                    raise ValueError("plugin returned duplicate finding IDs")
                results.append(
                    PluginRun(
                        plugin_id=plugin_id,
                        findings=tuple(sorted(findings, key=lambda item: item.id)),
                    )
                )
            except Exception as exc:  # isolate failures without logging claims or exception text
                _LOGGER.warning(
                    "plugin execution failed: plugin_id=%s exception_type=%s",
                    plugin_id,
                    type(exc).__name__,
                )
                results.append(
                    PluginRun(
                        plugin_id=plugin_id,
                        findings=(),
                        error_code="plugin_execution_failed",
                    )
                )
        return tuple(results)
