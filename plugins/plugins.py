"""Deprecated v1 directory plugin loader.

The v2 plugin system deliberately does not import arbitrary files from a
working directory. Use jwt_analyzer.plugins.PluginManager with trusted
installed entry points and explicit enablement instead.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class PluginManager:
    """Compatibility shell that refuses unsafe directory-based auto-loading."""

    def __init__(self, plugin_dir: str = "plugins") -> None:
        self.plugin_dir = plugin_dir
        self.plugins: dict[str, Any] = {}

    def load_plugins(self) -> None:
        """Refuse legacy auto-discovery rather than executing arbitrary local code."""
        raise RuntimeError(
            "Directory-based plugin loading is disabled in v2. "
            "Use jwt_analyzer.plugins.PluginManager and explicitly enable trusted packages."
        )

    def run_check(self, token: str) -> list[Any]:
        """The v1 raw-token plugin hook is intentionally unavailable in v2."""
        raise RuntimeError(
            "Raw-token v1 plugin execution is disabled in v2. "
            "Migrate to the versioned assessment plugin API."
        )
