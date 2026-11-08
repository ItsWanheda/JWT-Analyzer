# Legacy plugin directory — disabled in v2

The v1 directory-based plugin loader is disabled in the v2 development branch.
It previously imported arbitrary `*_plugin.py` files from a local directory
and passed raw JWT strings to plugin code. That behavior is not part of the v2
security model.

**Do not add plugin files to this directory.** The v2 plugin system discovers
installed package entry points without importing them and loads only plugins
explicitly enabled by the operator.

See [the v2 Plugin API and trust model](../docs/PLUGIN_API.md) for:

- The versioned `jwt_analyzer.plugins.v2` entry-point group.
- The required `PluginManifest` and normalized `Assessment` input contract.
- Explicit opt-in loading and namespaced findings.
- The important limitation that enabled plugins are trusted in-process Python
  code, not sandboxed extensions.

The legacy `plugins.plugins.PluginManager` compatibility shell raises a clear
error rather than loading files from the working directory or exposing raw JWT
strings to unversioned plugin code.
