"""Regression tests for the versioned, opt-in v2 plugin contract."""

import logging

import pytest

from jwt_analyzer.models import Assessment, Finding, Severity
from jwt_analyzer.plugins import (
    ENTRY_POINT_GROUP,
    PluginManager,
    PluginManifest,
)


class FakeEntryPoint:
    def __init__(self, name, factory):
        self.name = name
        self._factory = factory

    def load(self):
        return self._factory


class ExamplePlugin:
    manifest = PluginManifest(
        plugin_id="example_plugin",
        name="Example plugin",
        version="1.0.0",
        api_version="1",
        capabilities=("assessment.read",),
    )

    def run(self, assessment):
        if "sub" in assessment.claims:
            return (
                Finding(
                    id="plugin.example_plugin.subject_present",
                    title="Subject present",
                    description="Subject claim exists.",
                    severity=Severity.INFO,
                ),
            )
        return ()


def _assessment():
    return Assessment(header={"alg": "RS256"}, claims={"sub": "user-1"}, signature_present=True)


def test_discovery_reads_metadata_without_loading_plugin_code(monkeypatch):
    assert ENTRY_POINT_GROUP == "jwt_analyzer.plugins.v2"
    loaded = []
    point = FakeEntryPoint("example_plugin", lambda: loaded.append(True) or ExamplePlugin())
    monkeypatch.setattr("jwt_analyzer.plugins._available_entry_points", lambda: (point,))

    manager = PluginManager()
    assert manager.discover() == ("example_plugin",)
    assert loaded == []
    assert manager.run(_assessment()) == ()


def test_plugins_require_explicit_enablement_and_run_in_stable_order(monkeypatch):
    point = FakeEntryPoint("example_plugin", ExamplePlugin)
    monkeypatch.setattr("jwt_analyzer.plugins._available_entry_points", lambda: (point,))
    manager = PluginManager()

    assert manager.load_enabled([]) == ()
    assert manager.run(_assessment()) == ()
    assert manager.load_enabled(["example_plugin"]) == ("example_plugin",)
    results = manager.run(_assessment())

    assert len(results) == 1
    assert results[0].plugin_id == "example_plugin"
    assert [finding.id for finding in results[0].findings] == [
        "plugin.example_plugin.subject_present"
    ]


def test_plugin_failure_is_isolated_and_exception_text_is_not_logged(monkeypatch, caplog):
    secret = "private-claim-marker"

    class BrokenPlugin(ExamplePlugin):
        def run(self, assessment):
            raise RuntimeError(secret)

    point = FakeEntryPoint("example_plugin", BrokenPlugin)
    monkeypatch.setattr("jwt_analyzer.plugins._available_entry_points", lambda: (point,))
    manager = PluginManager()
    manager.load_enabled(["example_plugin"])

    with caplog.at_level(logging.WARNING, logger="jwt_analyzer.plugins"):
        result = manager.run(_assessment())

    assert result[0].error_code == "plugin_execution_failed"
    assert secret not in caplog.text
    assert "RuntimeError" in caplog.text


@pytest.mark.parametrize(
    "manifest",
    [
        {
            "plugin_id": "../evil",
            "name": "x",
            "version": "1.0.0",
            "api_version": "1",
            "capabilities": ("assessment.read",),
        },
        {
            "plugin_id": "example_plugin",
            "name": "x",
            "version": "latest",
            "api_version": "1",
            "capabilities": ("assessment.read",),
        },
        {
            "plugin_id": "example_plugin",
            "name": "x",
            "version": "1.0.0",
            "api_version": "99",
            "capabilities": ("assessment.read",),
        },
        {
            "plugin_id": "example_plugin",
            "name": "x",
            "version": "1.0.0",
            "api_version": "1",
            "capabilities": ("filesystem.write",),
        },
    ],
)
def test_manifest_rejects_invalid_or_unsupported_contracts(manifest):
    with pytest.raises(ValueError):
        PluginManifest(**manifest)


def test_manager_rejects_unknown_plugins_and_invalid_finding_namespace(monkeypatch):
    point = FakeEntryPoint("example_plugin", ExamplePlugin)
    monkeypatch.setattr("jwt_analyzer.plugins._available_entry_points", lambda: (point,))
    manager = PluginManager()

    with pytest.raises(ValueError):
        manager.load_enabled(["missing_plugin"])

    class InvalidPlugin(ExamplePlugin):
        def run(self, assessment):
            return (
                Finding(
                    id="foreign.finding",
                    title="Bad namespace",
                    description="Must be namespaced.",
                    severity=Severity.LOW,
                ),
            )

    monkeypatch.setattr(
        "jwt_analyzer.plugins._available_entry_points",
        lambda: (FakeEntryPoint("example_plugin", InvalidPlugin),),
    )
    manager.load_enabled(["example_plugin"])
    result = manager.run(_assessment())
    assert result[0].error_code == "plugin_execution_failed"
    assert result[0].findings == ()


def test_legacy_directory_loader_refuses_to_import_working_directory_plugins():
    from plugins.plugins import PluginManager as LegacyPluginManager

    manager = LegacyPluginManager()
    with pytest.raises(RuntimeError, match="Directory-based plugin loading is disabled"):
        manager.load_plugins()
    with pytest.raises(RuntimeError, match="Raw-token v1 plugin execution is disabled"):
        manager.run_check("raw.jwt.value")
