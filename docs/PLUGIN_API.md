# JWT Analyzer v2 Plugin API

**Contract version:** `1`  
**Entry-point group:** `jwt_analyzer.plugins.v2`

## Security model

Plugins are executable Python packages. They are **trusted in-process code**, not
sandboxed extensions. An enabled plugin can access files, environment variables,
the network, and other resources available to the JWT Analyzer process. Do not
install or enable plugins from untrusted publishers. Process isolation requires
a separate OS/container boundary and is not provided by this API.

Plugin discovery reads installed package metadata only. It does not import plugin
modules. Code is imported only when the operator explicitly calls
`PluginManager.load_enabled([...])`. The manager never scans the current working
directory, imports arbitrary files, or automatically enables discovered plugins.

Plugins receive a normalized `Assessment`, not the original compact JWT string.
Assessment claims and evidence may still contain sensitive values. Treat the
input as confidential and do not log or transmit it.

## Contract

A plugin package registers an entry point in the `jwt_analyzer.plugins.v2`
group. The entry-point name is its stable plugin ID, and its target is a
zero-argument factory returning an object with a `manifest` and `run(assessment)`.

```toml
[project.entry-points."jwt_analyzer.plugins.v2"]
claims_policy = "my_jwt_plugin:create_plugin"
```

```python
from jwt_analyzer.models import Assessment, Finding, Severity
from jwt_analyzer.plugins import PluginManifest

class ClaimsPolicyPlugin:
    manifest = PluginManifest(
        plugin_id="claims_policy",
        name="Claims policy example",
        version="1.0.0",
        api_version="1",
        capabilities=("assessment.read",),
    )

    def run(self, assessment: Assessment) -> tuple[Finding, ...]:
        if "tenant_id" in assessment.claims:
            return ()
        return (
            Finding(
                id="plugin.claims_policy.tenant_id_missing",
                title="Tenant claim is missing",
                description="The assessment does not contain tenant_id.",
                severity=Severity.MEDIUM,
                recommendation="Apply the tenant claim requirement in the issuer and verifier.",
                stage="policy",
            ),
        )

def create_plugin():
    return ClaimsPolicyPlugin()
```

Required manifest fields:

- `plugin_id`: lowercase stable identifier, 2–64 characters; must match entry-point name.
- `name`: human-readable name, up to 120 characters.
- `version`: semantic version.
- `api_version`: currently `1`.
- `capabilities`: currently only `assessment.read` is supported.

Findings must be normal `Finding` objects and IDs must begin with
`plugin.<plugin_id>.`. The manager validates the contract, isolates exceptions,
and returns plugin results in stable plugin-ID and finding-ID order. A plugin
must itself avoid time-dependent or random output if deterministic results are
required. The manager does not forcibly interrupt a hung plugin.

## Explicit enablement

```python
from jwt_analyzer.plugins import PluginManager

manager = PluginManager()
available = manager.discover()  # metadata only; does not import plugin code
enabled = manager.load_enabled(["claims_policy"])  # explicit trust decision
results = manager.run(assessment)
```

An empty enablement list loads nothing. Discovery is not consent to execute.
The current contract does not provide network, filesystem, token, configuration,
or persistence capabilities. The manifest capability declaration is a
compatibility and review signal, **not an OS-enforced sandbox**.

## Compatibility and support

The v2 plugin API is versioned independently from the CLI. Plugins must declare
the exact API version they implement. Unsupported versions and capabilities
fail closed. Breaking contract changes require a new API version and migration
documentation. No public registry or automatic package installer is included.
