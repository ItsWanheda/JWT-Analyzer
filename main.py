"""JWT Analyzer - CLI entry point.

Usage examples:
    python main.py audit --token-file tokens/jwt.txt
    python main.py audit --token-file tokens/jwt.txt --wordlist wordlists/big.txt --output reports/run1
    python main.py verify-jwks --token-file tokens/jwt.txt --jwks-url https://auth.example.com/.well-known/jwks.json

Note: I kept the CLI groups flat on purpose. Adding nested groups felt overkill
for a tool with ~6 commands. Can always refactor later if it grows.
"""

import click
import json
import logging
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from utils.io import read_token_from_file, read_text_file
from utils.report import generate_html_report, redact_sensitive_data
from core.parser import parse_jwt
from core.security import (
    check_none_algorithm, brute_force_secret,
    check_algorithm_confusion, check_kid_injection
)
from core.diff import compare_payloads
from core.verification import verify_with_public_key
from core.forgery import forge_token
from core.jwks import verify_with_jwks
from core.sensitive_scanner import scan_payload_for_secrets
from core.async_security import brute_force_parallel
from core.logging_config import setup_logging
from config import Config

# Console setup - we degrade gracefully if rich isn't available
console = Console()
if not Config.is_rich_enabled():
    console = Console(force_terminal=False, no_color=True)

logger = logging.getLogger(__name__)

VERSION = "1.2.0"


@click.group()
@click.version_option(VERSION, prog_name='jwt-analyzer')
@click.option('--verbose', '-v', is_flag=True, help='Debug logging')
@click.option('--log-file', default=None, help='Write logs to this file')
def cli(verbose, log_file):
    """JWT Analyzer - security testing tool for JSON Web Tokens."""
    log_level = 'DEBUG' if verbose else Config.LOG_LEVEL
    setup_logging(log_file=log_file, json_format=bool(log_file))
    logger.debug("CLI initialized")


@cli.command()
@click.option('--token-file', required=True, type=click.Path(exists=True))
@click.option('--wordlist', default=None, help='Path to secrets wordlist')
@click.option('--output', '-o', default=None, help='Output report basename (no extension)')
@click.option('--format', 'fmt', default='json', type=click.Choice(['json', 'html', 'both']))
@click.option('--workers', default=8, help='Threads for brute force')
@click.option('--skip-bruteforce', is_flag=True, help='Skip the brute force step')
def audit(token_file, wordlist, output, fmt, workers, skip_bruteforce):
    """Full security audit: parse + checks + PII scan + brute force.

    This is the main command. Runs everything and produces a report.
    For more targeted checks, use the individual subcommands.
    """
    try:
        token = read_token_from_file(token_file)
        findings = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
            transient=True,
        ) as progress:

            # Parse
            t = progress.add_task("Parsing token...", total=None)
            parsed = parse_jwt(token)
            progress.update(t, completed=True)

            # Security checks
            t = progress.add_task("Security checks...", total=None)
            if check_none_algorithm(token):
                findings.append({
                    'severity': 'CRITICAL',
                    'type': 'none_algorithm',
                    'title': "'none' algorithm detected",
                    'description': 'Token uses alg=none - signature bypass possible (CVE-2015-9235)',
                    'remediation': 'Reject none algorithm server-side. Pin allowed algorithms explicitly.'
                })

            confusion = check_algorithm_confusion(token)
            if confusion.get('status') == 'observed':
                findings.append({
                    'severity': 'LOW',
                    'type': 'algorithm_policy_review',
                    'title': 'Review JWT algorithm policy',
                    'description': confusion.get('finding', 'Review the declared algorithm.')
                    + ' This token-only check does not confirm a vulnerability.',
                    'remediation': 'Pin an explicit algorithm allowlist and ensure key type matches the configured algorithm.'
                })

            kid_check = check_kid_injection(token)
            if kid_check.get('status') == 'suspicious_input':
                findings.append({
                    'severity': 'MEDIUM',
                    'type': 'kid_suspicious_input',
                    'title': 'Suspicious kid header value',
                    'description': f"Suspicious patterns: {', '.join(kid_check['vulnerability_types'])}. "
                    + 'This is an indicator, not proof of injection.',
                    'remediation': 'Treat kid only as an opaque key identifier; use a fixed trusted key set and never interpolate it into commands, paths, or SQL.'
                })

            # expiry
            exp = parsed.get('expiry_info') or {}
            if not exp.get('exp_timestamp'):
                findings.append({
                    'severity': 'MEDIUM',
                    'type': 'no_expiry',
                    'title': 'Token has no expiry',
                    'description': 'No exp claim - this token lives forever.',
                    'remediation': 'Add exp claim. Short-lived tokens (15-60 min) + refresh tokens.'
                })
            elif exp.get('is_expired'):
                logger.info(f"Token expired {abs(exp['remaining_seconds']):.0f}s ago")
            progress.update(t, completed=True)

            # PII scan
            t = progress.add_task("PII scan...", total=None)
            pii = scan_payload_for_secrets(parsed['payload'])
            if pii['has_critical'] or pii['total_findings'] > 0:
                findings.append({
                    'severity': 'CRITICAL' if pii['has_critical'] else 'MEDIUM',
                    'type': 'sensitive_data',
                    'title': f"{pii['total_findings']} sensitive items in payload",
                    'description': pii['recommendation'],
                    'remediation': 'JWTs are signed, not encrypted. Strip PII/secrets before signing.'
                })
            progress.update(t, completed=True)

            # Brute force - skip if user wants a quick scan
            if not skip_bruteforce:
                wl_path = wordlist or Config.get_wordlist_path()
                if Path(wl_path).exists():
                    t = progress.add_task(f"Brute force ({wl_path})...", total=None)
                    secrets = [s.strip() for s in open(wl_path) if s.strip() and not s.startswith('#')]
                    found = brute_force_parallel(token, secrets, workers=workers)
                    if found:
                        findings.append({
                            'severity': 'CRITICAL',
                            'type': 'weak_secret',
                            'title': 'Weak secret found',
                            'description': 'A matching signing secret was found. Secret value is intentionally omitted.',
                            'remediation': 'Rotate immediately. Use ≥256 bits of entropy (e.g., openssl rand -base64 32).'
                        })
                    progress.update(t, completed=True)
                else:
                    logger.warning(f"Wordlist not found, skipping brute force: {wl_path}")

        # Summary
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1

        console.print("\n[bold]Audit Summary[/bold]")
        console.print(f"  [red]Critical:[/red] {counts['CRITICAL']}")
        console.print(f"  [orange1]High:[/orange1]     {counts['HIGH']}")
        console.print(f"  [yellow]Medium:[/yellow]   {counts['MEDIUM']}")
        console.print(f"  [blue]Low:[/blue]      {counts['LOW']}")

        # Exit code for CI/CD - non-zero if any critical findings
        if counts['CRITICAL'] > 0:
            console.print("\n[bold red]❌ Critical findings - exiting with code 2[/bold red]")
            exit_code = 2
        elif counts['HIGH'] > 0:
            exit_code = 1
        else:
            exit_code = 0

        # Write reports
        if output:
            report = {
                'token_header': parsed['header'],
                'payload': parsed['payload'],
                'findings': findings,
                'pii_details': pii,
                'summary': counts,
            }
            if fmt in ('json', 'both'):
                Path(output).parent.mkdir(parents=True, exist_ok=True)
                with open(f"{output}.json", 'w') as fh:
                    json.dump(redact_sensitive_data(report), fh, indent=2, default=str)
                console.print(f"[dim]JSON report: {output}.json[/dim]")
            if fmt in ('html', 'both'):
                generate_html_report(report, f"{output}.html")
                console.print(f"[dim]HTML report: {output}.html[/dim]")

        sys.exit(exit_code)

    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        logger.exception("Audit failed")
        console.print(f"[red]Unexpected error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--token-file', required=True, type=click.Path(exists=True))
def analyze(token_file):
    """Decode and show token contents (no signature check)."""
    try:
        token = read_token_from_file(token_file)
        data = parse_jwt(token)

        console.print("[bold]Header:[/bold]")
        console.print(json.dumps(data['header'], indent=2))
        console.print("\n[bold]Payload:[/bold]")
        console.print(json.dumps(data['payload'], indent=2))

        exp = data.get('expiry_info')
        if exp:
            if exp['is_expired']:
                ago = abs(exp['remaining_seconds'])
                console.print(f"\n[red]⚠ Expired {ago:.0f}s ago ({exp['exp_datetime']})[/red]")
            else:
                console.print(f"\n[green]✓ Valid for {exp['remaining_seconds']:.0f}s (expires {exp['exp_datetime']})[/green]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--token-file', required=True, type=click.Path(exists=True))
@click.option('--wordlist', default=None)
@click.option('--workers', default=8, help='Parallel workers (1=sequential)')
def brute_force(token_file, wordlist, workers):
    """Try to crack the JWT signing secret using a wordlist."""
    wl_path = wordlist or Config.get_wordlist_path()
    try:
        token = read_token_from_file(token_file)
        if not Path(wl_path).exists():
            console.print(f"[red]Wordlist not found: {wl_path}[/red]")
            sys.exit(1)

        secrets = [s.strip() for s in open(wl_path) if s.strip() and not s.startswith('#')]
        console.print(f"[yellow]Trying {len(secrets)} secrets with {workers} workers...[/yellow]")

        found = brute_force_parallel(token, secrets, workers=workers)
        if found:
            console.print("[bold green]✓ Matching secret found (value redacted)[/bold green]")
        else:
            console.print("[red]✗ Not in wordlist[/red]")
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--token1', required=True, type=click.Path(exists=True))
@click.option('--token2', required=True, type=click.Path(exists=True))
def diff(token1, token2):
    """Compare two JWT payloads side-by-side.

    Useful when you have a 'before/after' token from a privilege escalation test.
    """
    try:
        d = compare_payloads(token1, token2)
        if not (d['added'] or d['removed'] or d['changed']):
            console.print("[green]Payloads are identical[/green]")
            return

        table = Table(title="Payload differences")
        table.add_column("Key", style="cyan")
        table.add_column("Old", style="white")
        table.add_column("New", style="white")

        for k, v in d['changed'].items():
            table.add_row(k, str(v['old']), str(v['new']))
        for k, v in d['added'].items():
            table.add_row(k, "[dim]-[/dim]", str(v))
        for k, v in d['removed'].items():
            table.add_row(k, str(v), "[dim]-[/dim]")

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command('verify-rsa')
@click.option('--token-file', required=True, type=click.Path(exists=True))
@click.option('--public-key', required=True, type=click.Path(exists=True))
@click.option('--output', default=None, help='Save verification result as JSON')
def verify_rsa(token_file, public_key, output):
    """Verify JWT signature with an RSA/ECDSA public key.

    Auto-detects PEM vs JWK format based on file content.
    """
    try:
        token = read_token_from_file(token_file)
        key_content = read_text_file(public_key)
        result = verify_with_public_key(token, key_content)

        if result['status'] == 'valid':
            console.print("[bold green]✓ Signature valid[/bold green]")
            console.print(json.dumps(result['payload'], indent=2))
        else:
            console.print(f"[red]✗ {result['error']}[/red]")
            sys.exit(1)

        if output:
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command('verify-jwks')
@click.option('--token-file', required=True, type=click.Path(exists=True))
@click.option('--jwks-url', required=True)
def verify_jwks_cmd(token_file, jwks_url):
    """Verify against a JWKS endpoint (e.g., https://auth.example.com/.well-known/jwks.json)."""
    try:
        token = read_token_from_file(token_file)
        result = verify_with_jwks(token, jwks_url)

        if result['status'] == 'valid':
            console.print(f"[green]✓ Valid (kid={result.get('kid')})[/green]")
            console.print(json.dumps(result['payload'], indent=2))
        else:
            console.print(f"[red]✗ {result['error']}[/red]")
            sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('--token-file', required=True, type=click.Path(exists=True))
@click.option('--payload-file', required=True, type=click.Path(exists=True))
@click.option('--secret', required=True)
@click.option('--algorithm', default='HS256')
@click.option('--output', default=None)
@click.option('--yes', is_flag=True, help='Skip confirmation prompt')
def forge(token_file, payload_file, secret, algorithm, output, yes):
    """Forge a JWT with a new payload.

    ⚠️  Only use on systems you're authorized to test. Unauthorized
    token forgery can violate computer fraud laws (CFAA, etc.).
    """
    if not yes:
        if not click.confirm("Are you authorized to forge tokens against the target?", default=False):
            console.print("[yellow]Aborted.[/yellow]")
            return

    try:
        token = read_token_from_file(token_file)
        new_payload = json.loads(read_text_file(payload_file))

        forged = forge_token(token, new_payload, secret, algorithm)
        console.print(f"[green]✓ Forged token:[/green]")
        console.print(forged)

        if output:
            with open(output, 'w') as f:
                f.write(forged)
            console.print(f"[dim]Saved to {output}[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    cli()