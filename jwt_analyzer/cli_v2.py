"""Versioned, script-friendly CLI surface for JWT Analyzer v2."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, TextIO

import click

from . import __version__, evaluate_policy, inspect_token, iter_assessments
from .config import load_config
from .exceptions import ConfigurationError
from .models import Assessment

_MAX_TOKEN_LINE_BYTES = 1_048_576


def _write_json(value: Any, stream: TextIO) -> None:
    stream.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")


def _error(code: str, message: str, *, stream: TextIO = sys.stderr) -> None:
    _write_json({"schema_version": "1", "status": "error", "error": {
        "code": code,
        "message": message,
    }}, stream)


def _load_token(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise click.ClickException("token file could not be read") from exc
    if len(raw) > _MAX_TOKEN_LINE_BYTES:
        raise click.ClickException("token file exceeds the 1 MiB token limit")
    try:
        return raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise click.ClickException("token file must contain UTF-8 text") from exc


def _assessment_payload(assessment: Assessment) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "status": "ok",
        "assessment": assessment.to_dict(),
    }


@click.group()
@click.version_option(__version__, prog_name="jwt-analyzer-v2")
def cli() -> None:
    """Stable v2 commands with machine-readable stdout and errors on stderr."""


@cli.command("inspect")
@click.option(
    "--token-file",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
@click.option("--config", "config_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--evaluate-policy", is_flag=True, help="Evaluate the configured claim policy (advisory until verified).")
def inspect_command(token_file: Path, config_path: Path | None, evaluate_claim_policy: bool) -> None:
    """Structurally inspect one token; does not verify its signature."""
    try:
        config = load_config(config_path)
        token = _load_token(token_file)
        assessment = inspect_token(token)
        if evaluate_claim_policy:
            assessment = evaluate_policy(assessment, config.policy)
        _write_json(_assessment_payload(assessment), sys.stdout)
    except ConfigurationError:
        _error("invalid_configuration", "configuration is invalid")
        raise click.exceptions.Exit(2)
    except click.ClickException as exc:
        _error("input_error", exc.format_message())
        raise click.exceptions.Exit(2)
    except ValueError:
        _error("invalid_token", "token is malformed or violates parser limits")
        raise click.exceptions.Exit(1)


def _token_lines(stream: TextIO):
    for line in stream:
        if len(line.encode("utf-8")) > _MAX_TOKEN_LINE_BYTES:
            yield None
        else:
            token = line.strip()
            if token:
                yield token


@cli.command("batch")
@click.option(
    "--input-file",
    required=True,
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    help="UTF-8 file containing one compact JWT per line.",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option("--evaluate-policy", is_flag=True, help="Evaluate the configured claim policy (advisory until verified).")
def batch_command(input_file: Path, config_path: Path | None, evaluate_claim_policy: bool) -> None:
    """Stream newline-delimited tokens and emit one JSON result per item."""
    try:
        config = load_config(config_path)
        with input_file.open("r", encoding="utf-8-sig") as stream:
            results = iter_assessments(_token_lines(stream), max_items=config.max_batch_items)
            succeeded = 0
            failed = 0
            processed = 0
            for result in results:
                if evaluate_claim_policy and result.assessment is not None:
                    result = replace(result, assessment=evaluate_policy(result.assessment, config.policy))
                processed += 1
                if result.succeeded:
                    succeeded += 1
                else:
                    failed += 1
                _write_json({"schema_version": "1", **result.to_dict()}, sys.stdout)
        _write_json(
            {
                "schema_version": "1",
                "status": "complete" if failed == 0 else "partial",
                "summary": {
                    "processed": processed,
                    "succeeded": succeeded,
                    "failed": failed,
                },
            },
            sys.stdout,
        )
        if failed:
            raise click.exceptions.Exit(1)
    except ConfigurationError:
        _error("invalid_configuration", "configuration is invalid")
        raise click.exceptions.Exit(2)
    except (OSError, UnicodeError):
        _error("input_error", "batch input file could not be read as UTF-8")
        raise click.exceptions.Exit(2)
    except ValueError:
        _error("batch_limit_exceeded", "batch exceeds the configured item limit")
        raise click.exceptions.Exit(2)


if __name__ == "__main__":
    cli()
