"""Bounded, streaming batch assessment helpers for the public v2 API."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .api import inspect_token
from .exceptions import BatchLimitError
from .models import Assessment


@dataclass(frozen=True)
class BatchResult:
    """Outcome for one input item; failed items never abort the surrounding batch."""

    index: int
    assessment: Assessment | None = None
    error_code: str | None = None
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.assessment is not None

    def to_dict(self) -> dict[str, Any]:
        """Serialize one outcome without retaining the original compact token."""
        result: dict[str, Any] = {
            "index": self.index,
            "status": "succeeded" if self.succeeded else "failed",
        }
        if self.assessment is not None:
            result["assessment"] = self.assessment.to_dict()
        else:
            result["error"] = {
                "code": self.error_code or "assessment_failed",
                "message": self.error or "The item could not be assessed.",
            }
        return result


def iter_assessments(
    tokens: Iterable[str],
    *,
    max_items: int = 10_000,
) -> Iterator[BatchResult]:
    """Yield per-token results while consuming the input lazily.

    The iterator never materializes the input collection. `max_items` is a
    hard item-count bound; exceeding it raises ValueError before processing
    the first item beyond the limit. A malformed token produces a failed
    result and does not prevent later tokens from being assessed.
    """
    if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
        raise ValueError("max_items must be a positive integer")

    for index, token in enumerate(tokens):
        if index >= max_items:
            raise BatchLimitError(f"batch exceeds the configured limit of {max_items} items")
        if not isinstance(token, str):
            yield BatchResult(
                index=index,
                error_code="invalid_input",
                error="Each batch item must be a compact JWT string.",
            )
            continue
        try:
            yield BatchResult(index=index, assessment=inspect_token(token))
        except ValueError:
            code = "invalid_token"
            # Parser messages are intentionally not forwarded: they may contain
            # attacker-controlled data in future parser implementations.
            yield BatchResult(
                index=index,
                error_code=code,
                error="The token is malformed or violates parser limits.",
            )


def assess_many(tokens: Iterable[str], *, max_items: int = 10_000) -> Iterator[BatchResult]:
    """Compatibility-friendly alias for the streaming `iter_assessments` API."""
    yield from iter_assessments(tokens, max_items=max_items)
