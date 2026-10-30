"""Bounded parallel HMAC secret testing for authorized assessments.

The deadline stops new submissions and asks workers to stop between candidates.
A cryptographic call already running inside PyJWT cannot be interrupted safely;
shutdown therefore drains in-flight calls before returning.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from threading import Event

import jwt
from config import Config
from core.parser import MAX_TOKEN_LENGTH

logger = logging.getLogger(__name__)

MAX_BRUTE_FORCE_WORKERS = 32
MAX_BRUTE_FORCE_TIMEOUT_SECONDS = 3600
MAX_BRUTE_FORCE_CANDIDATES = 1_000_000
MAX_SECRET_CANDIDATE_BYTES = 4096


def brute_force_parallel(
    token: str,
    wordlist: Iterable[str],
    workers: int = 8,
    algorithms: Sequence[str] | None = None,
    timeout: float = 300,
) -> str | None:
    """Return a matching HMAC secret without copying or queueing the whole wordlist.

    Input is consumed incrementally. At most the worker limit candidates are in flight,
    worker count is capped, each candidate is size-limited, and submissions stop
    when the deadline or candidate budget is reached.

    The timeout is cooperative rather than a hard process-level kill: a PyJWT
    cryptographic call already executing in a worker thread cannot be cancelled.
    The function sets the stop event and waits for those bounded in-flight calls
    to finish before it returns.
    """
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return None
    if (
        not math.isfinite(float(timeout))
        or timeout <= 0
        or timeout > MAX_BRUTE_FORCE_TIMEOUT_SECONDS
    ):
        return None
    if isinstance(wordlist, (str, bytes, bytearray)):
        return None
    try:
        iterator = iter(wordlist)
    except TypeError:
        return None

    if algorithms is None:
        algorithms = Config.SUPPORTED_SYMMETRIC_ALGORITHMS
    if isinstance(algorithms, (str, bytes)) or not isinstance(algorithms, Sequence):
        return None
    allowed = set(Config.SUPPORTED_SYMMETRIC_ALGORITHMS)
    selected_algorithms = tuple(
        dict.fromkeys(alg for alg in algorithms if isinstance(alg, str) and alg in allowed)
    )
    if not selected_algorithms:
        return None

    worker_limit = max(1, min(workers, MAX_BRUTE_FORCE_WORKERS))
    if isinstance(wordlist, Sequence) and len(wordlist) < 100:
        worker_limit = 1

    deadline = time.monotonic() + float(timeout)
    stop_event = Event()
    attempts = 0
    submitted = 0
    pending: dict[Future, None] = {}
    found: str | None = None
    pool = ThreadPoolExecutor(
        max_workers=worker_limit,
        thread_name_prefix="jwt-audit",
    )

    def try_one(secret: str) -> tuple[str | None, int]:
        if stop_event.is_set() or time.monotonic() >= deadline:
            return None, 0
        if not isinstance(secret, str) or not secret:
            return None, 0
        try:
            candidate_size = len(secret.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            return None, 0
        if candidate_size > MAX_SECRET_CANDIDATE_BYTES:
            return None, 0

        count = 0
        for algorithm in selected_algorithms:
            if stop_event.is_set() or time.monotonic() >= deadline:
                break
            count += 1
            try:
                jwt.decode(token, secret, algorithms=[algorithm])
                return secret, count
            except jwt.InvalidTokenError:
                continue
            except (UnicodeError, TypeError, ValueError):
                continue
        return None, count

    def submit_next() -> bool:
        nonlocal submitted
        if (
            stop_event.is_set()
            or time.monotonic() >= deadline
            or submitted >= MAX_BRUTE_FORCE_CANDIDATES
            or len(pending) >= worker_limit
        ):
            return False
        try:
            candidate = next(iterator)
        except StopIteration:
            return False
        submitted += 1
        pending[pool.submit(try_one, candidate)] = None
        return True

    try:
        for _ in range(worker_limit):
            if not submit_next():
                break

        while pending and time.monotonic() < deadline and not stop_event.is_set():
            done, _ = wait(
                pending,
                timeout=max(0.0, deadline - time.monotonic()),
                return_when=FIRST_COMPLETED,
            )
            if not done:
                break
            for future in done:
                pending.pop(future, None)
                try:
                    secret, count = future.result()
                except Exception:
                    logger.debug("A candidate verification worker failed")
                    secret, count = None, 0
                attempts += count
                if secret is not None:
                    found = secret
                    stop_event.set()
                    break
                submit_next()
            if found is not None:
                break
    except KeyboardInterrupt:
        stop_event.set()
        for future in pending:
            future.cancel()
        raise
    finally:
        stop_event.set()
        for future in pending:
            future.cancel()
        # A running cryptographic call cannot be force-killed safely.
        pool.shutdown(wait=True, cancel_futures=True)

    if found is not None:
        logger.info("Matching secret found after at least %d attempts", attempts)
    elif time.monotonic() >= deadline:
        logger.warning("Brute force timed out after at least %d attempts", attempts)
    elif submitted >= MAX_BRUTE_FORCE_CANDIDATES:
        logger.warning("Brute force candidate budget reached after %d candidates", submitted)
    return found
