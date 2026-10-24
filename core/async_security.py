"""Bounded parallel HMAC secret testing for authorized assessments."""
import logging
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from threading import Event
from typing import List, Optional

import jwt
from config import Config

logger = logging.getLogger(__name__)


def brute_force_parallel(token: str, wordlist: List[str], workers: int = 8,
                         algorithms: Optional[List[str]] = None,
                         timeout: int = 300) -> Optional[str]:
    """Return a matching secret or None without submitting an unbounded queue."""
    if not wordlist or timeout <= 0:
        return None
    if algorithms is None:
        algorithms = Config.SUPPORTED_SYMMETRIC_ALGORITHMS
    allowed = set(Config.SUPPORTED_SYMMETRIC_ALGORITHMS)
    algorithms = [alg for alg in algorithms if alg in allowed]
    if not algorithms:
        return None
    workers = max(1, min(int(workers), 32))
    if len(wordlist) < 100:
        workers = 1
    deadline = time.monotonic() + timeout
    stop_event = Event()
    attempts = 0

    def try_one(secret: str):
        if stop_event.is_set() or time.monotonic() >= deadline:
            return None, 0
        count = 0
        for alg in algorithms:
            if stop_event.is_set() or time.monotonic() >= deadline:
                break
            count += 1
            try:
                jwt.decode(token, secret, algorithms=[alg])
                return secret, count
            except jwt.InvalidTokenError:
                continue
        return None, count

    iterator = iter(wordlist)
    pending = {}
    found = None
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="jwt-audit")
    try:
        for _ in range(workers):
            try:
                candidate = next(iterator)
            except StopIteration:
                break
            pending[pool.submit(try_one, candidate)] = candidate

        while pending and time.monotonic() < deadline and not stop_event.is_set():
            done, _ = wait(pending, timeout=max(0, deadline - time.monotonic()),
                           return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                pending.pop(future, None)
                secret, count = future.result()
                attempts += count
                if secret is not None:
                    found = secret
                    stop_event.set()
                    break
                if time.monotonic() < deadline and not stop_event.is_set():
                    try:
                        candidate = next(iterator)
                    except StopIteration:
                        continue
                    pending[pool.submit(try_one, candidate)] = candidate
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
        # An in-flight cryptographic verification cannot be force-killed safely.
        pool.shutdown(wait=True, cancel_futures=True)

    if found is not None:
        logger.info("Matching secret found after at least %d attempts", attempts)
    elif time.monotonic() >= deadline:
        logger.warning("Brute force timed out after at least %d attempts", attempts)
    return found
