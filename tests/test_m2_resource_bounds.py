"""M2 brute-force resource limits, cancellation, deadlines, and cleanup tests."""

import itertools
import threading
import time
from concurrent.futures import ThreadPoolExecutor as RealThreadPoolExecutor

import jwt
import pytest

import core.async_security as async_security


def test_worker_count_and_inflight_submission_queue_are_bounded(monkeypatch):
    submitted_futures = []
    observed = {"workers": None, "max_inflight": 0}

    class RecordingExecutor:
        def __init__(self, max_workers, **kwargs):
            observed["workers"] = max_workers
            self.inner = RealThreadPoolExecutor(max_workers=max_workers, **kwargs)

        def submit(self, function, *args, **kwargs):
            future = self.inner.submit(function, *args, **kwargs)
            submitted_futures.append(future)
            inflight = sum(not item.done() for item in submitted_futures)
            observed["max_inflight"] = max(observed["max_inflight"], inflight)
            return future

        def shutdown(self, wait=True, cancel_futures=False):
            self.inner.shutdown(wait=wait, cancel_futures=cancel_futures)

    def fake_decode(_token, secret, algorithms):
        time.sleep(0.002)
        if secret == "found-secret":
            return {"sub": "resource-test"}
        raise jwt.InvalidTokenError("not a match")

    monkeypatch.setattr(async_security, "ThreadPoolExecutor", RecordingExecutor)
    monkeypatch.setattr(async_security.jwt, "decode", fake_decode)
    words = itertools.chain((f"wrong-{index}" for index in range(200)), ["found-secret"])

    result = async_security.brute_force_parallel(
        "header.payload.signature",
        words,
        workers=10_000,
        algorithms=("HS256",),
        timeout=5,
    )

    assert result == "found-secret"
    assert observed["workers"] == async_security.MAX_BRUTE_FORCE_WORKERS
    assert observed["max_inflight"] <= async_security.MAX_BRUTE_FORCE_WORKERS
    assert observed["max_inflight"] > 1


def test_candidate_budget_stops_stream_consumption(monkeypatch):
    consumed = []
    monkeypatch.setattr(async_security, "MAX_BRUTE_FORCE_CANDIDATES", 3)
    monkeypatch.setattr(
        async_security.jwt,
        "decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(jwt.InvalidTokenError("no")),
    )

    def words():
        for index in range(100):
            consumed.append(index)
            yield f"candidate-{index}"

    assert async_security.brute_force_parallel(
        "header.payload.signature",
        words(),
        workers=1,
        algorithms=("HS256",),
        timeout=3,
    ) is None
    assert consumed == [0, 1, 2]


def test_oversized_candidate_is_skipped_without_aborting_the_stream(monkeypatch):
    monkeypatch.setattr(
        async_security.jwt,
        "decode",
        lambda _token, secret, _algorithms: (
            {"sub": "bounded"} if secret == "valid-secret"
            else (_ for _ in ()).throw(jwt.InvalidTokenError("no"))
        ),
    )

    result = async_security.brute_force_parallel(
        "header.payload.signature",
        ("x" * (async_security.MAX_SECRET_CANDIDATE_BYTES + 1), "valid-secret"),
        workers=1,
        algorithms=("HS256",),
        timeout=2,
    )

    assert result == "valid-secret"


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), 3601])
def test_invalid_or_excessive_timeouts_are_rejected(timeout):
    assert async_security.brute_force_parallel(
        "header.payload.signature",
        ["candidate"],
        workers=1,
        algorithms=("HS256",),
        timeout=timeout,
    ) is None


def test_invalid_worker_and_algorithm_inputs_fail_closed():
    assert async_security.brute_force_parallel(
        "header.payload.signature",
        ["candidate"],
        workers=True,
        algorithms=("HS256",),
    ) is None
    assert async_security.brute_force_parallel(
        "header.payload.signature",
        ["candidate"],
        workers=0,
        algorithms=("HS256",),
    ) is None
    assert async_security.brute_force_parallel(
        "header.payload.signature",
        ["candidate"],
        workers=1,
        algorithms=("RS256",),
    ) is None


def test_timeout_stops_submission_but_waits_for_uninterruptible_crypto_call(monkeypatch):
    entered_crypto = threading.Event()
    release_crypto = threading.Event()
    finished = threading.Event()
    result = []

    def blocked_decode(*_args, **_kwargs):
        entered_crypto.set()
        release_crypto.wait(timeout=3)
        raise jwt.InvalidTokenError("release after deadline")

    monkeypatch.setattr(async_security.jwt, "decode", blocked_decode)

    def run_check():
        result.append(
            async_security.brute_force_parallel(
                "header.payload.signature",
                ["candidate"],
                workers=1,
                algorithms=("HS256",),
                timeout=0.05,
            )
        )
        finished.set()

    thread = threading.Thread(target=run_check)
    thread.start()
    assert entered_crypto.wait(timeout=2)
    time.sleep(0.15)

    assert not finished.is_set()
    release_crypto.set()
    thread.join(timeout=2)

    assert finished.is_set()
    assert result == [None]


def test_worker_threads_are_cleaned_up_after_success(monkeypatch):
    def fake_decode(_token, secret, _algorithms):
        if secret == "correct":
            return {"sub": "cleanup"}
        raise jwt.InvalidTokenError("not a match")

    monkeypatch.setattr(async_security.jwt, "decode", fake_decode)
    result = async_security.brute_force_parallel(
        "header.payload.signature",
        [f"wrong-{index}" for index in range(150)] + ["correct"],
        workers=8,
        algorithms=("HS256",),
        timeout=3,
    )

    assert result == "correct"
    assert not [
        thread for thread in threading.enumerate()
        if thread.name.startswith("jwt-audit") and thread.is_alive()
    ]
