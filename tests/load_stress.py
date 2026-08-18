#!/usr/bin/env python3
# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Sustained load against a C++ service: does it crash, or soft-lock?

**This file is copied verbatim between the C++ services**, the same way
fileservice.proto is. The workloads differ per service; the harness does not.

Two failure modes are being hunted, and they need different evidence:

  **Crash** — the process dies and (under a supervisor) comes back. Easy to miss
  after the fact, because a restarted service looks healthy. Caught here by
  watching `fileengine_uptime_seconds` across the run: uptime that goes DOWN
  means a different process is answering than the one we started against.

  **Soft-lock** — the process is alive and accepts connections but stops making
  progress: every worker parked on a lock, a pool drained and never refilled, a
  thread wedged in uninterruptible I/O. A liveness probe alone will not see it,
  so the harness asks two questions a probe cannot: did the monitoring endpoint
  keep answering *while saturated*, and did the resources come back *afterwards*.

**Refusal is not failure.** These services shed load deliberately, in two ways,
and both are the design working rather than a fault:

  * a 503 (or 429) when the worker pool is saturated, which is also what /readyz
    reports so a balancer drains the instance;
  * a REFUSED CONNECTION once the accept queue is full. Poco's HTTPServer takes
    `threads` workers plus `threads * 8` queued, and drops anything beyond that
    at the TCP level — before any handler exists to answer with a 503. So a
    bridge's real ceiling is about `threads * 9` concurrent connections, and
    pushing past it produces resets, not slow responses.

Connection drops are therefore judged in context: expected while the pool is
saturated, a genuine defect when it is not. What is never acceptable is a request
that HANGS, a service that stops answering, or resources that never come back.

Usage:
    python3 tests/load_stress.py --target core|http|webdav [options]

Needs the stack up (scripts/start_backend_services.sh). Exits non-zero on
failure so it can gate a build.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import socket
import ssl  # noqa: F401  (imported for parity with https targets)
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------------------------------------------------------------- config
BRIDGE = os.environ.get("BRIDGE_URL", "http://localhost:8090")
WEBDAV = os.environ.get("WEBDAV_URL", "http://localhost:8088")
USER = os.environ.get("FE_USER", "testuser@rationalboxes.com")
PASSWORD = os.environ.get("FE_PASSWORD", "P@ssword1234567890*")
TENANT = os.environ.get("FE_TENANT", "default")

#: WebDAV refuses the LDAP directory password by design (the service-credential
#: hardening); it takes a backend-generated `key:secret`. Supply one to drive
#: authenticated traffic — without it the run still loads the accept loop and the
#: credential-verification path, which is where a soft-lock would show, but it
#: cannot exercise file operations.
WEBDAV_KEY = os.environ.get("WEBDAV_KEY", "")
WEBDAV_SECRET = os.environ.get("WEBDAV_SECRET", "")

MONITORS = {
    "core":   os.environ.get("CORE_MONITOR_URL", "http://localhost:8081"),
    "http":   os.environ.get("BRIDGE_MONITOR_URL", "http://localhost:8091"),
    "webdav": os.environ.get("WEBDAV_MONITOR_URL", "http://localhost:8089"),
}


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# ------------------------------------------------------------------- metrics
_SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})? (-?[0-9.eE+]+)$')


def scrape(url: str, timeout: float = 5.0) -> dict:
    """Parse a Prometheus exposition into {name: value} / {name: {label: value}}.

    Every service publishes the same names (one `fileengine_` namespace), which
    is what lets one harness judge three different services.
    """
    with urllib.request.urlopen(url + "/metrics", timeout=timeout) as resp:
        text = resp.read().decode()
    out: dict = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = _SAMPLE.match(line)
        if not m:
            continue
        name, labels, value = m.group(1), m.group(2) or "", float(m.group(3))
        state = re.search(r'state="([^"]*)"', labels)
        if state:
            out.setdefault(name, {})[state.group(1)] = value
        else:
            out[name] = value
    return out


class Sampler(threading.Thread):
    """Scrapes the target throughout the run.

    Every sample is also a liveness check of the monitoring listener: a service
    that stops answering here while under load is soft-locking, which is exactly
    what the `misses` count is for.
    """

    def __init__(self, url: str, interval: float = 0.5):
        super().__init__(daemon=True)
        self.url, self.interval = url, interval
        self.samples: list[dict] = []
        self.misses = 0
        self.latencies: list[float] = []
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                self.samples.append(scrape(self.url))
                self.latencies.append(time.time() - started)
            except Exception:  # noqa: BLE001
                self.misses += 1
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()

    def peak(self, name: str, key: str | None = None) -> float:
        best = 0.0
        for s in self.samples:
            v = s.get(name)
            if isinstance(v, dict) and key:
                v = v.get(key)
            if isinstance(v, (int, float)):
                best = max(best, float(v))
        return best


# ------------------------------------------------------------------ workloads
def _req(method: str, url: str, auth: str, body: bytes | None = None,
         content_type: str = "application/json", headers: dict | None = None,
         timeout: float = 30.0):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", auth)
    req.add_header("X-Tenant", TENANT)
    if body is not None:
        req.add_header("Content-Type", content_type)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read()


class Outcome:
    """One request's result, split the way the assertions need it.

    `shed` is a service deliberately refusing work under pressure — 503, or a
    429. That is correct behaviour and must not be counted as a failure, or the
    test would punish exactly the load-shedding it wants the service to do.
    """
    __slots__ = ("ok", "shed", "detail", "seconds")

    def __init__(self, ok: bool, shed: bool = False, detail: str = "", seconds: float = 0.0):
        self.ok, self.shed, self.detail, self.seconds = ok, shed, detail, seconds

    def refused_connection(self) -> bool:
        """Did the server refuse the connection outright, rather than hang?

        Poco closes the socket when its accept queue is full, which surfaces as a
        reset, a broken pipe, or a disconnect with no response. Bounded and
        self-protecting — unlike a request that never returns.
        """
        d = self.detail
        return any(marker in d for marker in (
            "RemoteDisconnected", "Connection reset", "Broken pipe",
            "ConnectionResetError", "BadStatusLine", "Errno 104", "Errno 32"))


def _run(fn) -> Outcome:
    started = time.time()
    try:
        fn()
        return Outcome(True, seconds=time.time() - started)
    except urllib.error.HTTPError as e:
        shed = e.code in (429, 503)
        return Outcome(shed, shed, f"HTTP {e.code}", time.time() - started)
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        # A dropped or hung connection is the failure this test exists to catch.
        return Outcome(False, False, f"{type(e).__name__}: {e}", time.time() - started)
    except Exception as e:  # noqa: BLE001
        return Outcome(False, False, f"{type(e).__name__}: {e}", time.time() - started)


def workload_core(i: int, size: int) -> Outcome:
    """Create + upload through the bridge: the core's real request path."""
    auth = _basic(USER, PASSWORD)

    def go():
        _, payload = _req("POST", f"{BRIDGE}/v1/dirs/root/files", auth,
                          json.dumps({"name": f"stress-{os.getpid()}-{i}.bin"}).encode())
        uid = json.loads(payload)["uid"]
        _req("PUT", f"{BRIDGE}/v1/files/{uid}/content", auth,
             (f"{i}:".encode() + b"x" * size), content_type="application/octet-stream")
    return _run(go)


def workload_http(i: int, size: int) -> Outcome:
    """Mixed read/write against the REST bridge.

    Deliberately not uploads alone: a bridge soft-locks on its worker pool, and
    mixing cheap reads with expensive writes is what puts pressure on it rather
    than on the core behind it.
    """
    auth = _basic(USER, PASSWORD)

    def go():
        if i % 3 == 0:
            _req("GET", f"{BRIDGE}/v1/nodes/root", auth)
        elif i % 3 == 1:
            _req("GET", f"{BRIDGE}/v1/dirs/root", auth)   # list the root directory
        else:
            _, payload = _req("POST", f"{BRIDGE}/v1/dirs/root/files", auth,
                              json.dumps({"name": f"stress-http-{os.getpid()}-{i}.bin"}).encode())
            uid = json.loads(payload)["uid"]
            _req("PUT", f"{BRIDGE}/v1/files/{uid}/content", auth,
                 b"y" * size, content_type="application/octet-stream")
    return _run(go)


def workload_webdav(i: int, size: int) -> Outcome:
    """WebDAV traffic — authenticated when a service credential is supplied.

    Without one every request is refused, which still drives the accept loop,
    the worker pool and credential verification. That is a narrower test but not
    a pointless one: those are the paths where a soft-lock under connection load
    actually happens. The summary says which mode ran, so a pass is never
    mistaken for more coverage than it had.
    """
    authenticated = bool(WEBDAV_KEY and WEBDAV_SECRET)
    auth = _basic(WEBDAV_KEY, WEBDAV_SECRET) if authenticated else _basic(USER, PASSWORD)

    def go():
        if not authenticated:
            # Expect a refusal; anything else is fine too. What must NOT happen is
            # a hang or a dropped connection, which _run() classifies as failure.
            try:
                _req("PROPFIND", f"{WEBDAV}/", auth, headers={"Depth": "0"}, timeout=20)
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    return          # refused as designed
                raise
            return
        if i % 3 == 2:
            _req("PUT", f"{WEBDAV}/stress-dav-{os.getpid()}-{i}.bin", auth,
                 b"z" * size, content_type="application/octet-stream", timeout=30)
        else:
            _req("PROPFIND", f"{WEBDAV}/", auth, headers={"Depth": "1"}, timeout=20)
    return _run(go)


WORKLOADS = {"core": workload_core, "http": workload_http, "webdav": workload_webdav}


# ----------------------------------------------------------------- assertions
def judge(target: str, before: dict, after: dict, sampler: Sampler,
          outcomes: list[Outcome], monitor_url: str) -> list[str]:
    problems: list[str] = []

    failed = [o for o in outcomes if not o.ok]
    shed = [o for o in outcomes if o.shed]

    # --- crash -----------------------------------------------------------
    # Uptime going backwards means a DIFFERENT process is answering: the one we
    # started against died and something restarted it. Without this a crash+
    # restart mid-run reads as a clean pass.
    up_before = before.get("fileengine_uptime_seconds", 0)
    up_after = after.get("fileengine_uptime_seconds", 0)
    if up_after < up_before:
        problems.append(
            f"the service RESTARTED during the run (uptime {up_before:.0f}s -> {up_after:.0f}s) "
            "— it crashed and came back")
    for s in sampler.samples:
        if s.get("fileengine_uptime_seconds", 0) < up_before:
            problems.append("uptime went backwards mid-run — the service restarted under load")
            break

    # --- soft-lock: did it keep answering while saturated? ----------------
    if sampler.misses:
        problems.append(
            f"the monitoring endpoint failed to answer {sampler.misses} time(s) during load "
            "— a live process that stops responding is the soft-lock this test hunts")

    # ...and does it answer now?
    try:
        scrape(monitor_url, timeout=10)
    except Exception as e:  # noqa: BLE001
        problems.append(f"the service is not answering after the load: {e}")

    # --- soft-lock: did the resources come back? --------------------------
    threads = after.get("fileengine_threads", {})
    if isinstance(threads, dict) and threads:
        if threads.get("uninterruptible", 0) > 0:
            problems.append(
                f"{threads['uninterruptible']:.0f} thread(s) left in uninterruptible sleep "
                "— blocked in the kernel, cannot be cancelled or timed out")
        not_waiting = after.get("fileengine_threads_not_waiting", 0)
        if not_waiting > 3:
            problems.append(
                f"{not_waiting:.0f} threads still not waiting after the load — workers should "
                "park again once traffic stops")

    grew = after.get("process_threads", 0) - before.get("process_threads", 0)
    if grew > 16:
        problems.append(
            f"thread count grew by {grew:.0f} and did not come back down "
            f"({before.get('process_threads', 0):.0f} -> {after.get('process_threads', 0):.0f})")

    fds = after.get("process_open_fds", 0) - before.get("process_open_fds", 0)
    if fds > 64:
        problems.append(
            f"open file descriptors grew by {fds:.0f} and did not come back "
            "— a descriptor leak will eventually refuse all connections")

    # Worker pool (bridges) — must drain back to idle.
    if "fileengine_worker_pool_used" in after:
        # Poco assigns a worker per connection, and a keep-alive connection holds
        # one after its request finishes — so a couple still in use at rest is
        # normal. What must not happen is workers never coming back: the check is
        # against saturation and against a pool that stayed near its peak.
        used = after["fileengine_worker_pool_used"]
        cap = after.get("fileengine_worker_pool_capacity", 0)
        if cap and used >= cap:
            problems.append(
                f"the worker pool is still FULL after the load ({used:.0f}/{cap:.0f}) "
                "— workers are not being returned")
        elif used > max(2, cap * 0.25):
            problems.append(
                f"{used:.0f} of {cap:.0f} workers still busy well after the load")
    # Database pool (core) — every connection must be returned.
    if "fileengine_db_pool_in_use" in after:
        if after["fileengine_db_pool_in_use"] > 0 or after.get("fileengine_db_pool_outstanding", 0) > 0:
            problems.append(
                f"database connections not returned: in_use={after['fileengine_db_pool_in_use']:.0f}, "
                f"outstanding={after.get('fileengine_db_pool_outstanding', 0):.0f}")
        if after.get("fileengine_db_pool_wait_timeouts_total", 0) > \
           before.get("fileengine_db_pool_wait_timeouts_total", 0):
            problems.append("a caller timed out waiting for a database connection")
    # In-flight RPCs (core) — nothing may be left running.
    if after.get("fileengine_rpc_in_flight_total", 0) > 0:
        problems.append(
            f"{after['fileengine_rpc_in_flight_total']:.0f} RPC(s) still in flight after settling")

    # --- request outcomes -------------------------------------------------
    # Split refusals from real failures. A connection refused once the accept
    # queue is full is the server protecting itself (see the module docstring);
    # the same refusal with the pool NOT saturated would mean it was dropping
    # work it had capacity for, which is a defect.
    dropped = [o for o in failed if o.refused_connection()]
    hung = [o for o in failed if not o.refused_connection()]

    saturated = False
    cap = after.get("fileengine_worker_pool_capacity", 0)
    if cap:
        saturated = sampler.peak("fileengine_worker_pool_used") >= cap
    elif "fileengine_db_pool_size" in after:
        saturated = sampler.peak("fileengine_db_pool_in_use") >= after["fileengine_db_pool_size"]

    if hung:
        detail = "; ".join(sorted({o.detail for o in hung})[:3])
        problems.append(
            f"{len(hung)}/{len(outcomes)} requests hung or failed for a reason other than "
            f"refusal ({detail})")

    if dropped and not saturated:
        detail = "; ".join(sorted({o.detail for o in dropped})[:2])
        problems.append(
            f"{len(dropped)}/{len(outcomes)} connections were dropped while the pool was NOT "
            f"saturated — work was refused that there was capacity for ({detail})")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", choices=sorted(WORKLOADS), required=True)
    ap.add_argument("--requests", type=int, default=600)
    ap.add_argument("--concurrency", type=int, default=48)
    ap.add_argument("--size", type=int, default=64 * 1024)
    ap.add_argument("--settle", type=float, default=4.0,
                    help="seconds to let things quiesce before judging the resting state")
    args = ap.parse_args()

    monitor = MONITORS[args.target]
    print(f"→ {args.target}: {args.requests} requests, {args.concurrency} concurrent, "
          f"{args.size // 1024} KiB payloads")
    if args.target == "webdav" and not (WEBDAV_KEY and WEBDAV_SECRET):
        print("  NOTE: no WEBDAV_KEY/WEBDAV_SECRET — driving the accept loop and credential "
              "check only.\n        Set them to stress real file operations.")

    try:
        before = scrape(monitor)
    except Exception as e:  # noqa: BLE001
        print(f"cannot reach {args.target} monitoring at {monitor}: {e}", file=sys.stderr)
        print("is the stack up? scripts/start_backend_services.sh", file=sys.stderr)
        return 2

    print(f"  baseline: {before.get('process_threads', 0):.0f} threads, "
          f"{before.get('process_open_fds', 0):.0f} fds, "
          f"uptime {before.get('fileengine_uptime_seconds', 0):.0f}s")

    sampler = Sampler(monitor)
    sampler.start()

    work = WORKLOADS[args.target]
    started = time.time()
    outcomes: list[Outcome] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(work, i, args.size) for i in range(args.requests)]
        for f in as_completed(futures):
            outcomes.append(f.result())
    elapsed = time.time() - started

    sampler.stop()
    sampler.join(timeout=5)

    ok = sum(1 for o in outcomes if o.ok and not o.shed)
    shed = sum(1 for o in outcomes if o.shed)
    failed = sum(1 for o in outcomes if not o.ok)
    lat = sorted(o.seconds for o in outcomes if o.ok)
    p95 = lat[int(len(lat) * 0.95)] if lat else 0.0

    dropped = sum(1 for o in outcomes if not o.ok and o.refused_connection())
    hung = failed - dropped
    print(f"  {ok} ok, {shed} shed (503/429), {dropped} refused at the accept queue, "
          f"{hung} hung/other  in {elapsed:.1f}s  |  p95 {p95:.2f}s")
    print(f"  peak under load: {sampler.peak('fileengine_threads_not_waiting'):.0f} threads busy, "
          f"{sampler.peak('fileengine_worker_pool_used') or sampler.peak('fileengine_db_pool_in_use'):.0f} "
          f"workers/connections in use, monitor missed {sampler.misses} scrape(s)")
    if sampler.latencies:
        print(f"  monitoring stayed answerable: worst scrape {max(sampler.latencies):.2f}s, "
              f"median {statistics.median(sampler.latencies):.2f}s")

    time.sleep(args.settle)
    after = scrape(monitor)
    print(f"  at rest:  {after.get('process_threads', 0):.0f} threads, "
          f"{after.get('process_open_fds', 0):.0f} fds, "
          f"{after.get('fileengine_threads_not_waiting', 0):.0f} not waiting")

    problems = judge(args.target, before, after, sampler, outcomes, monitor)

    print()
    if problems:
        print(f"FAIL — {args.target} did not survive the load cleanly:")
        for p in problems:
            print(f"  ✗ {p}")
        return 1
    print(f"PASS — {args.target} survived: no crash, no soft-lock, resources returned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
