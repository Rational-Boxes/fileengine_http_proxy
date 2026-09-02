# http_bridge — chunked / resumable upload

Status: **Proposed.** A working prototype exists on `feature/resumable-chunked-upload`
(bridge + SPA), verified against a live stack but **not merged and not deployed**.
This document is the design put up for review; the open questions in
[Issues for review](#issues-for-review) are the parts I do not think should be
settled without a decision from you.

## Why

A video upload to the DO deployment failed with `request body too large`. That
specific failure was a limit mismatch and is fixed separately (`1.9.7` + the
`/api/` edge cap at 4g), so **this document is not about that**. It is about what
the limit fix does not address.

What was measured while fixing it:

- The path is **already streamed end to end**. The browser streams the `File`,
  nginx forwards with `proxy_request_buffering off`, the bridge reads 256 KiB at
  a time into `StreamFileUpload`, and the core runs
  chunk → compress → encrypt → `ofstream`. A 1 GiB upload completed in 25s with
  the bridge's RSS steady at **45 MiB**.
- There is **no temp-copy cost**. The core writes straight to `storage_path`
  with no assemble-then-compress step and no temp-then-rename, so an upload
  needs 1× the stored size, not 2×.

So throughput and memory are not the problem. **Atomicity is.** A single PUT is
all or nothing: a connection lost at 900 MB of a 1 GB file starts again at zero.
On a phone, a hotel network, or a laptop that sleeps, that is the ordinary case
rather than the unlucky one — and it is the one thing raising a byte limit
cannot help with.

## Goals

1. A large upload survives a dropped connection: retry the part, not the file.
2. A client can ask **what actually arrived** rather than infer it.
3. An interrupted upload resumes after a page reload, and after a bridge restart.
4. Small files keep the existing single-PUT path unchanged.
5. No new datastore, no core or proto change.

## Non-goals

- **Parallel part uploads.** The prototype sends parts sequentially. Concurrency
  is a throughput optimisation and the API already permits it; it is deliberately
  not in the first cut.
- **Cross-instance resume.** See [Issue 1](#1-a-session-is-local-to-one-bridge-instance).
- **Deduplication or delta upload.** Out of scope.
- **Replacing WebDAV** as the bulk-transfer door.

## Topology

```
browser
  │  ≥ threshold: N parts, each its own request, each retryable
  ▼
nginx  (client_max_body_size 4g on /api/, proxy_request_buffering off)
  │
  ▼
http_bridge ── part n ──▶  <UPLOAD_SESSION_DIR>/<id>/n.part      (local disk)
  │                        <UPLOAD_SESSION_DIR>/<id>/manifest.json
  │
  └─ commit: parts read back in order, as ONE continuous stream
        │
        ▼
   core StreamFileUpload ─▶ compress ─▶ encrypt ─▶ storage_path ─▶ object store
```

The core has **no append RPC**. `StreamFileUpload` is one continuous stream that
produces one version, so commit is the point at which a set of parts turns back
into an ordinary upload. Nothing downstream of the bridge knows the upload was
chunked, which is what keeps this a bridge-only change.

## API

All five calls sit under the existing file resource and require the same bearer
auth as everything else.

| Call | Purpose | Success |
|---|---|---|
| `POST /v1/files/{uid}/uploads` | open a session; body `{size, chunk_size}` | `201` + state |
| `PUT /v1/files/{uid}/uploads/{id}/parts/{n}` | send part `n`, raw body | `204` |
| `GET /v1/files/{uid}/uploads/{id}` | what has landed | `200` + state |
| `POST /v1/files/{uid}/uploads/{id}/commit` | assemble → one version | `204` |
| `DELETE /v1/files/{uid}/uploads/{id}` | abandon, drop the parts | `204` |

State object:

```json
{ "upload_id": "…", "size": 26214400, "chunk_size": 8388608,
  "parts": 4, "received": [0,2], "complete": false, "expires_at": 1788474829 }
```

`received` is the whole point of the design: **the server is the record of
progress**, and a resuming client asks rather than assumes. A client-side tally
goes stale in exactly the way that skips a part — another tab, or a request whose
response was lost but whose body arrived.

## Behaviour & decisions

- **Parts on local disk, manifest beside them.** They are the file, gigabytes of
  it; neither Redis nor process memory is the right shape. The manifest is what
  lets a session survive a bridge restart, which is most of the value — resuming
  after the server bounced is precisely when resuming matters.
- **`PUT` a part is streamed to disk**, never buffered. A part may be 128 MiB;
  holding it whole would reintroduce, one route along, the buffering the streamed
  PUT exists to avoid.
- **A part is written to a temp name and renamed.** A part is wholly present or
  absent, so a connection dropped mid-part leaves nothing that `received` would
  later count as complete — which would otherwise put a hole in the committed file.
- **A wrong-sized part is refused on arrival**, where it can still be explained,
  rather than discovered as corruption after commit.
- **Assembling with a hole fails** rather than streaming what is there. The
  alternative silently commits a short file.
- **Commit discards parts only after the core has the version.** A transient core
  error then costs a retry, not the whole transfer.
- **Ownership is re-checked on every call** against user, tenant *and* target
  uid. A resumable upload is a handle that outlives a request, and a handle
  nobody owns is one anybody can finish. "Not yours" answers `404`, not `403`:
  whether someone else's upload exists is not this caller's business.
- **WRITE is checked when the session is opened**, not only at commit, because
  opening reserves disk. An unreachable core is treated as "no".
- **Client threshold.** ≥ 64 MiB chunks; below that the single PUT is kept. The
  direct path is not worse — it is fewer moving parts and the browser already
  streams it — it is simply all-or-nothing, which only matters once a transfer is
  long enough to be interrupted.
- **A remembered session is reused only when name, size and mtime all match**, so
  editing a file and re-dropping it cannot splice new bytes onto a half-sent
  older one. A session whose `chunk_size` differs is discarded — its parts do not
  line up with the ranges the current client would send.

## Sentinel sweep

Parts are the only thing this feature leaves on disk, and every failure mode
that does not end in a commit or an abort leaves some behind: a client that
closes the tab, a laptop that sleeps and never comes back, a create that died
between making the directory and writing the manifest, a part write interrupted
mid-rename. None of these is exceptional. Without something that removes them,
`UPLOAD_SESSION_DIR` only ever grows, and the failure is a full disk on the
host that also runs the core and the database.

So a **sentinel sweep** runs in two places, which between them cover the two
states a deployment is ever in:

- **On upload start**, in `create()`. This is close to free: `create()` already
  walks the session root to enforce `UPLOAD_MAX_SESSIONS_PER_USER`, so the sweep
  rides the walk that is happening anyway. It also has the right shape — the
  moment someone needs disk is the moment worth reclaiming it — and it keeps a
  busy deployment clean without anything scheduled at all.
- **On a systemd timer**, for the case sweep-on-start cannot reach: a deployment
  where nobody uploads for a week still accumulated detritus from the week
  before. This matches how audit retention is already run on this host.

Deliberately no in-process interval thread. Sweep-on-start covers active use and
the timer covers idle, so a third mechanism would only add a thread whose death
is silent.

### What counts as orphaned

In descending order of confidence:

1. **A session directory with no readable manifest.** A create that failed
   partway, or a manifest that was truncated. Nothing can ever resume it.
2. **A session past its `expires`.** The client was told when it would stop
   being resumable; after that the bytes are dead weight.
3. **A directory whose name is not a valid session id.** Nothing this code
   writes produces one, so it is either detritus from an older version or
   something that does not belong to us.
4. **A stray `*.partial`** inside an otherwise live session — the temp name a
   part is written under before it is renamed into place.

### The safety property that matters

**Age is measured from last modification, and nothing younger than the cull age
is ever removed** — including the four cases above. This is the whole of the
sweep's correctness:

- A session directory exists for a moment *before* its manifest is written, so
  rule 1 without an age check deletes sessions as they are being created. The
  window is milliseconds and the sweep runs hourly, which is precisely the kind
  of race that never appears in testing and appears in production.
- A `*.partial` file for a 128 MiB part is legitimately present for as long as
  that part takes to arrive. Rule 4 without an age check truncates uploads in
  flight.

The cull age must therefore be **greater than `UPLOAD_TTL_SECONDS`**, and the
bridge should refuse to start with a clear message if it is not — a sweep that
outruns the resume window silently deletes sessions clients are still entitled
to finish, and the symptom would be indistinguishable from Issue 1.

### How the timer reaches the parts

This is the part that has to be got right, because the obvious implementation is
wrong.

**Not** a host-side `find <dir> -mtime +2 -delete`. That path knows nothing about
manifests, `expires`, or which parts belong to a session still being written; it
would eventually delete a live upload, and the report would say it succeeded.

Instead the timer invokes the **bridge's own sweep**, so exactly one
implementation of "what is orphaned" exists:

```
fileengine-upload-sweep.timer  ─▶  .service
      └─ podman exec fileengine-http-bridge fileengine-upload-sweep
```

A small command in the bridge image, reading the same `UPLOAD_SESSION_DIR` and
`UPLOAD_CULL_AGE_SECONDS` as the server, so the policy cannot drift between the
two callers. Running it *inside the container* also means it sweeps the parts of
**that instance** — which is what keeps this correct if there is ever more than
one bridge, and is why the mechanism is `podman exec` rather than a path on the
host.

Schedule and jitter live in the timer unit (`OnUnitActiveSec`,
`RandomizedDelaySec`), not in bridge configuration — that is what a timer is
for, and it means the interval can be changed without touching the service.

### Reporting

The sweep logs what it removed (sessions, files, bytes reclaimed) and exports
counters, because a sweep that quietly stops is invisible: disk fills slowly and
the cause is a thread that died months earlier. `fileengine_upload_sweep_*` —
runs, sessions removed, bytes reclaimed, last-run age — alongside the metrics
the bridge already publishes. **Alert on last-run age climbing**, not on bytes
reclaimed: a healthy deployment with nothing to clean reclaims zero, which looks
identical to a sweeper that is no longer running.

### Note on the prototype

`sweepExpired()` as written on `feature/resumable-chunked-upload` is **not this**
and should not be shipped as-is: it calls `load()` twice, and it fetches
`last_write_time` and then ignores it — so it has no age check at all and would
be subject to both races above. It was written to prove the directory walk, not
the policy. The interval, the age check, the startup run and the reporting are
all still to be built.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `UPLOAD_SESSION_DIR` | `/var/tmp/fileengine-uploads` | where parts live |
| `UPLOAD_MAX_BYTES` | 5 GiB | largest single upload |
| `UPLOAD_MAX_PART_BYTES` | 128 MiB | largest part |
| `UPLOAD_TTL_SECONDS` | 86400 | abandoned sessions expire |
| `UPLOAD_MAX_SESSIONS_PER_USER` | 8 | bounds disk held by one user |
| `UPLOAD_SWEEP_ON_CREATE` | `true` | sweep during the directory walk `create()` already does |
| `UPLOAD_CULL_AGE_SECONDS` | 172800 | nothing modified more recently than this is removed (48h) |

The sweep **interval** is deliberately not here: it belongs to the systemd timer
(`OnUnitActiveSec`), so it can be changed without a bridge restart. Suggested
hourly with a randomised delay, alongside the existing audit-retention timer.

Part count is additionally capped at 10 000, so a tiny `chunk_size` on a huge
file cannot create a directory with hundreds of thousands of entries.

## Failure modes

| What happens | Result |
|---|---|
| Connection drops mid-part | Part absent; `received` omits it; client re-sends that part only |
| Connection drops between parts | Nothing lost; resume from `received` |
| Browser reload mid-upload | Session recalled from `localStorage`, `received` re-fetched |
| Bridge restarts mid-upload | Manifest and parts survive on disk; resume works |
| Client abandons the upload | Session expires after TTL; the sentinel sweep reclaims the parts once they pass the cull age |
| Create dies between mkdir and manifest | Directory has no manifest; swept once older than the cull age |
| Part write interrupted mid-rename | `*.partial` left behind; swept once older than the cull age |
| Commit fails in the core | Parts retained; commit is retryable |
| Part sent with the wrong size | `400`, part not stored |
| Commit while incomplete | `409` with the current state |
| Another user touches the session | `404` on every call |

## Issues for review

These are the parts I am not comfortable settling alone.

### 1. A session is local to one bridge instance

Parts are on the local filesystem. With one bridge — today's deployment — this
is invisible. Behind two, a client resuming against the other instance sees
`received: []` or a `404`, i.e. **it looks like the parts vanished**, and the
failure appears only under load balancing.

Options: (a) accept it and document that the bridge does not scale out while
this feature is on; (b) require sticky sessions at nginx for
`/api/v1/files/*/uploads/*`; (c) put the part directory on shared storage;
(d) store parts in the object store instead of local disk, which removes the
constraint entirely but adds a round trip per part and makes cleanup the object
store's problem. **My inclination is (b) now and (d) if the bridge is ever
genuinely scaled out** — but this is a deployment-architecture decision, not a
code one.

### 2. Part storage needs a volume, and nothing currently provides one

`UPLOAD_SESSION_DIR` defaults to `/var/tmp` *inside the container*. As it stands,
a container restart destroys in-flight sessions — which contradicts the "survives
a bridge restart" property above, in the exact deployment where it would be used.
A named volume (and headroom for concurrent uploads) has to be added to the
Ansible role and compose before this is worth shipping. **This is a blocker for
deployment, not for review.**

### 3. Sweep — DECIDED; numbers and packaging still open

Settled: sweep on upload start, plus a systemd timer (see
[Sentinel sweep](#sentinel-sweep)). Sweep-on-start covers a busy deployment and
costs almost nothing, because `create()` already walks the directory; the timer
covers an idle one, which sweep-on-start alone never would.

Still to decide or build:

- **The numbers.** 48h cull age against a 24h session TTL, timer hourly. The
  only hard constraint is cull age > TTL; the margin is a judgement about how
  long a stalled upload deserves to hold disk.
- **The `fileengine-upload-sweep` command does not exist yet**, nor the timer
  and service units in the Ansible role. Both are prerequisites for shipping.
- **What sweep-on-start does when the directory is large.** It is bounded by
  `UPLOAD_MAX_SESSIONS_PER_USER` in the normal case, but a directory that has
  accumulated detritus for months makes the first upload after a restart pay for
  all of it. A cap on work per invocation — sweep at most N sessions, leave the
  rest to the timer — would keep that off the request path.

### 4. Disk is bounded by session count, not by bytes

`UPLOAD_MAX_SESSIONS_PER_USER = 8` with `UPLOAD_MAX_BYTES = 5 GiB` means one
user can legitimately hold **40 GiB** of parts, and N users N×40 GiB. That is a
denial-of-service by ordinary use, not by attack. A byte-based quota (per user
and global) would be the honest bound; it needs a decision on what the limits
should be, and on what a user sees when they hit one.

### 5. No integrity check on a part or on the whole file

Nothing verifies that a part arrived intact beyond its length, and nothing
verifies the assembled file against a client-side digest. TCP and TLS make
silent corruption unlikely but not impossible, and the failure would be a
corrupt file that everything reports as successful. A per-part checksum
(client-supplied, verified on arrival) is cheap; a whole-file digest checked at
commit is stronger and costs a full read. **Worth deciding explicitly rather
than defaulting to none.**

### 6. A token can expire mid-upload

A large upload can outlive `TOKEN_TTL_SECONDS` (900s here). The SPA refreshes on
a timer so this is usually invisible, but a background tab may not, and the
failure lands as a `401` on one part with no special handling — the upload fails
where it could have paused. Worth deciding whether the uploader should refresh
on `401` and retry the part.

### 7. Commit is not atomic in the core

Independent of this feature: `put_stream` writes directly to `storage_path`, so
a stream that fails midway leaves a partial file rather than rolling back. Commit
makes that easier to hit, because it turns a long client-side transfer into a
long *server-side* one. A temp-then-rename in the core would fix it properly and
is a core change, so it is out of scope here — but this feature raises its odds.

### 8. The threshold and chunk size are picks, not measurements

64 MiB and 8 MiB were chosen for shape, not from data. Too small a chunk means
many requests and more overhead; too large means a costly retry. Worth measuring
against the real deployment before treating them as settled.

### 9. Interaction with the `Transfer-Encoding: chunked` gap

Also pre-existing: the bridge's body-size guard fires only on a **declared**
`Content-Length`, so a chunked request bypasses it and nginx's
`client_max_body_size` is the only bound. Part uploads inherit that. It is why
the edge cap is a number rather than `0`, but the bridge should bound its own
streamed reads as defence in depth.

## Alternatives considered

- **Raise the limits and stop there.** Done, and it is the right immediate fix,
  but it does not make a transfer survivable — it only moves where it dies.
- **Object-store multipart, client-direct (presigned URLs).** Removes the bridge
  from the data path entirely and is how large systems usually do this. Rejected
  for now: it bypasses the core's compress/encrypt pipeline and its permission
  model, which is a much larger architectural change than it first looks.
- **An append RPC in the core.** Cleaner than assembling in the bridge, and it
  would let commit be O(1). It is a proto change with four consumers and a core
  release; deferred rather than dismissed.
- **Parts in Redis.** Rejected: gigabytes of binary in a store that everything
  else depends on for auth and audit.

## Testing

The prototype carries 16 bridge unit tests (id validation against traversal,
part arithmetic, idempotent re-send, wrong-size refusal, hole detection,
per-user bounds, expiry) and 18 SPA tests (range coverage, resume-from-server,
progress accounting, retry, no-commit-on-failure, session identity).

Verified end to end against a live stack: 25 MiB in 4 parts, two sent and two
withheld, `received: [0,2]`, commit refused `409`, remaining parts sent, commit
`204`, content byte-identical, session gone. A second user received `404` on
status, part, commit and abort.

**Not yet tested:** a genuine mid-transfer network drop (simulated by withholding
parts, which is not the same thing), concurrent sessions against the same file,
and behaviour when the disk fills.

**The sweep needs tests it does not have**, and they are mostly about what it
must NOT remove — a directory younger than the cull age even with no manifest, a
`*.partial` for a part still arriving, a session inside its TTL. A sweep tested
only on what it deletes will pass while being far too eager, and the damage
lands on someone else's upload.
