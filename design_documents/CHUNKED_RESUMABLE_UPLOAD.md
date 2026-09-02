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

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `UPLOAD_SESSION_DIR` | `/var/tmp/fileengine-uploads` | where parts live |
| `UPLOAD_MAX_BYTES` | 5 GiB | largest single upload |
| `UPLOAD_MAX_PART_BYTES` | 128 MiB | largest part |
| `UPLOAD_TTL_SECONDS` | 86400 | abandoned sessions expire |
| `UPLOAD_MAX_SESSIONS_PER_USER` | 8 | bounds disk held by one user |

Part count is additionally capped at 10 000, so a tiny `chunk_size` on a huge
file cannot create a directory with hundreds of thousands of entries.

## Failure modes

| What happens | Result |
|---|---|
| Connection drops mid-part | Part absent; `received` omits it; client re-sends that part only |
| Connection drops between parts | Nothing lost; resume from `received` |
| Browser reload mid-upload | Session recalled from `localStorage`, `received` re-fetched |
| Bridge restarts mid-upload | Manifest and parts survive on disk; resume works |
| Client abandons the upload | Session expires after TTL and is swept |
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

### 3. Nothing sweeps expired sessions on a schedule

`sweepExpired()` exists and is correct, but is only reachable opportunistically.
Abandoned uploads therefore occupy disk until something calls it. Options: sweep
on session create (cheap, but only runs when someone uploads), a timer thread in
the bridge, or a systemd timer alongside the existing audit-retention job. **I
lean toward sweeping on create *and* a systemd timer**, so an idle deployment
still cleans up.

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
