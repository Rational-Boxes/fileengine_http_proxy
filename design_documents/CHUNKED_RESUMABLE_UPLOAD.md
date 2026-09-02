# http_bridge — chunked / resumable upload

Status: **Proposed**, with the integrity model, the sweep and the
staging location settled (see [Decisions](#decisions)). A working prototype
exists on `feature/resumable-chunked-upload`
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

## Decisions

Settled in review; the reasoning is in the sections named.

| Question | Decision |
|---|---|
| Where partial uploads are staged | **In the bridge**, on local disk. An append operation in the core was worked through and declined — [appendix](#appendix-an-append-operation-in-the-core) |
| Per-part integrity | **Required** `Content-Digest` on every part, verified on arrival and again at commit — [Part integrity](#part-integrity) |
| Whole-upload integrity | **Content root** over the part digests, declared by the client at commit and enforced by the bridge; plain `sha256` optional |
| Reclaiming orphaned parts | **Sweep on upload start, plus a systemd timer** invoking the bridge's own sweep — [Sentinel sweep](#sentinel-sweep) |
| Hashing on the client | **In a Web Worker.** WASM only if measurement justifies it |

Still open: the numbers (thresholds, cull age, chunk size), the deployment
plumbing, and the items under [Issues for review](#issues-for-review).

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
| `PUT /v1/files/{uid}/uploads/{id}/parts/{n}` | send part `n`, raw body + `Content-Digest` | `204` |
| `GET /v1/files/{uid}/uploads/{id}` | what has landed | `200` + state |
| `POST /v1/files/{uid}/uploads/{id}/commit` | assemble → one version; body `{content_root, sha256?}` | `204` |
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

## Part integrity

Every part carries a checksum and the bridge verifies it. Without one, the only
check on a part is its length, and the failure that gets through is the one
nobody notices: a corrupt file that every layer reports as a success.

### On the wire

The client sends a digest with each part:

```
PUT /v1/files/{uid}/uploads/{id}/parts/3
Content-Digest: sha-256=:9f6c28ccc09f06c4…=:
```

RFC 9530 `Content-Digest`, because it is the standard spelling and intermediaries
understand it. (`X-Part-SHA256: <hex>` would be equivalent in effect and simpler
to parse — a small open choice, not a design one.)

**Required, not optional.** The reflex is to make a new header optional for
compatibility, but there are no older clients — this API does not exist yet — and
an optional digest buys nothing while costing the ability to distinguish "this
client cannot checksum" from "this part is corrupt". A part without a digest is
refused.

### Where it is verified

- **On arrival**, incrementally, as the part streams to its temp file. Nothing is
  buffered to hash it; the digest is updated per 256 KiB read, the same buffer
  the write already uses. A mismatch deletes the temp file and answers `400` —
  the part is never renamed into place, so it never becomes `received` and the
  client re-sends it like any other failure.
- **At commit**, against the digest recorded in the manifest. This is free: the
  commit already reads every part to stream it, so verification rides that read.
  It closes the gap between arrival and commit — a part corrupted on disk, or a
  disk that lied — which arrival-time checking alone cannot see.

### Content root — the client declares it, the server enforces it

Per-part digests cannot see a file that changed **between** attempts. Each part
is individually valid — the early ones hash against the old content, the later
ones against the new — so every check passes and the reconstruction is a silent
splice of two different files. Catching that needs one value derived from the
whole.

The value is a **content root** over the part digests, not a hash of the file
bytes:

```
content_root = SHA-256( "fe-upload-v1" ‖ size ‖ chunk_size ‖ d₀ ‖ d₁ ‖ … ‖ dₙ₋₁ )
```

where `dᵢ` is the raw 32-byte SHA-256 of part `i`. A flat digest-of-digests, not
a tree — nothing here needs inclusion proofs. The size and chunk size are bound
in so the root cannot be reused across a different chunking of the same bytes.

**Both sides already have every input.** The client hashes each part to send it;
the bridge stores each part's digest in the manifest on arrival. So:

- the client computes the root **for free**, as a by-product of hashing it must
  do anyway — no second read of the file;
- the bridge recomputes it at commit from the manifest, hashing `n × 32` bytes.
  For a 1 GiB upload that is 4 KiB of hashing. It never re-reads the parts.

The client declares its root at commit and the bridge refuses to create a
version if they differ:

```
POST /v1/files/{uid}/uploads/{id}/commit
{ "content_root": "b6b4050498db9247…" }

409 { "error": "assembled content does not match the declared content root" }
```

Rejecting server-side rather than reporting the mismatch back matters: a spliced
file never becomes a version at all, instead of becoming one a well-behaved
client is trusted to notice.

#### The one thing that makes this work

**The root must be computed from the file as it was on the FIRST attempt, and
stored** alongside the session id. Recomputing it on resume is worse than
useless: the client would hash the remaining chunks from the *new* content and
combine them with stored digests for the old — arriving at exactly the root the
bridge computes from the same mixture, so the two agree and the splice goes
through undetected.

That means the client must hash the whole file during the first attempt even if
the upload does not finish. In practice the hasher runs ahead of the network:
hashing is 50–100 MB/s against an upload of perhaps 6 MB/s, so the digests are
complete long before the transfer is. Only an interruption in the first seconds
leaves the root unknown.

When it is unknown — an early interruption, or `localStorage` cleared between
attempts — the client has two honest options: declare nothing and fall back to
the name/size/mtime guard, or read the file once to compute a root over its
current content. The second still detects the splice (a root over the new file
cannot match one the bridge derives from old-and-new parts) and costs the full
pass this design otherwise avoids. Either is correct; the fallback is a
degradation, not a hole.

#### What it costs, and what it replaces

It replaces a plain whole-file SHA-256 declared at commit, which was the earlier
proposal. That would have required a **second full read of the file**, hashed
with an implementation WebCrypto does not provide — `crypto.subtle.digest()` is
one-shot over a BufferSource, with no streaming or incremental API, so a 1 GiB
file means either 1 GiB resident or a pure-JS/WASM hasher. The content root
needs none of that: the per-chunk hashing is already happening, and combining 32
byte digests is trivial in plain JS.

**What is given up** is that the root is meaningful only inside this protocol. A
plain SHA-256 is what `sha256sum` prints — it could later verify the stored file,
feed an audit record, or be checked by something that is not our client. The
content root cannot do any of that.

So: content root as the primary, because it is free and catches the case that
prompted it. **A plain `sha256` may be declared as well** — the field is
accepted, verified against the assembled stream at commit (which already reads
every byte, so the check itself is free), and simply omitted by clients that do
not want to pay for the extra read. That keeps the externally-comparable digest
available where it is worth its cost, without making every upload pay for it.

### What this does and does not defend against

It is a **corruption** check, not an authentication one. The caller is already
authenticated and the transport is TLS; a client that wants to send different
bytes can simply send different bytes and a matching digest. What it catches is
a truncated part, a flipped bit, a proxy that mangled a body, a bad disk, and an
assembly mistake in our own code.

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
| Part fails its `Content-Digest` | `400`, temp file discarded, part never becomes `received` |
| Part sent without a digest | `400` — the digest is required |
| Part corrupted on disk after arrival | Caught at commit against the manifest digest; commit fails, parts retained |
| Parts assembled wrongly by the bridge | Content root differs from the declared one; commit `409` |
| File edited between attempts (mtime changed) | Session not reused; a fresh one is opened |
| File edited between attempts (mtime preserved) | Parts individually valid, content root differs; commit `409`, parts retained |
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

### 5. Integrity — DECIDED; one client-side cost to weigh

Settled: a required per-part `Content-Digest`, verified on arrival and again at
commit, plus a whole-file digest computed during commit and returned. See
[Part integrity](#part-integrity).

Settled: a required per-part `Content-Digest`, verified on arrival and again at
commit, plus a **content root** over the part digests that the client declares at
commit and the bridge enforces — so a file edited between attempts is rejected
rather than spliced. Both are free: the client hashes each part anyway, and the
bridge recomputes the root from the manifest without re-reading a byte. A plain
`sha256` remains available as an optional extra for clients that want an
externally-comparable digest and will pay a second read for it. See
[Part integrity](#part-integrity).

Two things left, both on the client:

- **`crypto.subtle` is only available in a secure context.** Over HTTPS, or on
  `localhost`, it is there; on the dev stack reached by LAN IP over plain HTTP it
  is not, and the uploader would have no way to produce the digest the server now
  requires. Either large uploads are HTTPS-only (defensible, and true of the real
  deployment), or a pure-JS SHA-256 fallback is carried for dev — which is slow
  enough on 8 MiB to be worth avoiding if we can just say "use HTTPS".
- **Hashing must move off the main thread.** This is the non-negotiable part, and
  it is the Worker rather than the language: a 1 GiB file is ~128 chunks at
  roughly 20 ms each, and on the main thread that is seconds of blocking in
  slices long enough to feel. In a Worker, plain-JS SHA-256 at 50–100 MB/s is
  10–20 s of background CPU against an upload of minutes — invisible. The SPA
  has **no Web Worker anywhere today**, so this is new code, but it is ordinary.
- **WASM is an optimisation to justify by measurement, not to assume.** It buys
  ~5–10× on hashing, which matters only when the upload is fast enough for the
  hash to be the bottleneck — a LAN client, not the deployment this was reported
  from. And the project **ships no WebAssembly to the browser today**: the only
  `.wasm` in the tree is xeokit's `web-ifc`, which is never on the client path
  because models are loaded as server-produced `.xkt` renditions, and pdfjs's
  optional codecs are never fetched because nothing configures a `wasmUrl`.
  Adding it means solving four things for the first time — serving
  `application/wasm`, a CSP that permits `wasm-unsafe-eval`, Vite emitting and
  fingerprinting the asset, and vendoring a binary dependency into an AGPL
  product. None is hard; none is free either. Keeping the hasher behind an
  interface in the Worker means the swap later touches one module. A 1 GiB file is ~128
  chunks; at roughly 20 ms each that is 2.5 s of blocking spread through the
  upload, in slices long enough to feel. A Web Worker fixes it and is the
  standard answer, but it is real work rather than a line of code, and it should
  be planned rather than discovered when the progress bar stutters.

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
- **An append RPC in the core.** Worked through rather than dismissed in a line,
  and **decided against for now** — see [Appendix: an append operation in the
  core](#appendix-an-append-operation-in-the-core). The reason is sharper than
  "it is a proto change": the core encrypts with AES-256-GCM, whose tag is
  computed over the whole message in order, so appending to the stored format is
  inherently ordered while resumable upload is inherently unordered.
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

**Integrity needs its own tests**, and the interesting ones are the negatives: a
part whose digest does not match must not become `received`; a part file
corrupted on disk after arrival must fail the commit rather than pass it; and a
commit whose declared content root disagrees with the manifest must be refused.

The one that actually models the reported case is worth building deliberately:
upload half a file, **change the content**, resume, and assert the commit is
refused. Every part passes its own digest in that scenario — which is precisely
why a suite that only checks per-part integrity would report the splice as a
success.

**The sweep needs tests it does not have**, and they are mostly about what it
must NOT remove — a directory younger than the cull age even with no manifest, a
`*.partial` for a part still arriving, a session inside its TTL. A sweep tested
only on what it deletes will pass while being far too eager, and the damage
lands on someone else's upload.

---

## Appendix: an append operation in the core

The bridge holds parts because the core cannot be appended to. If it could, four
of the nine issues above — instance affinity, the part volume, the sweep, and
the disk quota — would stop being the bridge's problem. That is a real prize, so
it is worth being precise about the price.

### What the write path actually is

```
chunk ──▶ CompressStream (zlib deflate) ──▶ EncryptStream (AES-256-GCM) ──▶ ofstream
```

Both are **stateful, sequential** codecs, and the encryption is the binding
constraint:

- **AES-256-GCM emits `[IV ‖ ciphertext ‖ tag]`, and the tag is computed at
  `finish()` over the entire message.** You cannot append to a finished GCM
  stream — the tag would no longer authenticate. And you cannot compute the tag
  for part *n* without having processed parts *0…n-1*, in order. GCM's
  *encryption* is counter mode and would be seekable; its *authentication* is
  not.
- **zlib deflate carries a dictionary across the whole stream**, so the same
  ordering constraint applies, and its state cannot be cheaply checkpointed
  (`Z_FULL_FLUSH` at every part boundary would make it resettable at a cost to
  the compression ratio).
- Neither an OpenSSL `EVP_CIPHER_CTX` nor a zlib `z_stream` is serialisable, so
  **codec state cannot be persisted**. An upload in progress cannot survive a
  core restart unless the parts themselves are kept.

This is the crux, and it is not incidental: **appending to this format is
inherently ordered, while resumable upload is inherently unordered.** Retrying
one part, sending parts in parallel, filling a gap — all of it assumes parts are
independent. The storage format says they are not.

### The three shapes an append could take

**A — the core buffers parts and assembles at commit.**
`BeginUpload` / `AppendPart(index, bytes)` / `CommitUpload` / `AbortUpload` /
`UploadStatus`. Parts are stored as separate files under a pending version and
streamed through the pipeline once, at commit.

| Pros | Cons |
|---|---|
| Any bridge instance can serve any part — Issue 1 dissolves | It is the bridge design relocated: same disk, same sweep, same quota, now in the core |
| Storage lifecycle is owned by the component that owns storage | Proto change, 4 consumers, core release |
| Out-of-order and parallel parts work | A "pending version" concept the DB does not have, with its own GC |
| Survives a core restart (parts are on disk) | Makes Issue 7 (non-atomic writes) more pressing, not less |

**B — strictly-ordered streaming append.**
The core keeps the compress/encrypt pipeline open and appends each part into it
as it arrives.

| Pros | Cons |
|---|---|
| The only shape that genuinely removes intermediate storage — nothing is ever staged | Parts must arrive **in order**: no parallelism, and one slow retry stalls everything behind it |
| Commit is free — the stream is already written | Cannot survive a core restart: the GCM/zlib state is unserialisable, so a bounce loses every in-flight upload |
| | Holds an `EVP_CIPHER_CTX`, a `z_stream` and an open fd per in-flight upload, for the life of the transfer |
| | Resume after a client disconnect needs the core to hold that state on a TTL — memory pinned by idle uploads |

**C — per-part sealed blocks.**
Each part is independently compressed and encrypted, and the stored object
becomes a container of blocks rather than one stream.

| Pros | Cons |
|---|---|
| Append becomes trivial, order-free and restart-safe — the constraint disappears entirely | **Changes the on-disk format.** Every existing file is one `[IV ‖ ct ‖ tag]` stream; the read path must learn a container and support both, or every file must be migrated |
| Parts are independently verifiable and independently repairable | Compression ratio drops — no dictionary shared across parts |
| This is essentially how object-store multipart already works | The largest change of the three, in the most critical component |

### Decision: not now — parts stay in the bridge

**A moves the problem rather than removing it.** The parts still have to live
somewhere, still need sweeping, still need a quota — the only thing that changes
is which component owns the directory. That buys Issue 1 and little else, and
Issue 1 can be bought far more cheaply with sticky sessions at nginx.

**B is the only shape that truly removes the staging cost**, and it pays for it
by giving up the two properties that make chunked upload worth having: parts
that are independent, and an upload that survives a restart. A resumable
uploader that cannot resume across a core bounce is a poor trade.

**C is, honestly, the technically right long-term answer** — it is what object
stores do, and it makes every problem in this document go away. It is also a
storage-format change in the core, with a migration path for every file already
stored, to serve one door's upload ergonomics. That is disproportionate today.

**Decided: the parts stay in the bridge.** The three shapes above are recorded
so the reasoning does not have to be rebuilt, not because the question is still
open.

**Revisit when one of these becomes true**, at which point the arithmetic
changes rather than the argument:

1. **A second door needs resumable upload.** WebDAV or MCP wanting the same
   thing turns bridge-side staging from a local choice into duplication, and the
   core becomes the right home.
2. **The bridge genuinely scales out.** Sticky sessions are a workaround; if
   more than one bridge is a standing arrangement rather than a contingency,
   option A stops being a lateral move.
3. **The storage format is being changed anyway.** If C's container format is
   ever on the table for another reason — per-block repair, deduplication,
   partial reads — resumable append comes almost free alongside it, and should
   be designed in rather than retrofitted.
