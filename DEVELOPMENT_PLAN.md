# HTTP REST Bridge for FileEngine — Development Plan

**Status:** Draft · 2026-06-21

A thin, lightweight C++ HTTP service that exposes the FileEngine gRPC
`FileService` (`fileengine_rpc` protocol) as a JSON/REST API, securing every
request against the LDAP directory. It is the REST sibling of `webdav_bridge/`
and deliberately reuses that project's proven building blocks.

## Goals

- **Thin pass-through.** Map REST resources/verbs onto FileEngine gRPC calls
  with minimal logic; the gRPC core remains the source of truth (UIDs, ACLs,
  versions, metadata). No local database, no path cache.
- **LDAP-secured.** Authenticate every request against the directory; pass the
  resolved identity/roles/tenant to gRPC in the trusted `AuthenticationContext`.
- **Lightweight & concurrent.** A single small C++ binary, Poco-based HTTP
  server with a worker thread pool, sharing one gRPC channel. No framework
  bloat.
- **Multi-tenant.** Resolve the tenant from the request host (subdomain) exactly
  as the WebDAV bridge does, defaulting to `default`.

### Non-goals (v1)

WebDAV semantics, a UI, server-side path→UID resolution (the API is UID-native),
write-back caching, and TLS termination (handled by a reverse proxy / ngrok).

---

## Reuse from `webdav_bridge`

These move into a shared layer (copy now, extract a small `fileengine_common`
later):

| Component | Reused as-is | Notes |
|-----------|--------------|-------|
| `grpc_client_wrapper.{h,cpp}` | ✅ | Canonical `fileengine_rpc` wrapper (Touch/PutFile/GetFile/Stat/Copy/Move/Rename/metadata/ACL/roles/admin) |
| `ldap_authenticator.{h,cpp}` | ✅ | Real LDAP bind + group→role extraction; incl. `administrators → system_admin` mapping |
| `utils.{h,cpp}` | ✅ (mostly) | `extractTenantFromHostname` (full-label, hyphen-safe), logging, base64; drop WebDAV-only helpers |
| `proto/fileservice.proto` + generate script | ✅ | Same canonical proto |
| CMake patterns | ✅ | Protobuf **module mode**; `find_library` OpenLDAP (no `.pc` on Fedora) |

New code is just the HTTP layer + JSON (un)marshalling + routing.

---

## Architecture

```
client ──HTTP/JSON──> [http_bridge]
                         │  Poco HTTPServer (worker thread pool)
                         │  ├─ Router            (method + path -> handler)
                         │  ├─ AuthMiddleware    (LDAP bind, token cache, tenant)
                         │  ├─ Handlers          (REST -> gRPC translation)
                         │  └─ GRPCClientWrapper (one shared channel/stub)
                         ▼
                    FileEngine gRPC FileService (fileengine_rpc, :50051)
```

Request lifecycle: parse → authenticate (LDAP/token) → resolve tenant → build
`AuthenticationContext` → dispatch to handler → one gRPC call → map result to
HTTP status + JSON.

---

## Concurrency model

- **Poco `HTTPServer`** with a `ThreadPool` sized via config
  (`HTTP_THREAD_POOL`, default ~16). Each connection is serviced on a pool
  thread — the same mechanism the WebDAV bridge already uses.
- **One shared `grpc::Channel`** for the process. gRPC C++ channels and stubs
  are thread-safe and multiplex concurrent RPCs over HTTP/2, so a single wrapper
  instance is shared by all handler threads (no per-request channel setup).
- **Per-request `ClientContext`** (stack-local) carries deadlines; never shared.
- **Auth cost control:** an LDAP bind per request is expensive and serializes on
  the directory. Add a small **credential/token cache** (see Auth) with a short
  TTL and a mutex- or sharded-map guard, so hot paths skip the bind.
- **Backpressure:** bound the thread pool and set per-RPC deadlines so a slow
  gRPC core can't exhaust threads; return `503` when the pool is saturated.

Target: thousands of concurrent idle keep-alive connections, hundreds of
in-flight requests, limited mainly by the gRPC core and the LDAP server.

---

## Authentication & authorization

1. **HTTP Basic** (`Authorization: Basic`) → LDAP bind via the reused
   `LDAPAuthenticator` (real password bind, no bypass). On success it yields
   `{user, roles, tenant-from-DN-ignored}`.
2. **Tenant** comes from the host subdomain (`extractTenantFromHostname`),
   overridable by an `X-Tenant` header for non-subdomain clients; default
   `default`. (Host-driven, never the LDAP user-DN OU.)
3. **Roles** from LDAP group membership; `administrators` group →
   `system_admin` (root-level create + ACL bypass).
4. **Optional bearer tokens (v1.1):** `POST /v1/auth/token` does one LDAP bind
   and returns a short-lived opaque token (HMAC or random + server-side cache)
   carrying `{user, roles, tenant}`. Subsequent requests send
   `Authorization: Bearer <token>` and skip the LDAP round-trip. This is the
   primary concurrency lever for chatty clients.
5. The gRPC core enforces ACLs; the bridge does **no** local permission
   decisions — it forwards identity and maps the core's allow/deny to
   `200/403`.

Credentials and tokens are **never logged** (learned from the WebDAV plan's
Phase 6).

---

## REST API (v1)

Conventions: JSON bodies/responses (`application/json`); raw bytes for file
content; UIDs in the path; the filesystem root is the empty string or the
all-zeros UUID; errors are `{"error": "...", "code": "..."}` with the right
HTTP status. All paths are under `/v1`.

### Filesystem
| Method & path | gRPC | Notes |
|---|---|---|
| `GET /dirs/{uid}` | ListDirectory | `?deleted=true` → ListDirectoryWithDeleted; JSON entry list |
| `POST /dirs/{uid}` | MakeDirectory | body `{name}` → new dir uid |
| `DELETE /dirs/{uid}` | RemoveDirectory | |
| `POST /dirs/{uid}/files` | Touch | body `{name}` → new file uid |
| `POST /dirs/{uid}/upload?name=` | Touch + PutFile | raw body; one-shot create+write |
| `GET /nodes/{uid}` | Stat | JSON metadata (type/size/owner/timestamps/version) |
| `GET /nodes/{uid}/exists` | Exists | `{exists: bool}` |
| `GET /files/{uid}/content` | GetFile | raw bytes; `?version=<ts>` → GetVersion |
| `PUT /files/{uid}/content` | PutFile | raw body → new version |
| `DELETE /files/{uid}` | RemoveFile | soft delete |
| `POST /files/{uid}/undelete` | UndeleteFile | |
| `POST /nodes/{uid}/rename` | Rename | `{new_name}` |
| `POST /nodes/{uid}/move` | Move | `{destination_parent_uid}` |
| `POST /nodes/{uid}/copy` | Copy | `{destination_parent_uid}` |

### Versioning
`GET /files/{uid}/versions` (ListVersions) · `GET /files/{uid}/versions/{ts}`
(GetVersion) · `POST /files/{uid}/restore` `{version_timestamp}`
(RestoreToVersion) · `POST /files/{uid}/purge` `{keep_count}` (PurgeOldVersions).

### Metadata
`GET /nodes/{uid}/metadata` (GetAllMetadata; `?version=` → versioned) ·
`GET|PUT|DELETE /nodes/{uid}/metadata/{key}` (Get/Set/DeleteMetadata).

### Permissions / ACL
`GET /nodes/{uid}/permissions?user=&permission=` (CheckPermission) ·
`POST /nodes/{uid}/permissions` `{principal, permission, effect}` (Grant) ·
`DELETE /nodes/{uid}/permissions` `{principal, permission, effect}` (Revoke).
`permission` accepts letters (`r w x d …`) or names; `role:` principal prefix
and `effect: allow|deny` as in the CLI/clients.

### Roles (admin / system_admin)
`GET /roles` · `POST /roles {role}` · `DELETE /roles/{role}` ·
`GET /roles/{role}/users` · `PUT|DELETE /roles/{role}/users/{user}` ·
`GET /users/{user}/roles`.

### Admin & ops
`GET /storage` (GetStorageUsage) · `POST /sync` (TriggerSync) ·
`GET /healthz` (liveness) · `GET /readyz` (gRPC channel + LDAP reachable).

### Status mapping
`200/201/204` success · `400` bad JSON/args · `401` no/failed auth · `403`
core permission denied · `404` not found/`Exists=false` · `409` conflict (e.g.
copy/move into own subtree) · `502/503` gRPC unavailable/pool saturated. Map the
core's error strings, never fake a `2xx` (WebDAV plan's "fail loudly").

---

## Content & large files

- Default: buffer request/response bodies (simple, fine for typical files).
- v1.1: stream bodies over a threshold using `StreamFileUpload`/
  `StreamFileDownload` so memory doesn't scale with file size; honor `Range`
  on content GET.
- Set `Content-Type` from stored metadata when present, else
  `application/octet-stream`.

---

## Project layout & build

```
http_bridge/
├── CMakeLists.txt              # Poco, gRPC, Protobuf(module), OpenLDAP(find_library), nlohmann/json
├── proto/fileservice.proto     # canonical fileengine_rpc (+ generate script)
├── include/  src/
│   ├── grpc_client_wrapper.*   # reused
│   ├── ldap_authenticator.*    # reused
│   ├── utils.*                 # reused (trimmed)
│   ├── http_server.*           # Poco HTTPServer + ThreadPool + RequestHandlerFactory
│   ├── router.*                # method+path → handler
│   ├── auth_middleware.*       # LDAP/token + tenant resolution
│   ├── handlers/*.cpp          # fs / versions / metadata / acl / roles / admin
│   └── json.*                  # request parse + response build (nlohmann/json)
├── .env / .env-default         # GRPC host/port, LDAP, HTTP_PORT, thread pool
└── DEVELOPMENT_PLAN.md
```

Dependencies are already present on the build host from the WebDAV work (Poco,
gRPC, protobuf, OpenLDAP-devel); add header-only **nlohmann/json** (vendor under
`third_party/`).

---

## Phased implementation

| Phase | Deliverable | Accept |
|---|---|---|
| 0 | Skeleton: CMake builds; Poco HTTP server with thread pool; `/healthz`; shared gRPC channel | concurrent `curl` to `/healthz` returns 200 |
| 1 | Auth middleware (LDAP Basic) + tenant resolution + `AuthenticationContext` | 401 without creds; authenticated request reaches gRPC with right tenant/roles |
| 2 | Core filesystem endpoints (dirs, nodes, files, content up/down) | create→write→read→list→delete round-trip via curl |
| 3 | Versioning + metadata endpoints | version list/restore/purge; metadata CRUD round-trip |
| 4 | ACL + roles + admin endpoints | grant/check/revoke; role mgmt; storage/sync |
| 5 | Token auth + streaming + Range; load/concurrency test | N concurrent clients sustained; large up/down without memory blowup |
| 6 | Hardening: no credential logging, input validation, deadlines, CORS scoping, OpenAPI spec | review checklist passes; OpenAPI published |

---

## Testing

- **Integration (primary):** a `test_http.sh` curl suite mirroring the Python/JS
  client and CLI coverage — fs ops (incl. subtree-copy guard, root-UUID alias),
  versioning, metadata (incl. versioned), ACL r/w/x/d/m + allow/deny + role
  principals, roles, admin — run against a live core server (the Docker image).
- **Concurrency:** `ab`/`wrk`/`hey` for throughput and pool behaviour; assert no
  cross-request identity bleed (parallel requests as different users).
- **Multi-tenant:** subdomain/`X-Tenant` isolation (write to tenant A invisible
  in tenant B), as validated for the WebDAV bridge via ngrok.
- **Unit:** JSON marshalling, router matching, permission/effect coercion,
  `extractTenantFromHostname` edge cases.

---

## Security & ops

- TLS terminated upstream (reverse proxy / ngrok); bridge speaks plain HTTP on
  loopback. Document the trust boundary.
- Never log credentials/tokens; redact `Authorization`.
- Validate UIDs and JSON; cap body sizes; set gRPC deadlines.
- Scope CORS to configured origins (not `*`) on an authenticated API.
- Structured request logs (method, path, tenant, user, status, latency) +
  optional Prometheus metrics on a separate bind.

---

## Open questions / decisions

1. **Auth model:** Basic-only v1, or ship bearer tokens in v1 for concurrency?
   (Recommend Basic v1, tokens v1.1.)
2. **Resource addressing:** UID-only (recommended — matches the core, avoids the
   WebDAV path-cache problem), or also offer best-effort path lookups?
3. **JSON lib:** nlohmann/json (header-only, simplest) vs Poco::JSON (already
   linked). Recommend nlohmann for ergonomics.
4. **Shared code:** copy from `webdav_bridge` now, or first extract a
   `fileengine_common` library both bridges link? (Copy now, extract in Phase 6.)
5. **Packaging:** add an `http_bridge` RPM subpackage alongside the core/CLI
   packages, or ship separately?
6. **Token store** if tokens are adopted: in-process only (single instance) vs a
   shared store (Redis) for horizontal scaling.
