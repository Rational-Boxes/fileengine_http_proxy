# FileEngine HTTP REST Bridge — Developer Guide

A lightweight, concurrent C++ service that exposes the FileEngine gRPC
`FileService` (`fileengine_rpc`) as a JSON/REST API, secured by LDAP. It is the
REST sibling of the WebDAV bridge and reuses its gRPC wrapper, LDAP
authenticator, and utilities.

The machine-readable API contract is **[`openapi.yaml`](./openapi.yaml)**
(OpenAPI 3.0.3, 38 operations). The design and roadmap are in
[`DEVELOPMENT_PLAN.md`](./DEVELOPMENT_PLAN.md).

---

## Build

Dependencies (Fedora package names): `gcc-c++`, `cmake`, `grpc-devel`,
`protobuf-devel`, `protobuf-compiler`, `poco-devel`, `openldap-devel`.

```bash
mkdir build && cd build
cmake ..        # Protobuf module mode; OpenLDAP via find_library (no .pc on Fedora)
make -j"$(nproc)"
```

Produces a single `http_bridge` binary.

## Run

Config is read from environment variables (a `.env` in the working directory is
auto-loaded; copy `.env-default`). Key settings:

| Variable | Default | Meaning |
|---|---|---|
| `HTTP_HOST` / `HTTP_PORT` | `0.0.0.0` / `8090` | listen address |
| `HTTP_THREAD_POOL` | `16` | worker threads (concurrency) |
| `TOKEN_TTL_SECONDS` | `3600` | bearer-token lifetime |
| `HTTP_MAX_BODY_BYTES` | `104857600` | request-body cap (413 above) |
| `HTTP_CORS_ORIGIN` | _(empty)_ | scoped CORS origin; empty = no CORS |
| `FILEENGINE_GRPC_HOST` / `_PORT` | `localhost` / `50051` | core gRPC server |
| `FILEENGINE_LDAP_*` | — | LDAP endpoint / domain / bind DN+pw / bases |

```bash
./build/http_bridge        # logs to console; access log: "METHOD path -> status (Nms)"
```

TLS is terminated upstream (reverse proxy / ngrok); the bridge speaks plain
HTTP on the trusted side.

---

## Concurrency model

Poco `HTTPServer` services each connection on a worker-pool thread. One shared,
thread-safe gRPC channel/stub multiplexes all RPCs over HTTP/2. A bearer-token
cache lets chatty clients authenticate once and skip the per-request LDAP bind.
The token store is in-process (single instance); horizontal scaling would move
it to a shared store.

---

## Authentication & tenancy

Every `/v1` route (except issuing a token) requires:

- **HTTP Basic** — `Authorization: Basic <base64 user:pass>` → LDAP bind, or
- **Bearer** — `Authorization: Bearer <token>` from `POST /v1/auth/token`.

```bash
# Basic
curl -u alice:secret http://localhost:8090/v1/whoami

# Token (one LDAP bind, then reuse)
TOKEN=$(curl -s -u alice:secret -X POST http://localhost:8090/v1/auth/token | jq -r .token)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8090/v1/whoami
```

**Tenant** is resolved from the host subdomain (`acme.example.com → acme`) or an
`X-Tenant` header, defaulting to `default`. A member of a tenant's
`administrators` LDAP group is granted the core's `system_admin` role (root-level
create + ACL bypass).

The filesystem **root** is addressed as `root`, the empty string, or the
all-zeros UUID `00000000-0000-0000-0000-000000000000`.

---

## API at a glance

All paths are under `/v1`; UIDs are in the path; bodies/responses are JSON
except file content (raw bytes). See `openapi.yaml` for full schemas.

| Area | Endpoints |
|---|---|
| Auth | `POST/DELETE /auth/token`, `GET /whoami` |
| Directories | `POST/GET/DELETE /dirs/{uid}` (`?deleted=true`), `POST /dirs/{uid}/files` |
| Nodes | `GET /nodes/{uid}` (stat), `GET /nodes/{uid}/exists`, `POST /nodes/{uid}/rename\|move\|copy` |
| File content | `GET/PUT /files/{uid}/content` (streamed; GET honors `Range`), `DELETE /files/{uid}`, `POST /files/{uid}/undelete` |
| Versioning | `GET /files/{uid}/versions`, `GET …/versions/{ts}`, `POST …/restore`, `POST …/purge` |
| Metadata | `GET /nodes/{uid}/metadata`, `GET/PUT/DELETE …/metadata/{key}` |
| ACL | `GET /nodes/{uid}/permissions?user=&permission=&roles=`, `POST/DELETE …/permissions` |
| Roles | `GET/POST /roles`, `DELETE /roles/{role}`, `GET /roles/{role}/users`, `PUT/DELETE /roles/{role}/users/{user}`, `GET /users/{user}/roles` |
| Admin | `GET /storage`, `POST /sync` |
| Health | `GET /healthz`, `GET /readyz` |

### Conventions

- **Success**: `200` (body), `201` (created, returns `{uid}`/`{role}`),
  `204` (no body), `206` (partial content for `Range`).
- **Errors**: `{"error": "..."}` with `400` (bad input), `401` (unauthenticated),
  `403` (core permission denied), `404` (not found), `409` (conflict, e.g.
  copy/move into own subtree), `413` (body too large), `503` (backend down).
- **Permissions**: letters (`r w x d l u v b s m i`) or enum names; `effect`
  is `allow` (default) or `deny`; prefix a principal with `role:` to target a role.

### Example: create → write → read → list

```bash
B=http://localhost:8090; A=(-u alice:secret); ROOT=00000000-0000-0000-0000-000000000000
DIR=$(curl -s "${A[@]}" -X POST $B/v1/dirs/$ROOT -d '{"name":"project"}' | jq -r .uid)
FILE=$(curl -s "${A[@]}" -X POST $B/v1/dirs/$DIR/files -d '{"name":"notes.txt"}' | jq -r .uid)
curl -s "${A[@]}" -X PUT  $B/v1/files/$FILE/content --data-binary 'hello'
curl -s "${A[@]}"        $B/v1/files/$FILE/content          # -> hello
curl -s "${A[@]}"        $B/v1/dirs/$DIR | jq               # -> {"entries":[...]}
curl -s "${A[@]}" -H 'Range: bytes=0-2' $B/v1/files/$FILE/content   # -> hel (206)
```

---

## Testing

`tests/test_e2e.sh` is a curl-driven end-to-end suite (59 checks) run against a
live bridge + gRPC core + LDAP. It is the regression gate for every change.

```bash
# with the bridge running on :8090 and a reachable core + LDAP
BASE=http://localhost:8090 ./tests/test_e2e.sh
```

It covers health, LDAP+token auth (tenant/role/failure cases), filesystem
round-trip, streaming up/download + `Range`, versioning, metadata, ACL
(grant/check/revoke, role principals, DENY precedence), role management, admin,
and hardening (CORS, body cap). The default test user is `testuser` /
`password` in the `rationalboxes` directory.

---

## Security notes

- TLS upstream; the bridge is plain HTTP on the trusted network.
- Credentials and bearer tokens are never logged (the access log records only
  method, path, status, latency — no query string or `Authorization`).
- Body size is capped (`HTTP_MAX_BODY_BYTES`); CORS, when enabled, is scoped to
  a configured origin (never `*`).
- The core gRPC service enforces all ACLs; the bridge forwards identity and maps
  allow/deny to `200`/`403` — it makes no local authorization decisions.
