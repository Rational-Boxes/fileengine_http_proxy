# FileEngine HTTP REST Proxy

A lightweight, concurrent **C++ HTTP service** that exposes the FileEngine gRPC
`FileService` (`fileengine_rpc` protocol) as a clean **JSON/REST API**, secured
against an **LDAP** directory. It is the REST sibling of the WebDAV bridge and a
thin pass-through to the gRPC core — no local database, no path cache.

- 📒 **API contract:** [`openapi.yaml`](./openapi.yaml) (OpenAPI 3.0.3, 38 operations)
- 📖 **Developer guide:** [`DEVELOPER.md`](./DEVELOPER.md)
- 🗺️ **Design & roadmap:** [`DEVELOPMENT_PLAN.md`](./DEVELOPMENT_PLAN.md)

---

## Features

- **Full FileEngine surface** over REST: directories, files, content,
  versioning, metadata, ACLs, role management, and admin (storage/sync).
- **LDAP auth** (HTTP Basic) plus **bearer tokens** with an in-process TTL cache
  so chatty clients authenticate once and skip the per-request LDAP bind.
- **OAuth2 / OIDC login** (server-side BFF flow) for Google, GitHub, Microsoft,
  LinkedIn, Atlassian, and any OIDC provider — the IdP-verified email is mapped to
  the user's LDAP roles and a bridge bearer token is issued. See
  [`OAUTH_SETUP.md`](./OAUTH_SETUP.md).
- **Multi-tenant**: tenant resolved from the host subdomain or an `X-Tenant`
  header (default `default`); a tenant's `administrators` LDAP group maps to the
  core's `system_admin` role.
- **Streaming** upload/download (chunked, no whole-file buffering) with HTTP
  **`Range`** (`206 Partial Content`).
- **Concurrent**: Poco `HTTPServer` worker thread pool over one shared,
  thread-safe gRPC channel.
- **Hardened**: structured access log (no credentials/tokens/query logged),
  request body-size cap (`413`), scoped CORS (never `*`).
- **UID-native** addressing — resources are gRPC UIDs; the filesystem root is
  `root`, the empty string, or the all-zeros UUID.

## Architecture

```
client ──HTTP/JSON──▶ http_bridge ──gRPC/HTTP2──▶ FileEngine FileService (:50051)
                        │  Poco HTTPServer (worker thread pool)
                        │  ├─ auth: LDAP Basic + bearer-token cache
                        │  ├─ tenant: host subdomain / X-Tenant
                        │  ├─ handlers: REST → gRPC translation
                        │  └─ one shared GRPCClientWrapper (channel/stub)
                        └─ LDAP directory (bind + group→role)
```

The gRPC core is the source of truth (UIDs, ACLs, versions, metadata); the
bridge forwards the LDAP-resolved identity in the trusted `AuthenticationContext`
and maps the core's allow/deny to `200`/`403`. It makes no local authorization
decisions. TLS is terminated upstream (reverse proxy / ngrok).

## Quick start

Build dependencies (Fedora): `gcc-c++ cmake grpc-devel protobuf-devel
protobuf-compiler poco-devel openldap-devel`.

```bash
# build
mkdir build && cd build && cmake .. && make -j"$(nproc)" && cd ..

# configure (a .env in the CWD is auto-loaded)
cp .env-default .env     # set FILEENGINE_GRPC_*, FILEENGINE_LDAP_*, HTTP_*

# run (listens on :8090)
./build/http_bridge
```

```bash
# use it
B=http://localhost:8090; A=(-u alice:secret); ROOT=00000000-0000-0000-0000-000000000000
DIR=$(curl -s "${A[@]}" -X POST $B/v1/dirs/$ROOT -d '{"name":"project"}' | jq -r .uid)
FILE=$(curl -s "${A[@]}" -X POST $B/v1/dirs/$DIR/files -d '{"name":"notes.txt"}' | jq -r .uid)
curl -s "${A[@]}" -X PUT $B/v1/files/$FILE/content --data-binary 'hello'
curl -s "${A[@]}"        $B/v1/files/$FILE/content        # hello
```

## API overview

All routes are under `/v1` (except health); see [`openapi.yaml`](./openapi.yaml)
for full schemas.

| Area | Endpoints |
|---|---|
| Auth | `POST/DELETE /v1/auth/token`, `GET /v1/auth/oauth/{provider}[/callback]`, `GET /v1/whoami` |
| Directories | `POST/GET/DELETE /v1/dirs/{uid}`, `POST /v1/dirs/{uid}/files` |
| Nodes | `GET /v1/nodes/{uid}` (stat), `/exists`, `/rename`, `/move`, `/copy` |
| Content | `GET/PUT /v1/files/{uid}/content` (stream + `Range`), `DELETE /v1/files/{uid}`, `/undelete` |
| Versioning | `GET /v1/files/{uid}/versions[/{ts}]`, `/restore`, `/purge` |
| Metadata | `GET /v1/nodes/{uid}/metadata`, `GET/PUT/DELETE …/metadata/{key}` |
| ACL | `GET/POST/DELETE /v1/nodes/{uid}/permissions` |
| Roles | `GET/POST /v1/roles`, `…/{role}`, `…/{role}/users[/{user}]`, `/v1/users/{user}/roles` |
| Principals | `GET /v1/principals?q=&types=role,claim,user&limit=` (ACL-editor type-ahead) |
| Admin | `GET /v1/storage`, `POST /v1/sync` |
| Health | `GET /healthz`, `GET /readyz`, `GET /poolz` (on the monitoring port) |

Errors are `{"error": "..."}` with the mapped status (`400/401/403/404/409/413/503`).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HTTP_HOST` / `HTTP_PORT` | `0.0.0.0` / `8090` | listen address |
| `HTTP_THREAD_POOL` | `16` | worker threads on a dedicated, correctly-sized pool (not Poco's 16-capped `defaultPool`) |
| `HTTP_MONITORING_PORT` | `8091` | dedicated reporter listener for `/healthz` `/readyz` `/poolz`; one worker is held back for it so reporting stays responsive under load |
| `TOKEN_TTL_SECONDS` | `3600` | bearer-token lifetime |
| `HTTP_MAX_BODY_BYTES` | `104857600` | request-body cap |
| `HTTP_CORS_ORIGIN` | _(empty)_ | scoped CORS origin (empty = off) |
| `FILEENGINE_GRPC_HOST` / `_PORT` | `localhost` / `50051` | core gRPC server |
| `FILEENGINE_LDAP_*` | — | LDAP endpoint / domain / bind / bases |

## Testing

`tests/test_e2e.sh` is a curl-driven end-to-end suite (66 checks) run against a
live bridge + gRPC core + LDAP — the regression gate for every change:

```bash
BASE=http://localhost:8090 ./tests/test_e2e.sh
```

It covers health, LDAP + token auth, the filesystem round-trip, streaming +
`Range`, versioning, metadata, ACL (grant/check/revoke, role principals, DENY
precedence), role management, principal type-ahead, admin, and hardening.

## Project layout

```
http_bridge/
├── CMakeLists.txt        # Poco, gRPC, Protobuf(module), OpenLDAP(find_library)
├── proto/fileservice.proto
├── include/  src/
│   ├── http_server.*     # Poco server, router, handlers, auth middleware
│   ├── token_store.h     # in-process TTL bearer-token cache
│   ├── grpc_client_wrapper.*   # canonical fileengine_rpc wrapper (+ streaming)
│   ├── ldap_authenticator.*    # LDAP bind + group→role
│   └── utils.*
├── tests/test_e2e.sh     # curl E2E suite
├── openapi.yaml · DEVELOPER.md · DEVELOPMENT_PLAN.md
└── .env-default
```

## Status

Feature-complete against the development plan (Phases 0–6): health, auth,
filesystem, versioning, metadata, ACL, roles, admin, token auth, streaming, and
hardening — all built test-first and green. Reuses the proven gRPC wrapper and
LDAP authenticator from the WebDAV bridge.

## License

Copyright (C) 2026 James Hickman <james@rationalboxes.com>

This project is licensed under the **GNU General Public License, version 3 (or
later)** — see the [LICENSE](LICENSE) file for the full text.
