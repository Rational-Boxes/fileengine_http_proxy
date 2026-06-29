# http_bridge — LDAP read-only failover

Status: **Implemented** on `feature/replica-failover`.

Part of the workspace-wide replica-failover feature (see the matching branches in
`convert_search_ai`, `mcp`, `webdav_bridge`, `file_engine_core`). The REST bridge
touches **LDAP** for authentication / role resolution / principal search; it has no
database of its own (state lives in the gRPC core).

## Topology

```
        auth (read-only bind + search)            replication (syncrepl)
clients ──────────────▶ MASTER directory (cloud) ──────────────▶ REPLICA (on-prem, localhost)
                                                                  read-only standby
```

When the master directory is unreachable the bridge fails over to the on-prem
replica so logins/lookups keep working. All LDAP use here is read-only (bind +
search), so only the endpoint fails over — nothing to gate.

## Behavior & decisions

- **Failover engages only when a replica is configured** (`FILEENGINE_LDAP_ENDPOINT_REPLICA`).
  With one directory, behavior is unchanged.
- **Lazy circuit-breaker** (`circuit_breaker.h`, header-only, clock-injectable, no
  background threads): a failed master service-bind trips it for a cooldown; during
  the cooldown the replica is used; after it the master is re-probed and resumes on
  success. Accessed only under the authenticator's existing `ldap_mutex_`.

## Configuration (env, `main.cpp`)

| Env var | Default | Meaning |
|---------|---------|---------|
| `FILEENGINE_LDAP_ENDPOINT_REPLICA` | _(unset)_ | Replica directory URI. **Setting it enables failover.** |
| `FILEENGINE_FAILOVER_COOLDOWN_S` | `30` | Cooldown before re-probing the master. |

## Mechanism

`LDAPAuthenticator::connectToLDAP()` now:
1. no replica → `connectToEndpoint(master)` (unchanged);
2. breaker says try master → `connectToEndpoint(master)`; success resets the breaker,
   failure trips it and falls through;
3. `connectToEndpoint(replica)` for the read-only fallback.

`connectToEndpoint(endpoint)` is the former connect+service-bind body, parameterized
by endpoint. Every public method already routes through `connectToLDAP()`.

## Testing

`tests/test_failover.cpp` (CTest target `failover_tests`) covers the `CircuitBreaker`
state transitions with an injected clock. The endpoint failover itself is exercised
by the live e2e against a running directory.
