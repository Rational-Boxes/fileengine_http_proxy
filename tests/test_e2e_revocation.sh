#!/bin/bash
# End-to-end sign-out enforcement for the HTTP bridge (revoked-token denylist).
#
# Session tokens are stateless HS256 JWTs, so DELETE /v1/auth/token used to end
# nothing: it cut the WebDAV presence entry and wrote an audit record, and the
# token itself kept working — in another tab, in a script, in anything holding a
# copy — for the rest of TOKEN_TTL_SECONDS. The 204 said the session was over
# while it plainly was not.
#
# The bridge now records the revoked `jti` in the shared Redis (auth:revoked:{jti},
# expiring with the token) and refuses it. This asserts the whole loop, including
# the two properties that are easy to get quietly wrong:
#
#   * the entry is really in Redis, with a TTL bounded by the token's own life —
#     an in-process set would pass every other check here while revoking nothing
#     for any other instance;
#   * a SECOND bridge process, which never saw the logout, refuses the token too.
#     That is the whole reason the state is shared, and nothing else in the suite
#     would notice if it stopped being.
#
# Usage:
#   BASE=http://localhost:8090 FE_USER='throwaway@rationalboxes.com' \
#   FE_PASS='***' FE_TENANT=default ./tests/test_e2e_revocation.sh
#
# Optional, for the cross-instance assertions — a second bridge on another port,
# sharing this one's FILEENGINE_JWT_SECRET and Redis. Skipped when unset:
#   BASE_B=http://localhost:8190
# Optional, to assert the Redis entry directly (skipped when unset):
#   REDIS_CLI='redis-cli -a password1 --no-auth-warning'
#
# NB the user must NOT be 2FA-enrolled: this drives the password-only path, and a
# challenge response carries no token to revoke.
set -u
BASE="${BASE:-http://localhost:8090}"
BASE_B="${BASE_B:-}"
FE_USER="${FE_USER:-}"
FE_PASS="${FE_PASS:-}"
FE_TENANT="${FE_TENANT:-default}"
REDIS_CLI="${REDIS_CLI:-}"
# Must exceed AUTH_REVOCATION_CACHE_TTL_SECONDS, or a second instance is still
# entitled to honour its cached verdict and the test would be asserting a race.
CACHE_WAIT="${CACHE_WAIT:-8}"

PASS=0; FAIL=0
chk(){ if [ "$2" = "$1" ]; then printf '  \033[32m✓\033[0m %s (-> %s)\n' "$3" "$2"; PASS=$((PASS+1));
       else printf '  \033[31m✗\033[0m %s (want %s got %s)\n' "$3" "$1" "$2"; FAIL=$((FAIL+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
auth(){ code "$1/v1/whoami" -H "Authorization: Bearer $TOKEN" -H "X-Tenant: $FE_TENANT"; }

[ -n "$FE_USER" ] && [ -n "$FE_PASS" ] || { echo "SKIP: set FE_USER and FE_PASS"; exit 0; }
curl -s -o /dev/null --max-time 3 "$BASE/v1/whoami" 2>/dev/null || { echo "SKIP: bridge not reachable at $BASE"; exit 0; }

echo "=== sign-out enforcement: a revoked token stops working ==="

LOGIN=$(curl -s --max-time 15 -X POST "$BASE/v1/auth/token" \
        -H "Authorization: Basic $(printf '%s:%s' "$FE_USER" "$FE_PASS" | base64 -w0)" \
        -H "X-Tenant: $FE_TENANT")
TOKEN=$(printf '%s' "$LOGIN" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)
if [ -z "$TOKEN" ]; then
    printf '%s' "$LOGIN" | grep -q mfa_required \
        && { echo "SKIP: $FE_USER is 2FA-enrolled; this test needs the password-only path"; exit 0; }
    echo "SKIP: could not obtain a token"; exit 0
fi
JTI=$(python3 - "$TOKEN" <<'PY'
import sys, base64, json
p = sys.argv[1].split('.')[1]; p += '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p)).get('jti', ''))
PY
)

chk 200 "$(auth "$BASE")" "the fresh token is honoured"
[ -n "$REDIS_CLI" ] && chk 0 "$($REDIS_CLI EXISTS "auth:revoked:$JTI" 2>/dev/null)" "nothing on the denylist yet"

if [ -n "$BASE_B" ]; then
    chk 200 "$(auth "$BASE_B")" "a second instance honours it too"
fi

chk 204 "$(code -X DELETE "$BASE/v1/auth/token" -H "Authorization: Bearer $TOKEN")" "sign-out returns 204"

if [ -n "$REDIS_CLI" ]; then
    chk 1 "$($REDIS_CLI EXISTS "auth:revoked:$JTI" 2>/dev/null)" "the jti is on the SHARED denylist"
    TTL=$($REDIS_CLI TTL "auth:revoked:$JTI" 2>/dev/null)
    # Bounded by the token's own remaining life: the entry must expire, and must
    # not outlive the token it stands in for.
    if [ "${TTL:-0}" -gt 0 ] 2>/dev/null; then
        printf '  \033[32m✓\033[0m the entry expires with the token (TTL %ss)\n' "$TTL"; PASS=$((PASS+1))
    else
        printf '  \033[31m✗\033[0m the entry has no TTL (got %s) — it would outlive the token\n' "${TTL:-}"; FAIL=$((FAIL+1))
    fi
fi

# THE assertion. Before the denylist this was 200, and that was the whole bug.
chk 401 "$(auth "$BASE")" "the revoked token is refused"

if [ -n "$BASE_B" ]; then
    echo "  … waiting ${CACHE_WAIT}s for the second instance's cached verdict to lapse"
    sleep "$CACHE_WAIT"
    chk 401 "$(auth "$BASE_B")" "the instance that never saw the logout refuses it as well"
fi

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
