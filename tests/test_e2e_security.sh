#!/bin/bash
# Security-focused end-to-end tests for the FileEngine HTTP REST bridge.
#
# These encode the SECURE expectation for the auth-boundary findings from the
# 2026-07 security review. Some are regression guards for behavior that is
# already correct (unauthenticated reject, JWT tamper/alg-none over the wire);
# others are "verifying tests" for confirmed vulnerabilities and will FAIL until
# the corresponding fix lands — each such case is tagged  [EXPECT-FAIL-UNTIL-FIX].
#
# Assumes the bridge is running (default http://localhost:8090) with a live gRPC
# core + LDAP. If the bridge is unreachable the suite SKIPs (exit 0) so it is
# safe to wire into CI before the stack is guaranteed up.
#
# Usage: BASE=http://localhost:8090 \
#        FE_USER=<non-admin login> FE_PASS=<password> [FE_EXPECT_USER=<uid>] \
#        [FE_VICTIM=<a known other username>] \
#        ./tests/test_e2e_security.sh
set -u
BASE="${BASE:-http://localhost:8090}"
FE_USER="${FE_USER:-testuser}"
FE_PASS="${FE_PASS:-password}"
CRED="${FE_USER}:${FE_PASS}"
EXPECT_USER="${FE_EXPECT_USER:-${FE_USER}}"
VICTIM="${FE_VICTIM:-admin}"
PASS=0; FAIL=0; XFAIL=0; FAILED=()
ok()    { PASS=$((PASS+1));  printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()   { FAIL=$((FAIL+1));  FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }
xfail() { XFAIL=$((XFAIL+1)); printf '  \033[33m⚠ EXPECTED-FAIL (fix pending)\033[0m %s\n     %s\n' "$1" "${2:-}"; }

echo "=========================================================="
echo " FileEngine HTTP bridge — SECURITY E2E   base=$BASE"
echo "=========================================================="

# ---- preflight: skip cleanly if the bridge isn't up ----
if ! curl -sf -o /dev/null --max-time 3 "$BASE/healthz"; then
    echo "SKIP: bridge not reachable at $BASE (start the stack to run these)."
    exit 0
fi

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
b64url() { printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=\n'; }
code_for() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# ---- C2: empty-password LDAP bind must NOT authenticate ------------------
# Authorization: Basic base64("<victim>:")  (empty password → LDAP unauthenticated bind)
echo "[C2] empty-password bind must be rejected"
emptyauth=$(b64 "${VICTIM}:")
code=$(code_for -H "Authorization: Basic ${emptyauth}" -X POST "$BASE/v1/auth/token")
if [ "$code" = "401" ]; then ok "empty password -> 401 (rejected)"
else xfail "empty password should be 401, got $code (finding C2: add empty-password guard before ldap bind)" ; fi

# also via a normal resource endpoint
code=$(code_for -H "Authorization: Basic ${emptyauth}" "$BASE/v1/whoami")
if [ "$code" = "401" ]; then ok "whoami with empty password -> 401"
else xfail "whoami empty password should be 401, got $code (C2)"; fi

# ---- baseline: unauthenticated access is rejected (regression guard) -----
echo "[auth] unauthenticated requests rejected"
code=$(code_for "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "whoami without creds -> 401" || bad "whoami no creds -> 401" "got $code"

# get a real token for the (non-admin) test user
tokresp=$(curl -s -u "$CRED" -X POST "$BASE/v1/auth/token")
TOKEN=$(grep -oE '"token":"[^"]+"' <<<"$tokresp" | sed 's/.*"token":"//;s/"//')
if [ -z "$TOKEN" ]; then bad "could not obtain token for $FE_USER" "$tokresp"; fi

# ---- C1: a non-admin must NOT be able to self-assign system_admin --------
# Under the trust model the bridge is the admin-gate; the core trusts callers.
echo "[C1] role self-escalation must be forbidden for non-admins"
if [ -n "$TOKEN" ]; then
    code=$(code_for -H "Authorization: Bearer $TOKEN" -X PUT \
                    "$BASE/v1/roles/system_admin/users/${EXPECT_USER}")
    if [ "$code" = "403" ] || [ "$code" = "404" ]; then
        ok "PUT self into system_admin -> $code (denied)"
    else
        xfail "self-assign system_admin returned $code, expected 403 (finding C1: bridge role endpoints need an admin gate)"
    fi
    # createRole should likewise be admin-only
    code=$(code_for -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
                    -d '{"role":"pwn"}' -X POST "$BASE/v1/roles")
    if [ "$code" = "403" ] || [ "$code" = "404" ]; then ok "createRole as non-admin -> $code (denied)"
    else xfail "createRole as non-admin returned $code, expected 403 (C1)"; fi
fi

# ---- JWT integrity over the wire (regression guards) ---------------------
echo "[jwt] forged/tampered bearer tokens rejected"
if [ -n "$TOKEN" ]; then
    # tamper: flip the last char of the signature segment
    tampered="${TOKEN%?}$( [ "${TOKEN: -1}" = "A" ] && echo B || echo A )"
    code=$(code_for -H "Authorization: Bearer $tampered" "$BASE/v1/whoami")
    [ "$code" = "401" ] && ok "tampered signature -> 401" || bad "tampered token -> 401" "got $code"

    # alg:none unsigned token with an escalated payload
    h=$(b64url '{"alg":"none","typ":"JWT"}')
    p=$(b64url '{"sub":"attacker","tenant":"default","roles":{"default":["system_admin"]},"exp":9999999999}')
    none_tok="${h}.${p}."
    code=$(code_for -H "Authorization: Bearer $none_tok" "$BASE/v1/whoami")
    [ "$code" = "401" ] && ok "alg:none token -> 401" || bad "alg:none token -> 401" "got $code"
fi

# ---- M3: X-Tenant must not grant another tenant's privileges -------------
# A non-admin picking a foreign tenant must not gain roles there (empty roles
# => core denies writes). We assert a privileged write to a foreign tenant root
# is denied. (Read-by-default may still surface default-readable nodes — see M3.)
echo "[M3] foreign X-Tenant confers no privilege"
if [ -n "$TOKEN" ]; then
    code=$(code_for -H "Authorization: Bearer $TOKEN" -H 'X-Tenant: some-other-tenant' \
                    -H 'Content-Type: application/json' -d '{"name":"x"}' \
                    -X POST "$BASE/v1/dirs/")
    if [ "$code" = "403" ] || [ "$code" = "404" ]; then ok "write to foreign tenant root -> $code (denied)"
    else bad "write to foreign tenant -> denied" "got $code (review M3 tenant-membership check)"; fi
fi

echo "----------------------------------------------------------"
echo " passed=$PASS  failed=$FAIL  expected-fail(fix pending)=$XFAIL"
for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "   FAIL: $f"; done
# Expected-fails do not fail the run (they track known-open findings); real
# regressions (bad) do.
[ "$FAIL" -eq 0 ]
