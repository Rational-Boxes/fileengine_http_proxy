#!/bin/bash
# End-to-end: a generated key:secret (scope "api") signs in to the REST door.
#
# Generated credentials -> authenticate -> session bearer with lifetime and
# renewal. The key is presented once, at POST /v1/auth/token; the session it
# returns is an ordinary bearer, renewed by POST /v1/auth/refresh only while the
# key stays live. This asserts the properties that make that safe:
#
#   * a key scoped only to another door ("webdav") is refused here;
#   * the session carries amr ["svc"], holds roles for the key's tenant ONLY, and
#     cannot be pointed at another tenant with X-Tenant;
#   * it cannot be converted into an unbound session through the SSO hand-off;
#   * REGENERATING the key (same key_id, new secret) stops the old session from
#     renewing, and the new secret signs in;
#   * REVOKING the key stops renewal too, and the key no longer signs in;
#   * in a tenant that REQUIRES 2FA, a key session is let in (no 2fa_required) —
#     the generated secret stands in for the second factor, as on WebDAV/MCP.
#
# Usage:
#   BASE=http://localhost:8090 IDM=http://localhost:8093 \
#   FE_USER='testuser@rationalboxes.com' FE_PASS='***' FE_TENANT=default \
#   FE_OTHER_TENANT=filenginetest ./tests/test_e2e_api_key.sh
#
# FE_USER must be a member of FE_TENANT; FE_OTHER_TENANT (optional) should be
# another tenant the same user belongs to, to prove the key does not reach it.
# FE_2FA_TENANT (optional) is a tenant of the user's whose policy requires 2FA.
set -u
BASE="${BASE:-http://localhost:8090}"
IDM="${IDM:-http://localhost:8093}"
FE_TENANT="${FE_TENANT:-default}"
FE_OTHER_TENANT="${FE_OTHER_TENANT:-}"
FE_2FA_TENANT="${FE_2FA_TENANT:-}"
# Skip cleanly (exit 0) when the fixture is absent, as run_e2e_suite.sh expects.
if [ -z "${FE_USER:-}" ] || [ -z "${FE_PASS:-}" ]; then
    echo "SKIP: set FE_USER and FE_PASS to run the api-key e2e."; exit 0
fi
if ! curl -s -o /dev/null --max-time 3 "$IDM/healthz"; then
    echo "SKIP: ldap_manager not reachable at $IDM."; exit 0
fi

. "$(dirname "$0")/lib_login.sh"

pass=0; fail=0
check() { if [ "$2" = "$3" ]; then echo "  PASS: $1 ($3)"; pass=$((pass+1));
          else echo "  FAIL: $1 — expected $2, got $3"; fail=$((fail+1)); fi; }
jget() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }
claim() {  # claim <jwt> <python expr over c> — decodes the payload, no verification
    printf '%s' "$1" | cut -d. -f2 | python3 -c "
import sys,json,base64
p=sys.stdin.read().strip(); p+='='*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p)); print($2)" 2>/dev/null; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
mint() {  # mint <key_id> <secret> -> body of POST /v1/auth/token
    printf 'user = "%s:%s"\n' "$1" "$2" |
        curl -s -K - -H "X-Tenant: $FE_TENANT" -X POST "$BASE/v1/auth/token"; }

echo "0. Sign in as $FE_USER (to manage credentials)"
USER_TOK=$(fe_login "$FE_USER" "$FE_PASS" "$FE_TENANT") || { echo "login failed"; exit 1; }
AUTH=(-H "Authorization: Bearer $USER_TOK" -H "X-Tenant: $FE_TENANT")
new_cred() {
    curl -s "${AUTH[@]}" -H 'Content-Type: application/json' \
         -d "{\"label\":\"e2e-api-key\",\"scopes\":$1}" "$IDM/v1/me/service-credentials"; }

echo "1. A webdav-only key is refused at the REST door"
R=$(new_cred '["webdav"]'); DAV_KEY=$(printf '%s' "$R" | jget key_id); DAV_SEC=$(printf '%s' "$R" | jget secret)
check "webdav-scoped key -> 401" 401 "$(printf 'user = "%s:%s"\n' "$DAV_KEY" "$DAV_SEC" |
      curl -s -o /dev/null -w '%{http_code}' -K - -H "X-Tenant: $FE_TENANT" -X POST "$BASE/v1/auth/token")"
curl -s -o /dev/null "${AUTH[@]}" -X DELETE "$IDM/v1/me/service-credentials/$DAV_KEY"

echo "2. An api key signs in and gets a session bearer"
R=$(new_cred '["api"]'); KEY=$(printf '%s' "$R" | jget key_id); SEC=$(printf '%s' "$R" | jget secret)
check "credential created with scope api" "['api']" "$(printf '%s' "$R" | jget scopes)"
T1=$(mint "$KEY" "$SEC" | jget token)
check "token issued" yes "$([ -n "$T1" ] && echo yes || echo no)"
check "amr is [svc]" "['svc']" "$(claim "$T1" "c.get('amr')")"
check "skid is the key" "$KEY" "$(claim "$T1" "c.get('skid')")"
check "skname is the key's label" "e2e-api-key" "$(claim "$T1" "c.get('skname')")"
check "roles hold the key's tenant only" "['$FE_TENANT']" "$(claim "$T1" "sorted(c.get('roles',{}))")"
check "whoami with the bearer" 200 "$(code -H "Authorization: Bearer $T1" "$BASE/v1/whoami")"
check "wrong secret -> 401" 401 "$(printf 'user = "%s:%s"\n' "$KEY" "${SEC}x" |
      curl -s -o /dev/null -w '%{http_code}' -K - -H "X-Tenant: $FE_TENANT" -X POST "$BASE/v1/auth/token")"
check "key id with an EMPTY secret -> 401" 401 "$(printf 'user = "%s:"\n' "$KEY" |
      curl -s -o /dev/null -w '%{http_code}' -K - -H "X-Tenant: $FE_TENANT" -X POST "$BASE/v1/auth/token")"
if [ -n "$FE_OTHER_TENANT" ]; then
    check "X-Tenant to another of the user's tenants -> 403" 403 \
          "$(code -H "Authorization: Bearer $T1" -H "X-Tenant: $FE_OTHER_TENANT" "$BASE/v1/whoami")"
    check "minting in another tenant -> 401" 401 "$(printf 'user = "%s:%s"\n' "$KEY" "$SEC" |
          curl -s -o /dev/null -w '%{http_code}' -K - -H "X-Tenant: $FE_OTHER_TENANT" -X POST "$BASE/v1/auth/token")"
else
    echo "  SKIP: cross-tenant checks (FE_OTHER_TENANT unset)"
fi
check "SSO hand-off refused for a key session" 403 \
      "$(code -H "Authorization: Bearer $T1" -X POST "$BASE/v1/auth/sso/handoff")"

echo "3. Refresh renews while the key is live"
T2=$(curl -s -H "Authorization: Bearer $T1" -X POST "$BASE/v1/auth/refresh" | jget token)
check "refresh issued a token" yes "$([ -n "$T2" ] && echo yes || echo no)"
check "refreshed token keeps the key binding" "$KEY" "$(claim "$T2" "c.get('skid')")"
check "refreshed token carries the label" "e2e-api-key" "$(claim "$T2" "c.get('skname')")"
check "refreshed token keeps amr [svc]" "['svc']" "$(claim "$T2" "c.get('amr')")"

echo "4. Regenerating the key ends renewal of the old session"
R=$(curl -s "${AUTH[@]}" -H 'Content-Type: application/json' -d '{}' \
         -X POST "$IDM/v1/me/service-credentials/$KEY/rotate")
SEC2=$(printf '%s' "$R" | jget secret)
check "refresh after regenerate -> 401" 401 "$(code -H "Authorization: Bearer $T2" -X POST "$BASE/v1/auth/refresh")"
check "old secret -> 401" 401 "$(printf 'user = "%s:%s"\n' "$KEY" "$SEC" |
      curl -s -o /dev/null -w '%{http_code}' -K - -H "X-Tenant: $FE_TENANT" -X POST "$BASE/v1/auth/token")"
T3=$(mint "$KEY" "$SEC2" | jget token)
check "new secret signs in" yes "$([ -n "$T3" ] && echo yes || echo no)"

echo "5. Revoking the key ends renewal, and the key no longer signs in"
curl -s -o /dev/null "${AUTH[@]}" -X DELETE "$IDM/v1/me/service-credentials/$KEY"
check "refresh after revoke -> 401" 401 "$(code -H "Authorization: Bearer $T3" -X POST "$BASE/v1/auth/refresh")"
check "revoked key -> 401" 401 "$(printf 'user = "%s:%s"\n' "$KEY" "$SEC2" |
      curl -s -o /dev/null -w '%{http_code}' -K - -H "X-Tenant: $FE_TENANT" -X POST "$BASE/v1/auth/token")"

echo "6. Sign-out of a key session revokes it like any other"
R=$(new_cred '["api"]'); K4=$(printf '%s' "$R" | jget key_id); S4=$(printf '%s' "$R" | jget secret)
T4=$(mint "$K4" "$S4" | jget token)
check "sign-out -> 204" 204 "$(code -H "Authorization: Bearer $T4" -X DELETE "$BASE/v1/auth/token")"
check "signed-out token -> 401" 401 "$(code -H "Authorization: Bearer $T4" "$BASE/v1/whoami")"
curl -s -o /dev/null "${AUTH[@]}" -X DELETE "$IDM/v1/me/service-credentials/$K4"

echo "7. A key session is admitted in a tenant that requires 2FA"
if [ -n "$FE_2FA_TENANT" ]; then
    T2FA_USER=$(fe_login "$FE_USER" "$FE_PASS" "$FE_2FA_TENANT") || T2FA_USER=""
    check "2FA login in $FE_2FA_TENANT (to make the key)" yes "$([ -n "$T2FA_USER" ] && echo yes || echo no)"
    R=$(curl -s -H "Authorization: Bearer $T2FA_USER" -H "X-Tenant: $FE_2FA_TENANT" \
             -H 'Content-Type: application/json' -d '{"label":"e2e-api-key-2fa","scopes":["api"]}' \
             "$IDM/v1/me/service-credentials")
    K5=$(printf '%s' "$R" | jget key_id); S5=$(printf '%s' "$R" | jget secret)
    R=$(printf 'user = "%s:%s"\n' "$K5" "$S5" |
        curl -s -K - -H "X-Tenant: $FE_2FA_TENANT" -X POST "$BASE/v1/auth/token")
    T5=$(printf '%s' "$R" | jget token)
    check "no MFA challenge for a key" "" "$(printf '%s' "$R" | jget mfa_token)"
    check "key session passes the tenant's 2FA gate" 200 \
          "$(code -H "Authorization: Bearer $T5" "$BASE/v1/dirs/root")"
    curl -s -o /dev/null -H "Authorization: Bearer $T2FA_USER" -H "X-Tenant: $FE_2FA_TENANT" \
         -X DELETE "$IDM/v1/me/service-credentials/$K5"
else
    echo "  SKIP: 2FA-tenant check (FE_2FA_TENANT unset)"
fi

echo
echo "api key e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
