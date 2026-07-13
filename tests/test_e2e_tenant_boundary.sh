#!/bin/bash
# End-to-end tenant-boundary test for the HTTP bridge (security review H2 + M3).
#
# Verifies that a TENANT admin (admin of exactly one tenant) cannot cross into a
# tenant they are not a member of — on both the Basic and Bearer paths — while a
# multi-tenant member still reaches every tenant they belong to. Also asserts the
# tenant admin is NOT stamped the global `system_admin` role (H2).
#
# Requires two directory identities (defaults match the dev fixture):
#   TA_USER / TA_PASS       — admin of exactly TA_TENANT, NOT a member of FOREIGN_TENANT
#   BOTH_USER / BOTH_PASS   — member of BOTH TA_TENANT and FOREIGN_TENANT
#
# Usage:
#   BASE=http://localhost:8090 \
#   TA_USER=james@rationalboxes.com TA_PASS='***' TA_TENANT=filenginetest \
#   FOREIGN_TENANT=default \
#   BOTH_USER=testuser@rationalboxes.com BOTH_PASS='***' \
#   ./tests/test_e2e_tenant_boundary.sh
set -u
BASE="${BASE:-http://localhost:8090}"
TA_USER="${TA_USER:-james@rationalboxes.com}"
TA_PASS="${TA_PASS:-}"
TA_TENANT="${TA_TENANT:-filenginetest}"
FOREIGN_TENANT="${FOREIGN_TENANT:-default}"
BOTH_USER="${BOTH_USER:-testuser@rationalboxes.com}"
BOTH_PASS="${BOTH_PASS:-}"
ROOT_UID="00000000-0000-0000-0000-000000000000"
PASS=0; FAIL=0
code(){ curl -s -o /tmp/tb_body -w '%{http_code}' "$@"; }
chk(){ if [ "$2" = "$1" ]; then printf '  \033[32m✓\033[0m %s (-> %s)\n' "$3" "$2"; PASS=$((PASS+1));
       else printf '  \033[31m✗\033[0m %s (want %s got %s)\n' "$3" "$1" "$2"; FAIL=$((FAIL+1)); fi; }

if ! curl -sf -o /dev/null --max-time 3 "$BASE/healthz" 2>/dev/null && \
   ! curl -sf -o /dev/null --max-time 3 "${BASE%/*}/healthz" 2>/dev/null; then
    # health lives on the monitoring port; fall back to an unauth 401 probe
    curl -s -o /dev/null --max-time 3 "$BASE/v1/whoami" >/dev/null 2>&1 || { echo "SKIP: bridge not reachable at $BASE"; exit 0; }
fi
if [ -z "$TA_PASS" ] || [ -z "$BOTH_PASS" ]; then echo "SKIP: set TA_PASS and BOTH_PASS"; exit 0; fi

echo "=== tenant boundary: $TA_USER is admin of '$TA_TENANT' only ==="
c=$(code -u "$TA_USER:$TA_PASS" -H "X-Tenant: $TA_TENANT" "$BASE/v1/whoami")
chk 200 "$c" "tenant admin reaches OWN tenant ($TA_TENANT)"
if grep -q '"system_admin"' /tmp/tb_body; then
    printf '  \033[31m✗\033[0m tenant admin must NOT hold system_admin (H2)\n'; FAIL=$((FAIL+1))
else
    printf '  \033[32m✓\033[0m tenant admin is not global system_admin (H2)\n'; PASS=$((PASS+1))
fi

echo "=== cross-tenant must be blocked (Basic) ==="
chk 403 "$(code -u "$TA_USER:$TA_PASS" -H "X-Tenant: $FOREIGN_TENANT" "$BASE/v1/whoami")" "Basic whoami into $FOREIGN_TENANT"
chk 403 "$(code -u "$TA_USER:$TA_PASS" -H "X-Tenant: $FOREIGN_TENANT" "$BASE/v1/dirs/$ROOT_UID")" "Basic list $FOREIGN_TENANT root"

echo "=== cross-tenant must be blocked (Bearer) ==="
tok=$(curl -s -u "$TA_USER:$TA_PASS" -X POST "$BASE/v1/auth/token" | grep -oE '"token":"[^"]+"' | sed 's/.*"token":"//;s/"//')
if [ -n "$tok" ]; then
    chk 200 "$(code -H "Authorization: Bearer $tok" -H "X-Tenant: $TA_TENANT" "$BASE/v1/whoami")" "Bearer whoami OWN tenant"
    chk 403 "$(code -H "Authorization: Bearer $tok" -H "X-Tenant: $FOREIGN_TENANT" "$BASE/v1/whoami")" "Bearer whoami into $FOREIGN_TENANT"
else
    printf '  \033[31m✗\033[0m could not obtain a token for %s\n' "$TA_USER"; FAIL=$((FAIL+1))
fi

echo "=== control: $BOTH_USER is a member of BOTH tenants ==="
chk 200 "$(code -u "$BOTH_USER:$BOTH_PASS" -H "X-Tenant: $TA_TENANT" "$BASE/v1/whoami")" "multi-tenant member reaches $TA_TENANT"
chk 200 "$(code -u "$BOTH_USER:$BOTH_PASS" -H "X-Tenant: $FOREIGN_TENANT" "$BASE/v1/whoami")" "multi-tenant member reaches $FOREIGN_TENANT"

echo "-----------------------------------------------------------------------"
echo " passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
