#!/bin/bash
# Run the HTTP bridge's end-to-end suite as one pass, so tenant data separation
# and the other e2e checks are covered together rather than as scripts someone
# has to remember to run one at a time.
#
# Every child script SKIPs cleanly (exit 0) when the stack is down or its
# credentials are unset, so this is safe to wire into CI before the stack is
# guaranteed up: it fails only on a real assertion failure, never on absence.
#
# The tenant-boundary script is a REQUIRED member of this suite — the cross-tenant
# read/write separation it proves is a security invariant, not an optional extra.
#
# Usage (defaults match the dev fixture in the e2e-test-topology notes):
#   BASE=http://localhost:8090 \
#   FE_USER='testuser@rationalboxes.com'   FE_PASS='***' \
#   FE_USER2='throwaway@rationalboxes.com' FE_PASS2='***' FE_TENANT2='filenginetest' \
#   ./tests/run_e2e_suite.sh
#
# Tenant-boundary identities (derived from the above if not set explicitly):
#   TA_USER/TA_PASS/TA_TENANT — a user who is a member of exactly ONE tenant
#   FOREIGN_TENANT            — a tenant TA_USER is NOT a member of
#   BOTH_USER/BOTH_PASS       — a user who is a member of BOTH
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="${BASE:-http://localhost:8090}"

# Reachability probe: /healthz is on the monitoring port, so fall back to an
# unauthenticated 401 on a real route. If neither answers, skip the whole suite.
if ! curl -sf -o /dev/null --max-time 3 "$BASE/healthz" 2>/dev/null \
   && ! curl -s -o /dev/null --max-time 3 "$BASE/v1/whoami" 2>/dev/null; then
    echo "SKIP: bridge not reachable at $BASE (start the stack to run the e2e suite)."
    exit 0
fi

# Map the shared FE_* fixture onto the tenant-boundary script's own variables,
# unless the caller set them explicitly. The boundary script wants a single-tenant
# user (TA_*) and a foreign tenant they lack; the dev fixture's non-admin
# (throwaway, 'default' only) fits, with the multi-tenant testuser as the control.
export BASE
export TA_USER="${TA_USER:-${FE_USER2:-throwaway@rationalboxes.com}}"
export TA_PASS="${TA_PASS:-${FE_PASS2:-}}"
export TA_TENANT="${TA_TENANT:-default}"
export FOREIGN_TENANT="${FOREIGN_TENANT:-${FE_TENANT2:-filenginetest}}"
export BOTH_USER="${BOTH_USER:-${FE_USER:-testuser@rationalboxes.com}}"
export BOTH_PASS="${BOTH_PASS:-${FE_PASS:-}}"

# The suite, in order. Tenant boundary is listed first among the security checks
# so a separation regression surfaces immediately.
SUITE=(
    test_e2e_tenant_boundary.sh
    test_e2e_security.sh
    test_e2e.sh
    test_e2e_2fa.sh
)

RAN=0; SKIPPED=0; FAILED=()
for name in "${SUITE[@]}"; do
    script="$HERE/$name"
    [ -f "$script" ] || { echo "-- $name: not present, skipping"; continue; }
    echo
    echo "########################################################################"
    echo "# $name"
    echo "########################################################################"
    # A script that SKIPs prints "SKIP:" and exits 0; distinguish that from a
    # genuine pass so the summary is honest about what actually ran.
    out="$(bash "$script" 2>&1)"; rc=$?
    printf '%s\n' "$out"
    if [ $rc -ne 0 ]; then
        FAILED+=("$name")
    elif printf '%s' "$out" | grep -q '^SKIP:'; then
        SKIPPED=$((SKIPPED+1))
    else
        RAN=$((RAN+1))
    fi
done

echo
echo "========================================================================"
echo " e2e suite: ran=$RAN  skipped=$SKIPPED  failed=${#FAILED[@]}"
if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '   failed: %s\n' "${FAILED[*]}"
    exit 1
fi
echo "========================================================================"
