# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Shared E2E cleanup: really destroy what a test made.  source this file.
#
# WHY. Every suite here cleaned up with DELETE, which is the SOFT delete —
# reversible, and by design it leaves the row, the content, the versions and the
# derived copies (previews, extracted text, embeddings, diff renditions) exactly
# where they were. So each run left its files behind in the deleted view, and a
# long-lived test instance accumulated every file every run had ever made, all
# of them still holding their content. Cleanup that does not clean up.
#
# Erasure (PROPOSAL_accountability_record §5.4) is the operation that actually
# destroys: content, every version, the metadata history, and the derived copies
# in csai/discussion/difference, keeping only the record that the thing existed.
# That is what test litter should get.
#
# BEST-EFFORT, AND THAT IS DELIBERATE. Erasure is gated on the `erasure_admin`
# role (membership of the tenant's `erasure_admins` group) — a gate that
# test_e2e_erasure.sh exists partly to prove is real. Most suites run as an
# ordinary tenant admin who does NOT hold it, and cleanup must never be the
# reason a suite fails: a 403 here says the gate works, not that the test did.
# So we erase when we may and fall back to the soft delete when we may not, and
# say which happened at the end rather than pretending.
#
# Give cleanup its own erasure-capable identity to get true destruction:
#   FE_CLEANUP_TOKEN=<bearer>            (or)
#   FE_CLEANUP_USER=dpo@example.com FE_CLEANUP_PASS=...
# With neither, cleanup runs as the suite's own identity and usually soft-deletes.

FE_CLEANUP_ERASED=0
FE_CLEANUP_SOFT=0
FE_CLEANUP_FAILED=0
# Declared up front, not on first use: every suite here runs under `set -u`, where
# expanding an array that was never assigned is a fatal error, not an empty one.
FE_CLEANUP_AUTH=()
FE_CLEANUP_READY=0

# Resolve the cleanup identity once, into a curl auth argument array.
# Falls back to the caller's own $A / $CRED when nothing is configured.
fe_cleanup_init() {
    FE_CLEANUP_READY=1
    FE_CLEANUP_AUTH=()
    if [ -n "${FE_CLEANUP_TOKEN:-}" ]; then
        FE_CLEANUP_AUTH=(-H "Authorization: Bearer $FE_CLEANUP_TOKEN")
        return
    fi
    if [ -n "${FE_CLEANUP_USER:-}" ] && [ -n "${FE_CLEANUP_PASS:-}" ]; then
        local out tok
        out=$(curl -s --max-time 15 -X POST -u "$FE_CLEANUP_USER:$FE_CLEANUP_PASS" \
              -H "X-Tenant: ${FE_TENANT:-default}" "$BASE/v1/auth/token" 2>/dev/null)
        tok=$(grep -oE '"token":"[^"]+"' <<<"$out" | sed 's/.*"token":"//;s/"//')
        if [ -n "$tok" ]; then
            FE_CLEANUP_AUTH=(-H "Authorization: Bearer $tok")
            return
        fi
        # A 2FA-enrolled cleanup user cannot log in this way; say so once rather
        # than silently soft-deleting for the whole run.
        printf '  \033[33m⊘\033[0m cleanup: could not log in as %s (2FA? wrong password?) — falling back\n' \
               "$FE_CLEANUP_USER" >&2
    fi
    # Nothing configured: reuse whatever the suite authenticates with. Both
    # references are guarded — under `set -u` a suite that defines neither would
    # otherwise die in its own teardown.
    if [ -n "${A+x}" ] && [ "${#A[@]}" -gt 0 ]; then
        FE_CLEANUP_AUTH=("${A[@]}")
    elif [ -n "${CRED:-}" ]; then
        FE_CLEANUP_AUTH=(-u "$CRED")
    fi
}

# fe_cleanup <uid> [dirs|files]
#
# The second argument is only for the SOFT-delete fallback, which has separate
# paths for the two. Erasure does not: it is POST /v1/files/{uid}/erase whatever
# the node is, and on a FOLDER it erases what is inside as well — so erasing a
# test's root directory clears the whole tree in one call.
fe_cleanup() {
    local uid="$1" kind="${2:-files}"
    [ -n "$uid" ] || return 0
    # Resolve the identity once per run, not once per call — and keyed on a flag
    # rather than on the array being empty, so a suite with no credentials at all
    # does not re-attempt a login for every node it cleans up.
    [ "$FE_CLEANUP_READY" = "1" ] || fe_cleanup_init

    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
           "${FE_CLEANUP_AUTH[@]}" -H "X-Tenant: ${FE_TENANT:-default}" \
           -H 'Content-Type: application/json' \
           -X POST "$BASE/v1/files/$uid/erase" \
           -d '{"reason":"e2e cleanup"}' 2>/dev/null)
    # 200 erased outright, 202 initiated (other services still acknowledging).
    # Either way the content is gone here and the obligation is recorded.
    if [ "$code" = "200" ] || [ "$code" = "202" ]; then
        FE_CLEANUP_ERASED=$((FE_CLEANUP_ERASED+1))
        return 0
    fi

    # 403 = no erasure_admin, which is the common and correct case for an
    # ordinary admin. Anything else (404 already gone, 5xx) also falls through:
    # leaving litter behind is better than failing a suite in its teardown.
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
           "${FE_CLEANUP_AUTH[@]}" -H "X-Tenant: ${FE_TENANT:-default}" \
           -X DELETE "$BASE/v1/$kind/$uid" 2>/dev/null)
    case "$code" in
        200|204) FE_CLEANUP_SOFT=$((FE_CLEANUP_SOFT+1)) ;;
        404)     : ;;   # already gone; nothing to report
        *)       FE_CLEANUP_FAILED=$((FE_CLEANUP_FAILED+1)) ;;
    esac
    return 0
}

# One line at the end of a run, so "cleaned up" is a claim with evidence behind
# it rather than an assumption.
fe_cleanup_report() {
    local total=$((FE_CLEANUP_ERASED + FE_CLEANUP_SOFT + FE_CLEANUP_FAILED))
    [ "$total" -gt 0 ] || return 0
    printf '\ncleanup: %d erased' "$FE_CLEANUP_ERASED"
    [ "$FE_CLEANUP_SOFT" -gt 0 ] && printf ', %d soft-deleted (no erasure_admin — set FE_CLEANUP_USER/PASS or FE_CLEANUP_TOKEN to destroy them)' "$FE_CLEANUP_SOFT"
    [ "$FE_CLEANUP_FAILED" -gt 0 ] && printf ', \033[33m%d left behind\033[0m' "$FE_CLEANUP_FAILED"
    printf '\n'
}
