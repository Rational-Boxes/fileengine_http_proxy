#!/bin/bash
# End-to-end tests for ERASURE — "true delete" (PROPOSAL_accountability_record §5.4).
#
# WHY THIS EXISTS. Erasure was built with unit tests at every layer, and every
# layer passed while the feature was broken end to end. Four separate failures
# shipped, each invisible to the tests either side of it:
#
#   1. the bridge's service credential lacked the `destroy` capability, so the
#      core refused the RPC before any of the logic ran;
#   2. no role conferred ERASE, so an administrator could never erase anything;
#   3. the bridge derived the erasure_admin role at LOGIN but not on the
#      per-request path, so the role never reached the core;
#   4. the erasure accountability actions had no schema, so the chain refused the
#      record and — because record and destruction commit together — aborted the
#      erasure.
#
# Every one of those lives BETWEEN components. That is what this suite covers:
# it drives a real erasure through the REST door, against a live bridge, core,
# chain and directory, and asserts on what actually happened to the data.
#
# Usage:
#   BASE=http://localhost:8090 \
#   FE_ERASE_USER='dpo@example.com' FE_ERASE_PASS='...' \
#   [FE_TENANT=default] [FE_USER=<plain admin> FE_PASS=...] \
#   ./tests/test_e2e_erasure.sh
#
#   FE_ERASE_USER must hold the erasure_admin role (member of the tenant's
#   `erasure_admins` group). Without it, everything here fails at the first
#   erase — which is itself the point.
#
#   FE_USER/FE_PASS, if given, must be a tenant ADMIN who is NOT an
#   erasure_admin: it proves the role is a real gate and not decoration.
#   Omitted, that check SKIPs rather than passing silently.
#
#   Where 2FA blocks a password login, pass a bearer token instead:
#   FE_ERASE_TOKEN=... (and FE_TOKEN=... for the plain admin).

BASE="${BASE:-http://localhost:8090}"
TENANT="${FE_TENANT:-default}"
PASS=0; FAIL=0; SKIP=0; FAILED=()
ok()   { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33m⊘ SKIP\033[0m %s\n' "$1"; }

# Bearer for an identity, from a token if supplied or a password login.
mint() {  # mint <user> <pass> <preset-token>
    if [ -n "$3" ]; then printf '%s' "$3"; return 0; fi
    [ -n "$1" ] || return 1
    curl -s -u "$1:$2" -X POST "$BASE/v1/auth/token?tenant=$TENANT" \
         -H 'Content-Type: application/json' -d '{}' --max-time 20 \
      | grep -oE '"token":"[^"]+"' | sed 's/.*"token":"//;s/"//'
}
api() {  # api <token> <method> <path> [body]
    local t="$1" m="$2" p="$3" b="${4:-}"
    if [ -n "$b" ]; then
        curl -s -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H "X-Tenant: $TENANT" \
             -H 'Content-Type: application/json' -d "$b" --max-time 30
    else
        curl -s -X "$m" "$BASE$p" -H "Authorization: Bearer $t" -H "X-Tenant: $TENANT" --max-time 30
    fi
}
code_of() {  # code_of <token> <method> <path> [body]
    local t="$1" m="$2" p="$3" b="${4:-}"
    if [ -n "$b" ]; then
        curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" \
             -H "X-Tenant: $TENANT" -H 'Content-Type: application/json' -d "$b" --max-time 30
    else
        curl -s -o /dev/null -w '%{http_code}' -X "$m" "$BASE$p" -H "Authorization: Bearer $t" \
             -H "X-Tenant: $TENANT" --max-time 30
    fi
}
jstr() { grep -oE "\"$2\":\"[^\"]*\"" <<<"$1" | head -1 | sed "s/.*\"$2\":\"//;s/\"$//"; }

echo "=========================================================="
echo " FileEngine — ERASURE E2E   base=$BASE tenant=$TENANT"
echo "=========================================================="

ETOKEN=$(mint "${FE_ERASE_USER:-}" "${FE_ERASE_PASS:-}" "${FE_ERASE_TOKEN:-}")
if [ -z "$ETOKEN" ]; then
    echo "  FATAL: could not authenticate FE_ERASE_USER."
    echo "  Set FE_ERASE_USER/FE_ERASE_PASS, or FE_ERASE_TOKEN where 2FA is enrolled."
    exit 1
fi
ok "authenticated as the erasure administrator"

# A file of our own, so the suite never touches anything it did not create.
mkfile() {  # mkfile <name> <content> -> uid
    local uid
    uid=$(api "$ETOKEN" POST "/v1/dirs/root/files" "{\"name\":\"$1\"}")
    uid=$(grep -oE '"uid":"[^"]+"' <<<"$uid" | head -1 | sed 's/.*"uid":"//;s/"//')
    [ -n "$uid" ] || return 1
    curl -s -X PUT "$BASE/v1/files/$uid/content" -H "Authorization: Bearer $ETOKEN" \
         -H "X-Tenant: $TENANT" --data-binary "$2" --max-time 30 -o /dev/null
    printf '%s' "$uid"
}

STAMP=$(date +%s)

# ── 1. The whole path, in one call ──────────────────────────────────────────
# This single assertion is what all four shipped failures had in common: each
# made it fail, from a different component, with a different message.
echo "[erase]"
UID1=$(mkfile "erase-e2e-$STAMP.txt" "sensitive party data")
if [ -z "$UID1" ]; then bad "create a file to erase" "no uid returned"; else
    ok "created a file to erase ($UID1)"
    resp=$(api "$ETOKEN" POST "/v1/files/$UID1/erase" '{"reason":"e2e"}')
    ecode=$(code_of "$ETOKEN" POST "/v1/files/$UID1/erase" '{"reason":"e2e"}' )
    # (the second call is refused as already-erased; the first is the real one)
    ERASURE_ID=$(jstr "$resp" erasure_id)
    STATE=$(jstr "$resp" state)
    if [ -n "$ERASURE_ID" ]; then
        ok "erase accepted, erasure recorded ($STATE)"
    else
        bad "erase accepted" "$resp"
    fi

    # 202 while participants are outstanding, 200 only when there are none. The
    # distinction is the feature: 204/'done' would be a compliance claim the
    # platform cannot yet stand behind.
    case "$STATE" in
      initiated|complete) ok "state is a real erasure state ('$STATE')" ;;
      *) bad "state is a real erasure state" "got '$STATE' from $resp" ;;
    esac

    # ── 2. The content is actually gone ─────────────────────────────────────
    echo "[destruction]"
    c=$(code_of "$ETOKEN" GET "/v1/files/$UID1/content")
    [ "$c" != "200" ] && ok "content is unreadable after erasure ($c)" \
                      || bad "content is unreadable after erasure" "still 200"
    v=$(api "$ETOKEN" GET "/v1/files/$UID1/versions")
    if grep -qE '"versions":\[\s*\]' <<<"$v" || ! grep -q '"version' <<<"$v"; then
        ok "every version is destroyed"
    else
        bad "every version is destroyed" "$v"
    fi

    # ── 3. The fact survives; the name does not ─────────────────────────────
    # The payload is destroyed and the fact is retained (§5.4.1). A filename is
    # itself party data, so the default is to redact it.
    st=$(api "$ETOKEN" GET "/v1/nodes/$UID1")
    if [ -n "$st" ] && ! grep -q '"error"' <<<"$st"; then
        ok "the existence record survives (uid still resolves)"
        if grep -qE "\"name\":\"erase-e2e-$STAMP" <<<"$st"; then
            bad "the filename is redacted by default" "$st"
        else
            ok "the filename is redacted by default"
        fi
    else
        skip "existence record readable via /v1/nodes (endpoint returned: ${st:0:80})"
    fi

    # ── 4. Erasing twice is refused ─────────────────────────────────────────
    # Not pedantry: a second run would destroy nothing, report success, and
    # attest to a destruction that did not happen on that occasion.
    # Written as an if, not an || && || chain: that chain evaluates left to
    # right, so `A || B && C || D` ran C whenever B was true and reported a
    # failure that had not happened.
    if [ "$ecode" = "202" ] || [ "$ecode" = "200" ]; then
        bad "a second erasure is refused" "got $ecode"
    else
        ok "a second erasure is refused ($ecode)"
    fi

    # ── 5. The attestation record ───────────────────────────────────────────
    echo "[attestation]"
    if [ -n "$ERASURE_ID" ]; then
        stat=$(api "$ETOKEN" GET "/v1/erasures/$ERASURE_ID")
        grep -q "\"uid\":\"$UID1\"" <<<"$stat" \
            && ok "the erasure record names the file" || bad "erasure record names the file" "$stat"
        grep -q '"actor":"' <<<"$stat" \
            && ok "the erasure record names the actor" || bad "erasure record names the actor" "$stat"
        grep -q '"awaiting":\[' <<<"$stat" \
            && ok "the record lists who has yet to confirm" || bad "record lists awaiting" "$stat"
        # A deployment with no participants configured completes immediately —
        # correct only where nothing holds derived data. Say so either way.
        if grep -q '"state":"complete"' <<<"$stat"; then
            if grep -qE '"awaiting":\[\s*\]' <<<"$stat"; then
                ok "complete with nothing outstanding (no participants configured)"
            else
                bad "complete while participants are outstanding" "$stat"
            fi
        else
            ok "still initiated — participants have yet to confirm"
        fi
    fi
fi

# ── 5b. The tombstone does not appear as a file ─────────────────────────────
# An erased row is a tombstone, not a file: no content, no versions, no name, and
# undelete cannot bring it back. Listing it renders a nameless row that looks
# like corruption and offers actions that can only fail. The fact is retained in
# the erasure record and the chain, which is where an auditor looks.
echo "[no phantom rows]"
if [ -n "$UID1" ]; then
    lst=$(api "$ETOKEN" GET "/v1/dirs/root")
    if grep -q "\"uid\":\"$UID1\"" <<<"$lst"; then
        bad "the erased file is gone from the listing" "still present as a row"
    else
        ok "the erased file is gone from the listing"
    fi
    # Not in the with-deleted view either: it is not a deleted file.
    lstd=$(api "$ETOKEN" GET "/v1/dirs/root?deleted=true")
    if grep -q "\"uid\":\"$UID1\"" <<<"$lstd"; then
        bad "the erased file is gone from the deleted view too" "shows as recoverable"
    else
        ok "the erased file is gone from the deleted view too"
    fi
    # A nameless entry anywhere is the symptom this guards against.
    if grep -qE '"name":""' <<<"$lst$lstd"; then
        bad "no nameless rows in any listing" "a redacted tombstone is being rendered"
    else
        ok "no nameless rows in any listing"
    fi
fi

# ── 5c. The attestation LOOP ────────────────────────────────────────────────
# The seam every other check leaves open. With participants configured, an
# erasure is INITIATED and stays that way until csai, discussion and difference
# each destroy their derived copy and say so. This is the part that makes the
# completion record mean anything, and it is the only part that cannot be tested
# without all four processes running.
#
# Skipped, loudly, where no participants are configured — a suite that quietly
# passed through the no-participants branch is how this seam stayed open.
echo "[attestation loop]"
if [ -z "$ERASURE_ID" ]; then
    skip "attestation loop (no erasure to follow)"
elif ! grep -q '"state":"initiated"' <<<"$(api "$ETOKEN" GET "/v1/erasures/$ERASURE_ID")"; then
    skip "attestation loop — this deployment has no FILEENGINE_ERASURE_PARTICIPANTS, so erasures complete immediately and the acknowledge path is NOT covered"
else
    ok "erasure starts INITIATED with participants outstanding"
    deadline=$(( $(date +%s) + ${FE_ERASE_WAIT:-90} ))
    final=""
    while [ "$(date +%s)" -lt "$deadline" ]; do
        st=$(api "$ETOKEN" GET "/v1/erasures/$ERASURE_ID")
        case "$st" in
          *'"state":"complete"'*) final="complete"; break ;;
          *'"state":"failed"'*)   final="failed";   break ;;
        esac
        sleep 3
    done
    st=$(api "$ETOKEN" GET "/v1/erasures/$ERASURE_ID")
    if [ "$final" = "complete" ]; then
        ok "every participant acknowledged; the erasure completed"
    elif [ "$final" = "failed" ]; then
        bad "the erasure completed" "a participant reported it could not comply: $st"
    else
        bad "the erasure completed within ${FE_ERASE_WAIT:-90}s" "still outstanding: $st"
    fi
    # Nothing may be left waiting once complete: an empty awaiting list is the
    # difference between "we are done" and "we stopped asking".
    grep -qE '"awaiting":\[\s*\]' <<<"$st" \
        && ok "no participant is left outstanding" \
        || bad "no participant is left outstanding" "$st"
    # Each participant must appear BY NAME, having said what it destroyed. An
    # acknowledgement with no statement is not evidence.
    for p in csai discussion difference; do
        if grep -q "\"participant\":\"$p\"" <<<"$st"; then
            ok "$p acknowledged by name"
        else
            bad "$p acknowledged by name" "$st"
        fi
    done
    grep -q '"complied":false' <<<"$st" \
        && bad "every acknowledgement reports compliance" "$st" \
        || ok "every acknowledgement reports compliance"
    grep -q '"completed_at":0' <<<"$st" \
        && bad "the completion is timestamped" "completed_at is 0 in $st" \
        || ok "the completion is timestamped"
fi

# ── 5d. Erasing a FOLDER erases what is in it, attestably ───────────────────
# The flaw this pins: a folder's members were treated as RENDITIONS and erased
# with NO participants, so their content was destroyed in the core while csai,
# discussion and difference were never asked to purge theirs. Verified in
# production — a document inside an erased folder kept its text and embedding in
# the search index, with nothing outstanding to show it. And the walk was one
# level, so a subfolder's contents survived entirely.
echo "[folder erasure]"
FDIR=$(api "$ETOKEN" POST "/v1/dirs/root" "{\"name\":\"erase-tree-$STAMP\"}" \
       | grep -oE '"uid":"[^"]+"' | head -1 | sed 's/.*"uid":"//;s/"//')
if [ -z "$FDIR" ]; then skip "folder erasure (could not create a folder)"; else
    SUB=$(api "$ETOKEN" POST "/v1/dirs/$FDIR" "{\"name\":\"nested\"}" \
          | grep -oE '"uid":"[^"]+"' | head -1 | sed 's/.*"uid":"//;s/"//')
    mkin() {  # mkin <parent> <name> -> uid
        local uid
        uid=$(api "$ETOKEN" POST "/v1/dirs/$1/files" "{\"name\":\"$2\"}" \
              | grep -oE '"uid":"[^"]+"' | head -1 | sed 's/.*"uid":"//;s/"//')
        curl -s -X PUT "$BASE/v1/files/$uid/content" -H "Authorization: Bearer $ETOKEN" \
             -H "X-Tenant: $TENANT" --data-binary "party data" --max-time 30 -o /dev/null
        printf '%s' "$uid"
    }
    TOP=$(mkin "$FDIR" "top-$STAMP.txt")
    DEEP=$(mkin "$SUB" "deep-$STAMP.txt")
    ok "built a folder with a file and a nested subfolder"

    resp=$(api "$ETOKEN" POST "/v1/files/$FDIR/erase" '{"reason":"folder e2e"}')
    n=$(grep -o '"erasure_ids":\[[^]]*\]' <<<"$resp" | grep -o '"' | wc -l)
    n=$(( n / 2 ))
    # root + subfolder + 2 files = 4 records, one per node.
    [ "$n" -ge 4 ] && ok "every node in the subtree got its own erasure record ($n)" \
                   || bad "one erasure record per node" "got $n from $resp"

    # The nested file is the one the old code never reached at all.
    for u in "$TOP" "$DEEP"; do
        c=$(code_of "$ETOKEN" GET "/v1/files/$u/content")
        [ "$c" != "200" ] && ok "content destroyed ($u)" || bad "content destroyed" "$u still 200"
    done

    # And the part that actually mattered: each FILE must carry participants, so
    # the services holding its derived copies are asked. A record with an empty
    # awaiting list on a file means nobody was ever told.
    for u in "$TOP" "$DEEP"; do
        eid=$(api "$ETOKEN" GET "/v1/dirs/root" >/dev/null; \
              grep -o '"erasure_ids":\[[^]]*\]' <<<"$resp" >/dev/null; echo "")
    done
    missing=0
    for eid in $(grep -o '"erasure_ids":\[[^]]*\]' <<<"$resp" | tr -d '[]"' | sed 's/erasure_ids://' | tr ',' ' '); do
        st=$(api "$ETOKEN" GET "/v1/erasures/$eid")
        # Renditions legitimately have none; a FILE with content must have some.
        if grep -q '"state":"initiated"' <<<"$st" || grep -qE '"awaiting":\[\s*"' <<<"$st"; then
            :   # has participants outstanding — correct for a real file
        fi
    done
    # Direct assertion: the two documents' own records name participants.
    for u in "$TOP" "$DEEP"; do
        found=0
        for eid in $(grep -o '"erasure_ids":\[[^]]*\]' <<<"$resp" | tr -d '[]"' | sed 's/erasure_ids://' | tr ',' ' '); do
            st=$(api "$ETOKEN" GET "/v1/erasures/$eid")
            if grep -q "\"uid\":\"$u\"" <<<"$st"; then
                found=1
                if grep -qE '"awaiting":\[\s*\]' <<<"$st" && grep -q '"acks":\[\]' <<<"$st"; then
                    bad "the document's erasure asks the services ($u)" \
                        "no participants — its derived copies were never requested"
                else
                    ok "the document's erasure asks the services ($u)"
                fi
            fi
        done
        [ "$found" = "1" ] || bad "the document has an erasure record of its own ($u)" "none found"
    done
fi

# ── 6. Soft delete is NOT erasure ───────────────────────────────────────────
# The two must never share a path: a soft delete is reversible and consumers may
# reasonably keep derived data for it.
echo "[soft delete is not erasure]"
UID2=$(mkfile "softdel-e2e-$STAMP.txt" "recoverable")
if [ -n "$UID2" ]; then
    code_of "$ETOKEN" DELETE "/v1/files/$UID2" >/dev/null
    u=$(code_of "$ETOKEN" POST "/v1/files/$UID2/undelete")
    [ "$u" = "204" ] || [ "$u" = "200" ] \
        && ok "a soft-deleted file is still undeletable ($u)" \
        || bad "soft delete stays reversible" "undelete got $u"
    c=$(code_of "$ETOKEN" GET "/v1/files/$UID2/content")
    [ "$c" = "200" ] && ok "its content survived the soft delete" \
                     || bad "content survives a soft delete" "got $c"
else
    skip "soft-delete comparison (could not create a file)"
fi

# ── 7. The role is a real gate ──────────────────────────────────────────────
# A tenant administrator who is NOT an erasure_admin must be refused. This is
# the check that would have caught the role never reaching the core: it passes
# only if the role genuinely changes the outcome.
echo "[the role gates]"
PTOKEN=$(mint "${FE_USER:-}" "${FE_PASS:-}" "${FE_TOKEN:-}")
if [ -n "$PTOKEN" ]; then
    UID3=$(mkfile "gate-e2e-$STAMP.txt" "x")
    if [ -n "$UID3" ]; then
        g=$(code_of "$PTOKEN" POST "/v1/files/$UID3/erase" '{"reason":"should be refused"}')
        [ "$g" = "403" ] && ok "an administrator without erasure_admin is refused (403)" \
                         || bad "administrator without erasure_admin is refused" "got $g"
        # And it is still there afterwards.
        c=$(code_of "$ETOKEN" GET "/v1/files/$UID3/content")
        [ "$c" = "200" ] && ok "the refused file is untouched" || bad "refused file untouched" "got $c"
        api "$ETOKEN" POST "/v1/files/$UID3/erase" '{"reason":"cleanup"}' >/dev/null
    fi
else
    skip "erasure_admin is a real gate (set FE_USER/FE_PASS to a plain tenant admin)"
fi

# ── 8. Permission reporting matches enforcement ─────────────────────────────
# The SPA decides whether to OFFER erasure from this answer. If it disagreed with
# the check, the UI would either hide a power the user has or offer one that then
# fails.
echo "[permission reporting]"
p=$(api "$ETOKEN" GET "/v1/nodes/root/permissions?permission=ERASE")
grep -q '"has_permission":true' <<<"$p" \
    && ok "an erasure_admin is reported as holding ERASE" \
    || bad "ERASE reported for an erasure_admin" "$p"
if [ -n "$PTOKEN" ]; then
    p2=$(api "$PTOKEN" GET "/v1/nodes/root/permissions?permission=ERASE")
    grep -q '"has_permission":false' <<<"$p2" \
        && ok "a plain administrator is reported as NOT holding ERASE" \
        || bad "ERASE not reported for a plain admin" "$p2"
fi

echo "----------------------------------------------------------"
printf ' passed %d   failed %d   skipped %d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf '\n failures:\n'; for f in "${FAILED[@]}"; do printf '   - %s\n' "$f"; done
    exit 1
fi
exit 0
