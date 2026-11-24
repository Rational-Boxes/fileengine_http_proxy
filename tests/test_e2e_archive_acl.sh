#!/usr/bin/env bash
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
# Live E2E: a folder ZIP never carries what its requester could not open.
#
# A ZIP is one response holding many files, so it is exactly where an ACL
# mistake would leak in bulk: a member included because the WALK saw it, a
# subfolder descended into that the caller may not list, a soft-deleted file, a
# selection naming something outside the folder, another tenant's data. Each of
# those is set up here and the archive is checked from the outside.
#
# The tree is built by the admin fixture; the archives are requested by a
# NON-admin member of the same tenant (tenant admins bypass ACLs by design, so
# only a plain member can test them). Every protected file holds a unique
# CANARY string in its content AND its name, and the raw archive bytes are
# searched for all of them — members are written as stored deflate blocks, so
# content appears verbatim — which also covers the _download_report.txt entry
# and the central directory, not just the member list. The admin's own archive
# of the same folder must contain every canary that is not soft-deleted, so a
# pass cannot come from a fixture that silently failed to build.
#
#   FE_USER/FE_PASS    admin fixture (builds the tree, sets the ACLs)
#   FE_USER2/FE_PASS2  NON-admin member of FE_TENANT (requests the archives)
#   FE_TENANT2         a tenant FE_USER2 is NOT a member of (FE_USER is)
set -uo pipefail
BASE="${BASE:-http://localhost:8090}"
FE_USER="${FE_USER:-testuser@rationalboxes.com}"
FE_PASS="${FE_PASS:-P@ssword1234567890*}"
FE_TENANT="${FE_TENANT:-default}"
FE_USER2="${FE_USER2:-throwaway@rationalboxes.com}"
FE_PASS2="${FE_PASS2:-Thr0waway!23456789}"
FE_TENANT2="${FE_TENANT2:-filenginetest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/lib_login.sh
. "$HERE/lib_login.sh"
# shellcheck source=tests/lib_cleanup.sh
. "$HERE/lib_cleanup.sh"

PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }
uidof() { grep -oE '"uid":"[a-f0-9-]+"' | head -1 | sed 's/.*"uid":"//;s/"//'; }
field() { grep -oE "\"$1\":\"[^\"]+\"" | head -1 | sed "s/.*\"$1\":\"//;s/\"//"; }

TOKEN=$(fe_login "$FE_USER" "$FE_PASS" "$FE_TENANT") || { echo "login failed"; exit 1; }
A=(-H "Authorization: Bearer $TOKEN" -H "X-Tenant: $FE_TENANT" -H 'Content-Type: application/json')
# The non-admin over Basic: an interactive 2FA login is not needed to prove ACLs.
U=(-u "$FE_USER2:$FE_PASS2" -H "X-Tenant: $FE_TENANT")
code=$(curl -s -o "$HERE/.whoami.$$" -w '%{http_code}' "${U[@]}" "$BASE/v1/whoami")
roles=$(cat "$HERE/.whoami.$$" 2>/dev/null); rm -f "$HERE/.whoami.$$"
if [ "$code" != 200 ]; then echo "SKIP: $FE_USER2 cannot sign in over Basic ($code)"; exit 0; fi
case "$roles" in *tenant_admin*|*system_admin*|*administrators*)
    echo "SKIP: $FE_USER2 is an admin ($roles); ACLs do not bind admins, so it proves nothing"; exit 0;; esac
FE_CLEANUP_TOKEN="${FE_CLEANUP_TOKEN:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="00000000-0000-0000-0000-000000000000"
SUF="zipacl_$(date +%s)_$RANDOM"
TAG="Z$RANDOM$RANDOM"           # canaries unique to this run

mkdir_() { curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$1" -d "{\"name\":\"$2\"}" | uidof; }
put_()   {   # parent name content -> uid
    local u; u=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$1/files" -d "{\"name\":\"$2\"}" | uidof)
    printf '%s' "$3" | curl -s -o /dev/null "${A[@]}" -H 'Content-Type: application/octet-stream' \
         -X PUT "$BASE/v1/files/$u/content" --data-binary @-
    echo "$u"
}
deny_() {    # uid recursive(true|false)
    curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/nodes/$1/permissions" \
         -d "{\"principal\":\"$FE_USER2\",\"permission\":\"r\",\"effect\":\"deny\",\"recursive\":$2}"
}

echo "[setup, as $FE_USER]"
TOP=$(mkdir_ "$ROOT" "$SUF")
OPEN=$(put_ "$TOP" "open.txt" "open-content")
SECRET=$(put_ "$TOP" "secret-$TAG-1.txt" "CANARY-$TAG-1")
PRIV=$(mkdir_ "$TOP" "private")
put_ "$PRIV" "hidden-$TAG-2.txt" "CANARY-$TAG-2" >/dev/null
INNER=$(mkdir_ "$PRIV" "inner-$TAG-3")
put_ "$INNER" "deep-$TAG-4.txt" "CANARY-$TAG-4" >/dev/null
SHUT=$(mkdir_ "$TOP" "shut")                  # denied on the folder ONLY, not its child
put_ "$SHUT" "child-$TAG-5.txt" "CANARY-$TAG-5" >/dev/null
MIXED=$(mkdir_ "$TOP" "mixed")
VISIBLE=$(put_ "$MIXED" "visible.txt" "visible-content")
LOCKED=$(put_ "$MIXED" "locked-$TAG-6.txt" "CANARY-$TAG-6")
TRASHED=$(put_ "$TOP" "trashed-$TAG-7.txt" "CANARY-$TAG-7")
curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/files/$TRASHED"
d1=$(deny_ "$SECRET" false); d2=$(deny_ "$PRIV" true); d3=$(deny_ "$SHUT" false); d4=$(deny_ "$LOCKED" false)
[ -n "$TOP" ] && [ -n "$LOCKED" ] && [ "$d1$d2$d3$d4" = "204204204204" ] \
    && ok "tree built; READ denied to $FE_USER2 on a file, a folder (recursive), a folder (alone), a file in a visible folder" \
    || { bad "setup" "deny codes $d1 $d2 $d3 $d4"; fe_cleanup "$TOP" dirs; exit 1; }

canaries_in() {   # zipfile -> the canary numbers found anywhere in its raw bytes
    local f="$1" n out=""
    for n in 1 2 3 4 5 6 7; do grep -aq -- "-$TAG-$n" "$f" && out="$out$n"; done
    echo "${out:-none}"
}
members() { python3 -I -c 'import sys,zipfile;print(" ".join(sorted(zipfile.ZipFile(sys.argv[1]).namelist())))' "$1" 2>&1; }

echo "[control: the admin's archive holds every canary that is not soft-deleted]"
curl -s -o "$WORK/admin.zip" "${A[@]}" "$BASE/v1/dirs/$TOP/archive"
c=$(canaries_in "$WORK/admin.zip")
[ "$c" = "123456" ] && ok "admin archive: canaries 1-6 present, 7 (soft-deleted) absent" || bad "admin control" "found: $c"

echo "[the non-admin's whole-folder archive]"
code=$(curl -s -o "$WORK/u.zip" -w '%{http_code}' "${U[@]}" "$BASE/v1/dirs/$TOP/archive")
[ "$code" = 200 ] && ok "GET archive as $FE_USER2 -> 200" || bad "non-admin archive" "got $code"
c=$(canaries_in "$WORK/u.zip")
[ "$c" = "none" ] && ok "no denied or deleted file's name or bytes anywhere in it (report and directory included)" \
                  || bad "LEAK: canaries in the non-admin archive" "found: $c"
m=$(members "$WORK/u.zip")
[ "$m" = "mixed/visible.txt open.txt" ] && ok "exactly the readable items: open.txt, mixed/visible.txt" \
    || bad "non-admin members" "$m"
cmp -s <(unzip -p "$WORK/u.zip" open.txt 2>/dev/null) <(printf 'open-content') \
    && ok "readable content intact" || bad "readable content"

echo "[the SPA's path: a ticket the non-admin minted]"
T=$(curl -s "${U[@]}" -X POST "$BASE/v1/dirs/$TOP/archive-ticket" | field ticket)
code=$(curl -s -o "$WORK/t.zip" -w '%{http_code}' "$BASE/v1/dirs/$TOP/archive?ticket=$T")
c=$(canaries_in "$WORK/t.zip")
[ "$code" = 200 ] && [ "$c" = none ] && cmp -s "$WORK/u.zip" "$WORK/t.zip" \
    && ok "ticketed download = the holder's view, nothing more" || bad "ticket archive" "code $code canaries $c"

echo "[selections cannot reach what the listing hides]"
for pair in "secret file:$SECRET" "denied folder:$PRIV" "folder-only deny:$SHUT" "soft-deleted file:$TRASHED" \
            "grandchild of a visible folder:$LOCKED"; do
    what=${pair%%:*}; uid=${pair#*:}
    code=$(curl -s -o "$WORK/err" -w '%{http_code}' "${U[@]}" -H 'Content-Type: application/json' \
           -X POST "$BASE/v1/dirs/$TOP/archive-ticket" -d "{\"uids\":[\"$OPEN\",\"$uid\"]}")
    code2=$(curl -s -o "$WORK/s.zip" -w '%{http_code}' -X POST "$BASE/v1/dirs/$TOP/archive?ticket=$T" \
            -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uids=$OPEN,$uid")
    c=none; [ "$code2" = 200 ] && c=$(canaries_in "$WORK/s.zip")
    [ "$code" = 400 ] && [ "$code2" = 400 ] && [ "$c" = none ] \
        && ok "selecting a $what -> 400 at the ticket and at the download" \
        || bad "selection of a $what" "ticket $code, download $code2, canaries $c"
done
code=$(curl -s -o "$WORK/s.zip" -w '%{http_code}' "${U[@]}" -H 'Content-Type: application/json' \
       -X POST "$BASE/v1/dirs/$TOP/archive" -d "{\"uids\":[\"$OPEN\",\"$MIXED\"]}")
c=$(canaries_in "$WORK/s.zip"); m=$(members "$WORK/s.zip")
[ "$code" = 200 ] && [ "$c" = none ] && [ "$m" = "mixed/visible.txt open.txt" ] \
    && ok "selecting a visible folder still drops the denied file inside it" || bad "selected mixed folder" "code $code canaries $c members $m"

echo "[denied folders cannot be archived directly]"
for pair in "recursively denied:$PRIV" "denied on its own:$SHUT"; do
    what=${pair%%:*}; uid=${pair#*:}
    code=$(curl -s -o "$WORK/d.zip" -w '%{http_code}' "${U[@]}" "$BASE/v1/dirs/$uid/archive")
    code2=$(curl -s -o /dev/null -w '%{http_code}' "${U[@]}" -X POST "$BASE/v1/dirs/$uid/archive-ticket")
    c=none; [ "$code" = 200 ] && c=$(canaries_in "$WORK/d.zip")
    case "$code$code2" in 403403|404404|403404|404403)
        ok "a folder $what: archive $code, ticket $code2" ;;
      *) bad "folder $what" "archive $code (canaries $c), ticket $code2" ;;
    esac
done
code=$(curl -s -o "$WORK/d.zip" -w '%{http_code}' "${U[@]}" "$BASE/v1/dirs/$INNER/archive")
c=none; [ "$code" = 200 ] && c=$(canaries_in "$WORK/d.zip")
[ "$code" != 200 ] && ok "a subfolder of a denied folder, by uid: $code" || bad "inner by uid" "200, canaries $c"
# A ticket is scoped to ONE folder: the non-admin's ticket for TOP opens nothing else.
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/dirs/$PRIV/archive?ticket=$T")
[ "$code" = 401 ] && ok "the TOP ticket does not open a subfolder by uid" || bad "ticket rescoped" "got $code"

echo "[tenant boundary]"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$FE_USER2:$FE_PASS2" -H "X-Tenant: $FE_TENANT2" "$BASE/v1/dirs/$TOP/archive")
code2=$(curl -s -o /dev/null -w '%{http_code}' -u "$FE_USER2:$FE_PASS2" -H "X-Tenant: $FE_TENANT2" -X POST "$BASE/v1/dirs/$TOP/archive-ticket")
[ "$code" = 403 ] && [ "$code2" = 403 ] && ok "a non-member of $FE_TENANT2 -> 403 (archive and ticket)" \
    || bad "non-member tenant" "archive $code, ticket $code2"
B=(-H "Authorization: Bearer $TOKEN" -H "X-Tenant: $FE_TENANT2")
code=$(curl -s -o "$WORK/x.zip" -w '%{http_code}' "${B[@]}" "$BASE/v1/dirs/$TOP/archive")
code2=$(curl -s -o /dev/null -w '%{http_code}' "${B[@]}" -X POST "$BASE/v1/dirs/$TOP/archive-ticket")
c=none; [ "$code" = 200 ] && c=$(canaries_in "$WORK/x.zip")
[ "$code" != 200 ] && [ "$code2" != 200 ] \
    && ok "a member of both tenants cannot archive a $FE_TENANT folder through $FE_TENANT2 ($code / $code2)" \
    || bad "cross-tenant archive" "archive $code (canaries $c), ticket $code2"

fe_cleanup "$TOP" dirs
fe_cleanup_report
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ] || { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
