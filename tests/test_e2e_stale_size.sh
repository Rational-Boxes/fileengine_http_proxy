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
# Live E2E: a wrong recorded size must never produce a short file that looks whole.
#
# GET /v1/files/{uid}/content declares Content-Length (or a Content-Range total)
# from the version row's size, and that column is wrong for some production rows
# (copies made before core 1.9.67). Before the guard, a size SMALLER than the
# content gave a 200 with a matching length and a truncated body — curl exit 0,
# nothing logged. This uploads a 100,000-byte file, rewrites its recorded size in
# the dev database to 90,000 and to 110,000, and requires every response that
# cannot be complete to FAIL at the transport (curl exit 18/56: the bridge resets
# the connection), never to end cleanly short. The folder archive and the version
# route (both chunked, sized by what really went out) must stay correct.
#
# Needs the dev Postgres (PGHOST/PGPORT, default localhost:5434) to fake the
# stale size; skips when it is not reachable.
#
#   BASE=http://localhost:8090 FE_USER=... FE_PASS=... tests/test_e2e_stale_size.sh
set -uo pipefail
BASE="${BASE:-http://localhost:8090}"
FE_USER="${FE_USER:-testuser@rationalboxes.com}"
FE_PASS="${FE_PASS:-P@ssword1234567890*}"
FE_TENANT="${FE_TENANT:-default}"
PGHOST="${PGHOST:-localhost}"; PGPORT="${PGPORT:-5434}"
PGUSER="${PGUSER:-postgres}"; PGPASSWORD="${PGPASSWORD:-postgres}"; PGDATABASE="${PGDATABASE:-fileengine}"
export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/lib_login.sh
. "$HERE/lib_login.sh"
# shellcheck source=tests/lib_cleanup.sh
. "$HERE/lib_cleanup.sh"

q() { psql -Atc "$1"; }
if ! command -v psql >/dev/null || ! q 'select 1' >/dev/null 2>&1; then
    echo "SKIP: dev Postgres not reachable at $PGHOST:$PGPORT (needed to fake a stale size)"; exit 0
fi

PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }
uidof() { grep -oE '"uid":"[a-f0-9-]+"' | head -1 | sed 's/.*"uid":"//;s/"//'; }

TOKEN=$(fe_login "$FE_USER" "$FE_PASS" "$FE_TENANT") || { echo "login failed"; exit 1; }
H=(-H "Authorization: Bearer $TOKEN" -H "X-Tenant: $FE_TENANT")
A=("${H[@]}" -H 'Content-Type: application/json')
FE_CLEANUP_TOKEN="${FE_CLEANUP_TOKEN:-}"
WORK="$(mktemp -d)"
SCHEMA="tenant_${FE_TENANT}"

echo "[setup]"
D=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/00000000-0000-0000-0000-000000000000" \
      -d "{\"name\":\"stale_size_$(date +%s)_$RANDOM\"}" | uidof)
F=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$D/files" -d '{"name":"probe.bin"}' | uidof)
head -c 100000 /dev/urandom > "$WORK/probe.bin"
curl -s -o /dev/null "${H[@]}" -H 'Content-Type: application/octet-stream' \
     -X PUT "$BASE/v1/files/$F/content" --data-binary @"$WORK/probe.bin"
V=$(q "select version_timestamp from $SCHEMA.versions where file_uid='$F'")
[ -n "$D" ] && [ -n "$F" ] && [ -n "$V" ] && ok "100,000-byte probe uploaded" || { bad "setup" "D=$D F=$F V=$V"; exit 1; }
setsize() { q "update $SCHEMA.versions set size=$1 where file_uid='$F'; update $SCHEMA.files set size=$1 where uid='$F'" >/dev/null; }
trap 'setsize 100000; rm -rf "$WORK"' EXIT

# fetch label [curl args...] -> sets CODE, EXIT, LEN
fetch() {
    CODE=$(curl -s -o "$WORK/got" -w '%{http_code}' "${H[@]}" "$@"); EXIT=$?
    LEN=$(stat -c %s "$WORK/got" 2>/dev/null || echo 0)
}
same_as() {   # offset length -> 0 when $WORK/got equals that slice of the probe
    cmp -s "$WORK/got" <(tail -c +$(( $1 + 1 )) "$WORK/probe.bin" | head -c "$2")
}
broken() { [ "$EXIT" = 18 ] || [ "$EXIT" = 52 ] || [ "$EXIT" = 56 ]; }   # partial file / nothing / reset

echo "[recorded size correct: nothing changes]"
setsize 100000
fetch "$BASE/v1/files/$F/content"
[ "$CODE" = 200 ] && [ "$EXIT" = 0 ] && same_as 0 100000 && ok "whole file -> 200, complete" || bad "whole, correct size" "code $CODE exit $EXIT len $LEN"
fetch -H 'Range: bytes=1000-' "$BASE/v1/files/$F/content"
[ "$CODE" = 206 ] && [ "$EXIT" = 0 ] && same_as 1000 99000 && ok "open range -> 206, complete" || bad "open range, correct size" "code $CODE exit $EXIT len $LEN"
fetch -H 'Range: bytes=89000-95000' "$BASE/v1/files/$F/content"
[ "$CODE" = 206 ] && [ "$EXIT" = 0 ] && same_as 89000 6001 && ok "closed range -> 206, exact" || bad "closed range, correct size" "code $CODE exit $EXIT len $LEN"

for sz in 90000 110000; do
    setsize "$sz"
    [ "$sz" -lt 100000 ] && what="UNDER-recorded ($sz < 100000)" || what="OVER-recorded ($sz > 100000)"
    echo "[$what]"
    fetch "$BASE/v1/files/$F/content"
    broken && ok "whole file fails at the transport (curl exit $EXIT), not a clean short 200" \
           || bad "whole file, size $sz" "code $CODE exit $EXIT len $LEN"
    fetch -H 'Range: bytes=1000-' "$BASE/v1/files/$F/content"
    broken && ok "open range fails at the transport (curl exit $EXIT)" \
           || bad "open range, size $sz" "code $CODE exit $EXIT len $LEN"
    fetch -H 'Range: bytes=0-999' "$BASE/v1/files/$F/content"
    [ "$CODE" = 206 ] && [ "$EXIT" = 0 ] && same_as 0 1000 \
        && ok "a closed range inside both sizes is still served exactly" \
        || bad "inner closed range, size $sz" "code $CODE exit $EXIT len $LEN"
    fetch -H 'Range: bytes=89000-95000' "$BASE/v1/files/$F/content"
    if [ "$sz" -lt 100000 ]; then
        broken && ok "a closed range the stale size clamped fails (curl exit $EXIT)" \
               || bad "clamped closed range, size $sz" "code $CODE exit $EXIT len $LEN"
    else
        [ "$CODE" = 206 ] && [ "$EXIT" = 0 ] && same_as 89000 6001 \
            && ok "a closed range within the real content is served exactly" \
            || bad "closed range, size $sz" "code $CODE exit $EXIT len $LEN"
    fi
    fetch "$BASE/v1/files/$F/versions/$V"
    [ "$CODE" = 200 ] && [ "$EXIT" = 0 ] && same_as 0 100000 \
        && ok "the version route (chunked) is complete regardless" || bad "version route, size $sz" "code $CODE exit $EXIT len $LEN"
    fetch "$BASE/v1/dirs/$D/archive"
    r=$(python3 -I -c 'import sys,zipfile;z=zipfile.ZipFile(sys.argv[1]);print("OK" if z.testzip() is None and z.read("probe.bin")==open(sys.argv[2],"rb").read() else "bad")' "$WORK/got" "$WORK/probe.bin" 2>&1)
    [ "$CODE" = 200 ] && [ "$r" = OK ] && ok "the folder archive holds the real 100,000 bytes" || bad "archive, size $sz" "code $CODE: $r"
done

setsize 100000
fe_cleanup "$D" dirs
fe_cleanup_report
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ] || { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
