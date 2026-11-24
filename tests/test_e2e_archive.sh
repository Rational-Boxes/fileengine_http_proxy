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
# Live E2E for GET /v1/dirs/{uid}/archive — a folder tree streamed as a ZIP.
#
# Builds a small tree (nested folders, an empty folder, a 6 MiB random file that
# spans many core chunks, an empty file, a UTF-8 name, a name with a slash in
# it, and two siblings differing only in case), downloads it through BOTH doors
# (bearer, and the ticket the SPA navigates with), and has Python's zipfile
# check every CRC and compare every member byte-for-byte with what was uploaded.
# Then a SELECTION of the folder's items (POST, JSON for API clients and a form
# for the SPA): only those items, each with its subtree, named after the folder.
# Then the refusals: no credential, a ticket for another folder, an archive
# ticket on a file's content route, a download ticket on the archive route, a
# ticket presented as a bearer, and a file uid given to the folder route.
#
#   BASE=http://localhost:8090 FE_USER=... FE_PASS=... tests/test_e2e_archive.sh
set -uo pipefail
BASE="${BASE:-http://localhost:8090}"
FE_USER="${FE_USER:-testuser@rationalboxes.com}"
FE_PASS="${FE_PASS:-P@ssword1234567890*}"
FE_TENANT="${FE_TENANT:-default}"
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
FE_CLEANUP_TOKEN="${FE_CLEANUP_TOKEN:-}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ROOT="00000000-0000-0000-0000-000000000000"
SUF="zip_$(date +%s)_$RANDOM"

mkdir_() { curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$1" -d "{\"name\":\"$2\"}" | uidof; }
put_()   {   # parent name localfile -> uid
    local u; u=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$1/files" -d "{\"name\":\"$2\"}" | uidof)
    curl -s -o /dev/null "${A[@]}" -H 'Content-Type: application/octet-stream' \
         -X PUT "$BASE/v1/files/$u/content" --data-binary @"$3"
    echo "$u"
}

echo "[setup]"
TOP=$(mkdir_ "$ROOT" "$SUF")
[ -n "$TOP" ] && ok "created $SUF" || { bad "create top folder"; exit 1; }
SUB=$(mkdir_ "$TOP" "drawings")
DEEP=$(mkdir_ "$SUB" "level 2")
EMPTY=$(mkdir_ "$TOP" "empty folder")
mkdir -p "$WORK/src"
head -c $((6 * 1024 * 1024 + 123)) /dev/urandom > "$WORK/src/big.bin"
printf 'hello archive\n' > "$WORK/src/readme.txt"
: > "$WORK/src/empty.txt"
printf 'ü ✓\n' > "$WORK/src/utf8.txt"
printf 'upper\n' > "$WORK/src/upper.txt"
printf 'lower\n' > "$WORK/src/lower.txt"
printf 'slash\n' > "$WORK/src/slash.txt"
README=$(put_ "$TOP"  "readme.txt" "$WORK/src/readme.txt")
put_ "$SUB"  "big.bin"    "$WORK/src/big.bin"    >/dev/null
put_ "$DEEP" "empty.txt"  "$WORK/src/empty.txt"  >/dev/null
put_ "$DEEP" "Plan ü.txt" "$WORK/src/utf8.txt"   >/dev/null
put_ "$TOP"  "Notes.txt"  "$WORK/src/upper.txt"  >/dev/null
put_ "$TOP"  "notes.txt"  "$WORK/src/lower.txt"  >/dev/null
SLASHF=$(put_ "$TOP" "a/../../b.txt" "$WORK/src/slash.txt")
[ -n "$SUB" ] && [ -n "$DEEP" ] && [ -n "$EMPTY" ] && ok "tree built" || bad "tree build"

# What the archive must contain, path -> source file. "a/../../b.txt" is one
# name; the slashes become '_' so it cannot climb out of the extraction dir.
cat > "$WORK/expect.tsv" <<EOF
readme.txt	$WORK/src/readme.txt
drawings/big.bin	$WORK/src/big.bin
drawings/level 2/empty.txt	$WORK/src/empty.txt
drawings/level 2/Plan ü.txt	$WORK/src/utf8.txt
Notes.txt	$WORK/src/upper.txt
notes (2).txt	$WORK/src/lower.txt
a_.._.._b.txt	$WORK/src/slash.txt
empty folder/	-
EOF

verify_zip() {   # zipfile -> "OK" or a reason
    python3 -I - "$1" "$WORK/expect.tsv" <<'PY'
import sys, zipfile
zpath, exp = sys.argv[1], sys.argv[2]
want = {}
for line in open(exp, encoding="utf-8"):
    p, src = line.rstrip("\n").split("\t")
    want[p] = src
try:
    zf = zipfile.ZipFile(zpath)
except Exception as e:
    print(f"not a zip: {e}"); sys.exit()
bad = zf.testzip()
if bad: print(f"CRC mismatch: {bad}"); sys.exit()
names = set(zf.namelist())
for p, src in want.items():
    if p not in names:
        print(f"missing {p!r}; have {sorted(names)}"); sys.exit()
    if src != "-" and zf.read(p) != open(src, "rb").read():
        print(f"content differs: {p}"); sys.exit()
extra = [n for n in names if n not in want and not n.endswith("/")]
if extra: print(f"unexpected members: {extra}"); sys.exit()
if any(n.startswith("/") or ".." in n.split("/") for n in names):
    print("unsafe path in archive"); sys.exit()
print("OK")
PY
}

echo "[bearer download]"
code=$(curl -s -D "$WORK/h1" -o "$WORK/a1.zip" -w '%{http_code}' "${A[@]}" "$BASE/v1/dirs/$TOP/archive")
[ "$code" = "200" ] && ok "GET /v1/dirs/{uid}/archive -> 200" || bad "bearer archive" "got $code"
grep -qi '^content-type: application/zip' "$WORK/h1" && ok "Content-Type application/zip" || bad "content-type" "$(cat "$WORK/h1")"
grep -qi '^transfer-encoding: chunked' "$WORK/h1" && ok "streamed (chunked, no precomputed length)" || bad "chunked" "$(cat "$WORK/h1")"
grep -qi "^content-disposition: attachment; filename=\"$SUF.zip\"" "$WORK/h1" \
  && ok "Content-Disposition names the folder" || bad "disposition" "$(grep -i disposition "$WORK/h1")"
r=$(verify_zip "$WORK/a1.zip")
[ "$r" = "OK" ] && ok "every member present, CRC-valid and byte-identical" || bad "archive contents" "$r"
if command -v unzip >/dev/null; then
    unzip -tq "$WORK/a1.zip" >/dev/null 2>&1 && ok "Info-ZIP unzip -t accepts it" || bad "unzip -t" "$(unzip -tq "$WORK/a1.zip" 2>&1 | tail -3)"
fi

echo "[ticket download (the SPA's path)]"
out=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$TOP/archive-ticket")
T=$(field ticket <<<"$out")
[ -n "$T" ] && ok "POST archive-ticket -> ticket" || bad "mint ticket" "$out"
code=$(curl -s -o "$WORK/a2.zip" -w '%{http_code}' "$BASE/v1/dirs/$TOP/archive?ticket=$T")
[ "$code" = "200" ] && ok "ticketed GET (no Authorization header) -> 200" || bad "ticket archive" "got $code"
r=$(verify_zip "$WORK/a2.zip")
[ "$r" = "OK" ] && ok "ticketed archive verifies" || bad "ticket archive contents" "$r"
cmp -s "$WORK/a1.zip" "$WORK/a2.zip" && ok "same tree -> byte-identical archive (deterministic)" || bad "determinism" "archives differ"

echo "[refusals]"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/dirs/$TOP/archive")
[ "$code" = "401" ] && ok "no credential -> 401" || bad "anonymous" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/dirs/$SUB/archive?ticket=$T")
[ "$code" = "401" ] && ok "ticket for another folder -> 401" || bad "wrong-uid ticket" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/files/$TOP/content?ticket=$T")
[ "$code" = "401" ] && ok "archive ticket on the file content route -> 401" || bad "archive ticket on content" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $T" "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "archive ticket as a bearer -> 401" || bad "ticket as bearer" "got $code"
DT=$(curl -s "${A[@]}" -X POST "$BASE/v1/files/$SLASHF/download-ticket" | field ticket)
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/dirs/$SLASHF/archive?ticket=$DT")
[ "$code" = "401" ] && ok "file download ticket on the archive route -> 401" || bad "download ticket on archive" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" "$BASE/v1/dirs/$SLASHF/archive")
[ "$code" = "400" ] && ok "a file uid on the folder route -> 400" || bad "file as folder" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/dirs/$SLASHF/archive-ticket")
[ "$code" = "400" ] && ok "no archive ticket for a file -> 400" || bad "ticket for file" "got $code"

echo "[selected items]"
printf '%s\t%s\n' "readme.txt" "$WORK/src/readme.txt" "drawings/big.bin" "$WORK/src/big.bin" \
    "drawings/level 2/empty.txt" "$WORK/src/empty.txt" "drawings/level 2/Plan ü.txt" "$WORK/src/utf8.txt" \
    > "$WORK/expect_sel.tsv"
verify_sel() { cp "$WORK/expect.tsv" "$WORK/expect.full"; cp "$WORK/expect_sel.tsv" "$WORK/expect.tsv"
               local r; r=$(verify_zip "$1"); cp "$WORK/expect.full" "$WORK/expect.tsv"; echo "$r"; }
code=$(curl -s -D "$WORK/hs" -o "$WORK/s1.zip" -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/dirs/$TOP/archive" \
       -d "{\"uids\":[\"$README\",\"$SUB\"]}")
[ "$code" = "200" ] && ok "POST {uids:[readme, drawings]} -> 200" || bad "bearer selection" "got $code $(head -c 200 "$WORK/s1.zip")"
grep -qi "^content-disposition: attachment; filename=\"$SUF.zip\"" "$WORK/hs" \
  && ok "a selection is named after the folder" || bad "selection disposition" "$(grep -i disposition "$WORK/hs")"
r=$(verify_sel "$WORK/s1.zip")
[ "$r" = "OK" ] && ok "only the selected items, subtree included, byte-identical" || bad "selection contents" "$r"
n=$(python3 -I -c 'import sys,zipfile;print(sorted({n.split("/")[0] for n in zipfile.ZipFile(sys.argv[1]).namelist()}))' "$WORK/s1.zip")
[ "$n" = "['drawings', 'readme.txt']" ] && ok "nothing unselected at the top (no Notes, no empty folder)" || bad "selection top level" "$n"

# The SPA's path: a ticket minted WITH the selection, then a plain form POST.
out=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$TOP/archive-ticket" -d "{\"uids\":[\"$README\",\"$SUB\"]}")
TS=$(field ticket <<<"$out")
[ -n "$TS" ] && ok "archive-ticket accepts a selection" || bad "selection ticket" "$out"
code=$(curl -s -o "$WORK/s2.zip" -w '%{http_code}' -X POST "$BASE/v1/dirs/$TOP/archive?ticket=$TS" \
       -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uids=$README,$SUB")
r=$(verify_sel "$WORK/s2.zip")
[ "$code" = "200" ] && [ "$r" = "OK" ] && ok "ticketed form POST (no Authorization) -> the same selection" || bad "form selection" "code $code: $r"
cmp -s "$WORK/s1.zip" "$WORK/s2.zip" && ok "same selection -> byte-identical archive" || bad "selection determinism" "differ"

code=$(curl -s -o "$WORK/err" -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/dirs/$TOP/archive-ticket" -d "{\"uids\":[\"$DEEP\"]}")
[ "$code" = "400" ] && grep -q "not an item in this folder" "$WORK/err" \
  && ok "a grandchild is not a selection of this folder -> 400 at the ticket" || bad "stray uid at ticket" "code $code $(cat "$WORK/err")"
code=$(curl -s -o "$WORK/err" -w '%{http_code}' -X POST "$BASE/v1/dirs/$TOP/archive?ticket=$TS" \
       -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uids=$README,$DEEP")
[ "$code" = "400" ] && ok "...and at the download, before any byte is sent" || bad "stray uid at download" "code $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/dirs/$TOP/archive" -d '{"uids":[]}')
[ "$code" = "400" ] && ok "an empty selection -> 400" || bad "empty selection" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/dirs/$TOP/archive" -d '{"uids":["../etc"]}')
[ "$code" = "400" ] && ok "a non-uid -> 400" || bad "non-uid" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/dirs/$SUB/archive?ticket=$TS" \
       -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode "uids=$DEEP")
[ "$code" = "401" ] && ok "the folder's ticket does not open another folder by POST either" || bad "ticket wrong folder POST" "got $code"

echo "[empty folder]"
code=$(curl -s -o "$WORK/e.zip" -w '%{http_code}' "${A[@]}" "$BASE/v1/dirs/$EMPTY/archive")
n=$(python3 -I -c 'import sys,zipfile;print(len(zipfile.ZipFile(sys.argv[1]).namelist()))' "$WORK/e.zip" 2>&1)
[ "$code" = "200" ] && [ "$n" = "0" ] && ok "an empty folder -> a valid, empty ZIP" || bad "empty folder" "code $code, entries $n"

fe_cleanup "$TOP" dirs
fe_cleanup_report
echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ] || { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
