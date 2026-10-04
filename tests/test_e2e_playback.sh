#!/usr/bin/env bash
# End-to-end: byte-range serving and playback tickets, against a live stack.
#
# What it proves, and why each matters:
#   * Range is served by the CORE (offset/length), not by streaming from zero
#     and discarding: exact `Content-Range: bytes s-e/total` and Content-Length
#     on the first frame, byte-identical windows, an open range to the end, and
#     416 `bytes */total` past the end. Before core e7f6dac/8ea97ca the first
#     frame carried no total and every 206 went out without these headers — a
#     player cannot seek on that, and no unit test could see it.
#   * A playback ticket is a narrow credential: it opens exactly one file, is
#     refused as a bearer, is capped at 30 minutes, is minted only for media,
#     serves an allowlisted media type with nosniff, and dies with the session
#     that minted it.
#   * The bearer path still serves application/octet-stream, and the download
#     ticket still works.
#
# Self-contained: generates a small clip with ffmpeg (H.264 or VP9). Set MEDIA_SRC to a
# real recording to run it against something camera-shaped (the 137 MB clip
# used during development exercised the multi-chunk v2 seek path).
#
# Env: BASE, FE_USER, FE_PASS, FE_TENANT (default 'default'), MEDIA_SRC.
# SKIPs (exit 0) when the bridge is down, credentials are unset, or ffmpeg is
# missing and no MEDIA_SRC was given.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="${BASE:-http://localhost:8090}"
TENANT="${FE_TENANT:-default}"
. "$HERE/lib_login.sh"

[ -n "${FE_USER:-}" ] && [ -n "${FE_PASS:-}" ] || { echo "SKIP: set FE_USER and FE_PASS"; exit 0; }
curl -s -o /dev/null --max-time 3 "$BASE/v1/whoami" || { echo "SKIP: bridge not reachable at $BASE"; exit 0; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

SRC="${MEDIA_SRC:-}"
if [ -z "$SRC" ]; then
    command -v ffmpeg >/dev/null || { echo "SKIP: ffmpeg not found and MEDIA_SRC unset"; exit 0; }
    # ~2-3 MB: larger than one 1 MiB stream chunk, so windows cross frames.
    # H.264/MP4 where the build has libx264; otherwise VP9/WebM (Fedora's
    # ffmpeg-free has no libx264) — which is what published renditions are.
    if ffmpeg -hide_banner -encoders 2>/dev/null | grep -q libx264; then
        SRC="$W/clip.mp4"; venc=(-c:v libx264 -b:v 3M -c:a aac -movflags +faststart)
    else
        SRC="$W/clip.webm"; venc=(-c:v libvpx-vp9 -b:v 3M -deadline realtime -cpu-used 8 -c:a libopus)
    fi
    ffmpeg -loglevel error -f lavfi -i testsrc2=size=1280x720:rate=30 \
           -f lavfi -i sine=frequency=440 -t 6 "${venc[@]}" -shortest "$SRC" \
        || { echo "FAIL: could not generate a test clip"; exit 1; }
fi
TOTAL=$(stat -c %s "$SRC")
EXT="${SRC##*.}"; EXT="${EXT,,}"
case "$EXT" in
    mp4|m4v) MIME=video/mp4 ;; webm) MIME=video/webm ;; mov) MIME="" ;;
    *) echo "SKIP: MEDIA_SRC extension .$EXT is not a playback type"; exit 0 ;;
esac
[ -n "$MIME" ] || { echo "SKIP: .mov is not on the playback allowlist"; exit 0; }
[ "$TOTAL" -gt 1100000 ] || { echo "FAIL: MEDIA_SRC must exceed ~1.1 MB to test windowing"; exit 1; }

pass=0; fail=0
ok()  { echo "  PASS $*"; pass=$((pass+1)); }
bad() { echo "  FAIL $*"; fail=$((fail+1)); }
hdr() { grep -i "^$1:" "$2" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ //'; }
status() { head -1 "$1" | awk '{print $2}'; }
jget() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

TOK=$(fe_login "$FE_USER" "$FE_PASS" "$TENANT") || { echo "FAIL: login"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOK" -H "X-Tenant: $TENANT")
TAG="e2e-playback-$$"

mkfile() {
    curl -s "${AUTH[@]}" -X POST "$BASE/v1/dirs/root/files" \
         -H 'Content-Type: application/json' -d "{\"name\":\"$1\"}" | jget uid
}
VID=$(mkfile "$TAG.$EXT"); TXT=$(mkfile "$TAG.txt")
[ -n "$VID" ] && [ -n "$TXT" ] || { echo "FAIL: could not create test files"; exit 1; }
cleanup_files() {
    local t
    t=$(fe_login "$FE_USER" "$FE_PASS" "$TENANT") || return
    for u in $VID $TXT; do
        curl -s -o /dev/null -H "Authorization: Bearer $t" -H "X-Tenant: $TENANT" \
             -X DELETE "$BASE/v1/files/$u"
    done
}
trap 'cleanup_files; rm -rf "$W"' EXIT

code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X PUT --data-binary @"$SRC" \
       -H 'Content-Type: application/octet-stream' "$BASE/v1/files/$VID/content")
case "$code" in 200|201|204) ;; *) echo "FAIL: upload $code"; exit 1;; esac
curl -s -o /dev/null "${AUTH[@]}" -X PUT --data-binary 'hello' "$BASE/v1/files/$TXT/content"

A=1000000; B=1099999   # crosses the 1 MiB chunk boundary
echo "== bearer Range"
curl -s -D "$W/h" -o "$W/b" "${AUTH[@]}" -H "Range: bytes=$A-$B" "$BASE/v1/files/$VID/content"
[ "$(status "$W/h")" = 206 ] && ok "206" || bad "status $(status "$W/h")"
[ "$(hdr Content-Range "$W/h")" = "bytes $A-$B/$TOTAL" ] && ok "exact Content-Range" \
    || bad "Content-Range '$(hdr Content-Range "$W/h")'"
[ "$(hdr Content-Length "$W/h")" = $((B-A+1)) ] && ok "exact Content-Length" \
    || bad "Content-Length '$(hdr Content-Length "$W/h")'"
cmp -s "$W/b" <(tail -c +$((A+1)) "$SRC" | head -c $((B-A+1))) && ok "window bytes identical" || bad "window bytes differ"
[ "$(hdr Accept-Ranges "$W/h")" = bytes ] && ok "Accept-Ranges: bytes" || bad "no Accept-Ranges"
[ "$(hdr Content-Type "$W/h")" = application/octet-stream ] && ok "bearer path stays octet-stream" \
    || bad "type '$(hdr Content-Type "$W/h")'"
[ "$(hdr X-Content-Type-Options "$W/h")" = nosniff ] && ok "nosniff" || bad "no nosniff"

echo "== open-ended, suffix-of-file, past the end"
curl -s -D "$W/h" -o "$W/b" "${AUTH[@]}" -H "Range: bytes=$((TOTAL-595))-" "$BASE/v1/files/$VID/content"
[ "$(hdr Content-Range "$W/h")" = "bytes $((TOTAL-595))-$((TOTAL-1))/$TOTAL" ] && ok "open range to the end" \
    || bad "'$(hdr Content-Range "$W/h")'"
cmp -s "$W/b" <(tail -c 595 "$SRC") && ok "tail bytes identical" || bad "tail bytes differ"
for start in "$TOTAL" "$((TOTAL+5000))"; do
    curl -s -D "$W/h" -o /dev/null "${AUTH[@]}" -H "Range: bytes=$start-" "$BASE/v1/files/$VID/content"
    [ "$(status "$W/h")" = 416 ] && [ "$(hdr Content-Range "$W/h")" = "bytes */$TOTAL" ] \
        && ok "416 bytes */total at offset $start" \
        || bad "past end ($start): $(status "$W/h") '$(hdr Content-Range "$W/h")'"
done

echo "== whole file"
curl -s -D "$W/h" "${AUTH[@]}" "$BASE/v1/files/$VID/content" | sha256sum > "$W/got"
[ "$(status "$W/h")" = 200 ] && ok "no Range -> 200" || bad "status $(status "$W/h")"
[ "$(hdr Content-Length "$W/h")" = "$TOTAL" ] && ok "Content-Length = total" || bad "len '$(hdr Content-Length "$W/h")'"
[ "$(cut -d' ' -f1 "$W/got")" = "$(sha256sum "$SRC" | cut -d' ' -f1)" ] && ok "SHA-256 identical" || bad "whole file differs"

echo "== playback ticket"
R=$(curl -s "${AUTH[@]}" -X POST "$BASE/v1/files/$VID/playback-ticket")
T=$(printf '%s' "$R" | jget ticket); EXP=$(printf '%s' "$R" | jget expires_in)
[ -n "$T" ] && ok "minted" || bad "mint: $R"
[ -n "$EXP" ] && [ "$EXP" -le 1800 ] && [ "$EXP" -gt 0 ] && ok "lifetime $EXP s (<= 30 min cap)" || bad "expires_in '$EXP'"
curl -s -D "$W/h" -o "$W/b" -H 'Range: bytes=500-1499' "$BASE/v1/files/$VID/content?ticket=$T"
[ "$(status "$W/h")" = 206 ] && ok "ticketed Range 206" || bad "ticketed: $(status "$W/h")"
[ "$(hdr Content-Type "$W/h")" = "$MIME" ] && ok "served as $MIME" || bad "type '$(hdr Content-Type "$W/h")'"
[ "$(hdr X-Content-Type-Options "$W/h")" = nosniff ] && ok "nosniff under a ticket" || bad "no nosniff"
cmp -s "$W/b" <(tail -c +501 "$SRC" | head -c 1000) && ok "ticketed bytes identical" || bad "ticketed bytes differ"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/files/$TXT/content?ticket=$T")
[ "$code" = 401 ] && ok "ticket opens no other file (401)" || bad "other file: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $T" "$BASE/v1/files/$VID/content")
[ "$code" = 401 ] && ok "ticket refused as a bearer (401)" || bad "as bearer: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/files/$VID/content?ticket=${T%?}x")
[ "$code" = 401 ] && ok "tampered ticket refused (401)" || bad "tampered: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" -X POST "$BASE/v1/files/$TXT/playback-ticket")
[ "$code" = 415 ] && ok "no playback ticket for non-media (415)" || bad "txt ticket: $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/files/$VID/playback-ticket")
[ "$code" = 401 ] && ok "minting needs a session (401)" || bad "anonymous mint: $code"

echo "== download ticket unchanged"
D=$(curl -s "${AUTH[@]}" -X POST "$BASE/v1/files/$TXT/download-ticket" | jget ticket)
body=$(curl -s -D "$W/h" "$BASE/v1/files/$TXT/content?ticket=$D")
[ "$body" = hello ] && [ "$(hdr Content-Type "$W/h")" = application/octet-stream ] \
    && ok "download ticket: bytes + octet-stream" || bad "download ticket: '$body' '$(hdr Content-Type "$W/h")'"

echo "== sign-out revokes the session's tickets"
curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $TOK" "$BASE/v1/auth/token"
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Range: bytes=0-99' "$BASE/v1/files/$VID/content?ticket=$T")
[ "$code" = 401 ] && ok "playback ticket dead after sign-out (401)" || bad "after sign-out: $code"

echo "RESULT: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
