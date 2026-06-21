#!/bin/bash
# End-to-end tests for the FileEngine HTTP REST bridge.
# Assumes the service is already running (default http://localhost:8090) and a
# live FileEngine gRPC core + LDAP directory are reachable.
#
# Usage: BASE=http://localhost:8090 ./tests/test_e2e.sh

BASE="${BASE:-http://localhost:8090}"
PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }

echo "=========================================================="
echo " FileEngine HTTP bridge — E2E   base=$BASE"
echo "=========================================================="

# ---- health ----
echo "[health]"
body=$(curl -s -o /tmp/hb_body -w '%{http_code}' "$BASE/healthz"); code=$body
[ "$code" = "200" ] && ok "GET /healthz -> 200" || bad "GET /healthz -> 200" "got $code"
if grep -q '"status"' /tmp/hb_body && grep -q 'ok' /tmp/hb_body; then ok "healthz body {status: ok}"; else bad "healthz body" "$(cat /tmp/hb_body)"; fi

# ---- auth + tenant (whoami) ----
echo "[auth]"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "whoami without creds -> 401" || bad "whoami without creds -> 401" "got $code"

out=$(curl -s -u testuser:password "$BASE/v1/whoami")
grep -q '"user":"testuser"' <<<"$out" && ok "whoami authenticates testuser (LDAP)" || bad "whoami testuser" "$out"
grep -q '"tenant":"default"' <<<"$out" && ok "default tenant (non-subdomain)" || bad "default tenant" "$out"
grep -q 'system_admin' <<<"$out" && ok "administrators group -> system_admin role" || bad "system_admin role" "$out"

code=$(curl -s -o /dev/null -w '%{http_code}' -u testuser:wrongpass "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "wrong password -> 401" || bad "wrong password -> 401" "got $code"

out=$(curl -s -u testuser:password -H 'X-Tenant: acme' "$BASE/v1/whoami")
grep -q '"tenant":"acme"' <<<"$out" && ok "X-Tenant header overrides tenant" || bad "X-Tenant override" "$out"

# ---- filesystem round-trip ----
echo "[filesystem]"
ROOT="00000000-0000-0000-0000-000000000000"      # all-zeros UUID = root
SUF="hb_$(date +%s)_$RANDOM"
A=(-u testuser:password)
uidof() { grep -oE '"uid":"[a-f0-9-]+"' | head -1 | sed 's/.*"uid":"//;s/"//'; }

out=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$ROOT" -d "{\"name\":\"$SUF\"}")
DIR=$(uidof <<<"$out"); [ -n "$DIR" ] && ok "POST /v1/dirs (create dir under root) -> uid" || bad "create dir" "$out"

out=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$DIR/files" -d '{"name":"hello.txt"}')
FILE=$(uidof <<<"$out"); [ -n "$FILE" ] && ok "POST /v1/dirs/{uid}/files (create file) -> uid" || bad "create file" "$out"

code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X PUT "$BASE/v1/files/$FILE/content" --data-binary 'hello rest world')
[ "$code" = "204" ] || [ "$code" = "200" ] && ok "PUT /v1/files/{uid}/content -> 2xx" || bad "put content" "got $code"

out=$(curl -s "${A[@]}" "$BASE/v1/files/$FILE/content")
[ "$out" = "hello rest world" ] && ok "GET content roundtrip matches" || bad "get content" "$out"

out=$(curl -s "${A[@]}" "$BASE/v1/nodes/$FILE")
grep -q '"name":"hello.txt"' <<<"$out" && ok "GET /v1/nodes/{uid} stat" || bad "stat" "$out"

out=$(curl -s "${A[@]}" "$BASE/v1/dirs/$DIR")
grep -q 'hello.txt' <<<"$out" && ok "GET /v1/dirs/{uid} lists file" || bad "list dir" "$out"

code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/files/$FILE")
{ [ "$code" = "204" ] || [ "$code" = "200" ]; } && ok "DELETE /v1/files/{uid} -> 2xx" || bad "delete file" "got $code"

curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/dirs/$DIR"   # cleanup

echo "=========================================================="
echo " RESULTS:  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -gt 0 ] && { echo " Failed:"; printf '   - %s\n' "${FAILED[@]}"; }
echo "=========================================================="
[ "$FAIL" -eq 0 ]
