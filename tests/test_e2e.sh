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

# ---- token auth ----
echo "[token auth]"
out=$(curl -s -u testuser:password -X POST "$BASE/v1/auth/token")
TOKEN=$(grep -oE '"token":"[a-f0-9]+"' <<<"$out" | sed 's/.*"token":"//;s/"//')
[ -n "$TOKEN" ] && ok "POST /v1/auth/token issues token" || bad "issue token" "$out"
grep -q '"token_type":"Bearer"' <<<"$out" && ok "token_type Bearer + expires_in" || bad "token_type" "$out"
grep -q '"user":"testuser"' <<<"$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/whoami")" && ok "Bearer token authenticates (no LDAP)" || bad "bearer auth"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer deadbeefbogus' "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "bogus bearer -> 401" || bad "bogus bearer" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE/v1/auth/token")
[ "$code" = "204" ] && ok "DELETE /v1/auth/token (revoke) -> 204" || bad "revoke" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "revoked token -> 401" || bad "revoked token" "got $code"

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

# ---- streaming (large file) + Range ----
echo "[streaming + range]"
SD=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$ROOT" -d "{\"name\":\"${SUF}_stream\"}" | uidof)
BF=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$SD/files" -d '{"name":"big.bin"}' | uidof)
# 2 MiB of deterministic data
head -c 2097152 /dev/zero | tr '\0' 'A' > /tmp/hb_big.bin
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X PUT "$BASE/v1/files/$BF/content" --data-binary @/tmp/hb_big.bin)
{ [ "$code" = "204" ] || [ "$code" = "200" ]; } && ok "PUT 2MiB (streaming upload) -> 2xx" || bad "stream upload" "got $code"
curl -s "${A[@]}" "$BASE/v1/files/$BF/content" -o /tmp/hb_big_dl.bin
[ "$(wc -c </tmp/hb_big_dl.bin)" = "2097152" ] && ok "GET 2MiB (streaming download) full size" || bad "stream download size" "$(wc -c </tmp/hb_big_dl.bin)"
cmp -s /tmp/hb_big.bin /tmp/hb_big_dl.bin && ok "streamed content matches" || bad "stream content mismatch"
# Range request: bytes 0-9 (10 bytes)
code=$(curl -s -o /tmp/hb_range -w '%{http_code}' "${A[@]}" -H 'Range: bytes=0-9' "$BASE/v1/files/$BF/content")
[ "$code" = "206" ] && ok "Range request -> 206" || bad "range status" "got $code"
[ "$(wc -c </tmp/hb_range)" = "10" ] && ok "Range returns requested 10 bytes" || bad "range size" "$(wc -c </tmp/hb_range)"
curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/dirs/$SD"   # cleanup
rm -f /tmp/hb_big.bin /tmp/hb_big_dl.bin /tmp/hb_range

# ---- versioning + metadata + manipulation ----
echo "[versioning + metadata + manipulation]"
WS=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$ROOT" -d "{\"name\":\"${SUF}_ext\"}" | uidof)
F2=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$WS/files" -d '{"name":"v.txt"}' | uidof)
curl -s -o /dev/null "${A[@]}" -X PUT "$BASE/v1/files/$F2/content" --data-binary 'v1'
sleep 1; curl -s -o /dev/null "${A[@]}" -X PUT "$BASE/v1/files/$F2/content" --data-binary 'v2'
sleep 1; curl -s -o /dev/null "${A[@]}" -X PUT "$BASE/v1/files/$F2/content" --data-binary 'v3'

out=$(curl -s "${A[@]}" "$BASE/v1/files/$F2/versions")
vc=$(grep -oE '[0-9]{8}_[0-9]{6}' <<<"$out" | wc -l)
[ "$vc" -ge 3 ] && ok "GET /v1/files/{uid}/versions ($vc)" || bad "versions list" "$out"
TS=$(grep -oE '[0-9]{8}_[0-9]{6}(\.[0-9]+)?' <<<"$out" | head -1)
out=$(curl -s "${A[@]}" "$BASE/v1/files/$F2/versions/$TS")
[ -n "$out" ] && ok "GET specific version" || bad "get version" "$out"
out=$(curl -s "${A[@]}" -X POST "$BASE/v1/files/$F2/restore" -d "{\"version_timestamp\":\"$TS\"}")
grep -q 'restored_version' <<<"$out" && ok "POST restore version" || bad "restore" "$out"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/files/$F2/purge" -d '{"keep_count":1}')
[ "$code" = "204" ] && ok "POST purge -> 204" || bad "purge" "got $code"

curl -s -o /dev/null "${A[@]}" -X PUT "$BASE/v1/nodes/$F2/metadata/color" -d '{"value":"blue"}'
out=$(curl -s "${A[@]}" "$BASE/v1/nodes/$F2/metadata/color")
grep -q '"value":"blue"' <<<"$out" && ok "metadata PUT+GET key" || bad "metadata get" "$out"
out=$(curl -s "${A[@]}" "$BASE/v1/nodes/$F2/metadata")
grep -q '"color":"blue"' <<<"$out" && ok "metadata GET all" || bad "metadata getall" "$out"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/nodes/$F2/metadata/color")
[ "$code" = "204" ] && ok "metadata DELETE -> 204" || bad "metadata delete" "got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/nodes/$F2/rename" -d '{"new_name":"renamed_v.txt"}')
[ "$code" = "204" ] && ok "POST rename -> 204" || bad "rename" "got $code"
grep -q '"exists":true'  <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/$F2/exists")" && ok "exists true" || bad "exists true"
grep -q '"exists":false' <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/deadbeef-0000-0000-0000-000000000000/exists")" && ok "exists false (bogus uid)" || bad "exists false"
curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/files/$F2"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/files/$F2/undelete")
[ "$code" = "204" ] && ok "soft-delete + POST undelete -> 204" || bad "undelete" "got $code"
SUB=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$WS" -d '{"name":"sub"}' | uidof)
CF=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$WS/files" -d '{"name":"copyme.txt"}' | uidof)
curl -s -o /dev/null "${A[@]}" -X PUT "$BASE/v1/files/$CF/content" --data-binary 'copy me'
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/nodes/$CF/copy" -d "{\"destination_parent_uid\":\"$SUB\"}")
[ "$code" = "204" ] && ok "POST copy -> 204" || bad "copy" "got $code"
grep -q 'copyme.txt' <<<"$(curl -s "${A[@]}" "$BASE/v1/dirs/$SUB")" && ok "copied file appears in dest" || bad "copy result"

# error mapping
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" "$BASE/v1/nodes/deadbeef-0000-0000-0000-000000000000")
{ [ "$code" = "404" ] || [ "$code" = "500" ]; } && ok "stat bogus uid -> error status ($code)" || bad "stat bogus" "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" "$BASE/v1/bogus/resource")
[ "$code" = "404" ] && ok "unknown route -> 404" || bad "unknown route" "got $code"

curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/dirs/$WS"   # cleanup

# ---- admin + roles + ACL ----
echo "[admin + roles + ACL]"
grep -q 'total_space' <<<"$(curl -s "${A[@]}" "$BASE/v1/storage")" && ok "GET /v1/storage" || bad "storage"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/sync")
[ "$code" = "204" ] && ok "POST /v1/sync -> 204" || bad "sync" "got $code"

ROLE="hbrole_$(date +%s)"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/roles" -d "{\"role\":\"$ROLE\"}")
[ "$code" = "201" ] && ok "POST /v1/roles -> 201" || bad "create role" "got $code"
grep -q "$ROLE" <<<"$(curl -s "${A[@]}" "$BASE/v1/roles")" && ok "GET /v1/roles lists new role" || bad "list roles"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X PUT "$BASE/v1/roles/$ROLE/users/carol")
[ "$code" = "204" ] && ok "PUT assign user to role -> 204" || bad "assign role" "got $code"
grep -q 'carol' <<<"$(curl -s "${A[@]}" "$BASE/v1/roles/$ROLE/users")" && ok "GET /v1/roles/{role}/users" || bad "role users"
grep -q "$ROLE" <<<"$(curl -s "${A[@]}" "$BASE/v1/users/carol/roles")" && ok "GET /v1/users/{user}/roles" || bad "user roles"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/roles/$ROLE/users/carol")
[ "$code" = "204" ] && ok "DELETE remove user from role -> 204" || bad "remove role member" "got $code"

GD=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$ROOT" -d "{\"name\":\"acl_$(date +%s)\"}" | uidof)
GF=$(curl -s "${A[@]}" -X POST "$BASE/v1/dirs/$GD/files" -d '{"name":"acl.txt"}' | uidof)
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"dave","permission":"r"}')
[ "$code" = "204" ] && ok "POST grant READ to dave -> 204" || bad "grant" "got $code"
grep -q '"has_permission":true' <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/$GF/permissions?user=dave&permission=r")" && ok "GET check: dave has READ" || bad "check perm true"
# role-based grant + role check
curl -s -o /dev/null "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d "{\"principal\":\"role:$ROLE\",\"permission\":\"r\"}"
grep -q '"has_permission":true' <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/$GF/permissions?user=carol&permission=r&roles=$ROLE")" && ok "GET check: carol(role) has READ" || bad "role check"
# deny precedence
curl -s -o /dev/null "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"erin","permission":"r"}'
curl -s -o /dev/null "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"erin","permission":"r","effect":"deny"}'
grep -q '"has_permission":false' <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/$GF/permissions?user=erin&permission=r")" && ok "DENY overrides ALLOW" || bad "deny precedence"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"dave","permission":"r"}')
[ "$code" = "204" ] && ok "DELETE revoke permission -> 204" || bad "revoke" "got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/roles/$ROLE")
[ "$code" = "204" ] && ok "DELETE /v1/roles/{role} -> 204" || bad "delete role" "got $code"
curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/dirs/$GD"   # cleanup

echo "=========================================================="
echo " RESULTS:  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -gt 0 ] && { echo " Failed:"; printf '   - %s\n' "${FAILED[@]}"; }
echo "=========================================================="
[ "$FAIL" -eq 0 ]
