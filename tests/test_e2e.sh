#!/bin/bash
# End-to-end tests for the FileEngine HTTP REST bridge.
# Assumes the service is already running (default http://localhost:8090) and a
# live FileEngine gRPC core + LDAP directory are reachable.
#
# Usage: BASE=http://localhost:8090 \
#        FE_USER=<login> FE_PASS=<password> [FE_EXPECT_USER=<resolved uid>] \
#        ./tests/test_e2e.sh
# Credentials/identity are configurable so the suite runs against any directory
# (defaults match a testuser:password fixture).

BASE="${BASE:-http://localhost:8090}"
CRED="${FE_USER:-testuser}:${FE_PASS:-password}"
WRONG="${FE_USER:-testuser}:wrongpass-nope"
EXPECT_USER="${FE_EXPECT_USER:-${FE_USER:-testuser}}"
CORS_ORIGIN="${FE_CORS_ORIGIN:-https://app.example.com}"   # must match the bridge's HTTP_CORS_ORIGIN
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

out=$(curl -s -u "$CRED" "$BASE/v1/whoami")
grep -q "\"user\":\"$EXPECT_USER\"" <<<"$out" && ok "whoami authenticates testuser (LDAP)" || bad "whoami testuser" "$out"
grep -q '"tenant":"default"' <<<"$out" && ok "default tenant (non-subdomain)" || bad "default tenant" "$out"
grep -q 'system_admin' <<<"$out" && ok "administrators group -> system_admin role" || bad "system_admin role" "$out"

code=$(curl -s -o /dev/null -w '%{http_code}' -u "$WRONG" "$BASE/v1/whoami")
[ "$code" = "401" ] && ok "wrong password -> 401" || bad "wrong password -> 401" "got $code"

out=$(curl -s -u "$CRED" -H 'X-Tenant: acme' "$BASE/v1/whoami")
grep -q '"tenant":"acme"' <<<"$out" && ok "X-Tenant header overrides tenant" || bad "X-Tenant override" "$out"

# ---- token auth ----
echo "[token auth]"
out=$(curl -s -u "$CRED" -X POST "$BASE/v1/auth/token")
TOKEN=$(grep -oE '"token":"[a-f0-9]+"' <<<"$out" | sed 's/.*"token":"//;s/"//')
[ -n "$TOKEN" ] && ok "POST /v1/auth/token issues token" || bad "issue token" "$out"
grep -q '"token_type":"Bearer"' <<<"$out" && ok "token_type Bearer + expires_in" || bad "token_type" "$out"
grep -q "\"user\":\"$EXPECT_USER\"" <<<"$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/whoami")" && ok "Bearer token authenticates (no LDAP)" || bad "bearer auth"
# token introspection (consumed by downstream services for auth coordination)
intro=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/v1/auth/introspect")
{ grep -q '"active":true' <<<"$intro" && grep -q "\"user\":\"$EXPECT_USER\"" <<<"$intro"; } \
  && ok "GET /v1/auth/introspect -> active + identity" || bad "introspect" "$intro"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer deadbeefbogus' "$BASE/v1/auth/introspect")
[ "$code" = "401" ] && ok "introspect bogus token -> 401" || bad "introspect bogus" "got $code"
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
A=(-u "$CRED")
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
# self-check defaults to the CALLER's own identity (user + roles): the admin holds
# LIST_DELETED only via its system_admin role, so a no-user/no-roles check must use
# the caller's roles and pass (regression: checkPerm previously dropped them).
grep -q '"has_permission":true' <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/$GF/permissions?permission=l")" && ok "GET check defaults to caller roles (admin has LIST_DELETED)" || bad "self-role check"
# deny precedence
curl -s -o /dev/null "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"erin","permission":"r"}'
curl -s -o /dev/null "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"erin","permission":"r","effect":"deny"}'
grep -q '"has_permission":false' <<<"$(curl -s "${A[@]}" "$BASE/v1/nodes/$GF/permissions?user=erin&permission=r")" && ok "DENY overrides ALLOW" || bad "deny precedence"
# list ACL entries (backs the ACL editor); principals are bare, type 1 = role, effect 1 = DENY
acls=$(curl -s "${A[@]}" "$BASE/v1/nodes/$GF/acls")
{ grep -q '"principal":"dave"' <<<"$acls" && grep -q "\"principal\":\"$ROLE\"" <<<"$acls" && grep -q '"type":1' <<<"$acls"; } \
  && ok "GET /v1/nodes/{uid}/acls lists entries (user + role)" || bad "list acls" "$acls"
grep -q '"effect":1' <<<"$acls" && ok "acls include DENY effect" || bad "acls deny effect" "$acls"
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/nodes/$GF/permissions" -d '{"principal":"dave","permission":"r"}')
[ "$code" = "204" ] && ok "DELETE revoke permission -> 204" || bad "revoke" "got $code"

# ---- principals type-ahead (ACL editor) ----
echo "[principals type-ahead]"
# Seed a CLAIM-type ACL so the claim catalog has something to return.
CLAIM="dept=eng_$(date +%s)"
curl -s -o /dev/null "${A[@]}" -X POST "$BASE/v1/nodes/$GF/permissions" -d "{\"principal\":\"claim:$CLAIM\",\"permission\":\"r\"}"
out=$(curl -s "${A[@]}" "$BASE/v1/principals")
{ grep -q '"roles"' <<<"$out" && grep -q '"claims"' <<<"$out" && grep -q '"users"' <<<"$out"; } \
  && ok "GET /v1/principals returns roles+claims+users" || bad "principals shape" "$out"
grep -q "$CLAIM" <<<"$(curl -s "${A[@]}" "$BASE/v1/principals?types=claim")" \
  && ok "claim catalog includes granted claim" || bad "claim catalog"
grep -q "$CLAIM" <<<"$(curl -s "${A[@]}" "$BASE/v1/principals?types=claim&q=dept=")" \
  && ok "claim prefix filter matches" || bad "claim prefix match"
! grep -q "$CLAIM" <<<"$(curl -s "${A[@]}" "$BASE/v1/principals?types=claim&q=zzz_nomatch")" \
  && ok "claim prefix filter excludes non-matches" || bad "claim prefix exclude"
grep -q "$ROLE" <<<"$(curl -s "${A[@]}" "$BASE/v1/principals?types=role&q=hbrole_")" \
  && ok "role type-ahead by prefix" || bad "role type-ahead"
grep -q '"roles":\[\]' <<<"$(curl -s "${A[@]}" "$BASE/v1/principals?types=claim")" \
  && ok "types=claim yields empty roles array" || bad "types filter"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/principals")
[ "$code" = "401" ] && ok "principals without creds -> 401" || bad "principals auth" "got $code"

code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X DELETE "$BASE/v1/roles/$ROLE")
[ "$code" = "204" ] && ok "DELETE /v1/roles/{role} -> 204" || bad "delete role" "got $code"
curl -s -o /dev/null "${A[@]}" -X DELETE "$BASE/v1/dirs/$GD"   # cleanup

# ---- hardening ----
echo "[hardening]"
# scoped CORS (configured origin, never *)
hdr=$(curl -s -D - -o /dev/null -X OPTIONS -H "Origin: $CORS_ORIGIN" "$BASE/v1/whoami")
grep -qi "access-control-allow-origin: $CORS_ORIGIN" <<<"$hdr" && ok "CORS scoped origin header" || bad "CORS header" "$(grep -i access-control <<<"$hdr" | head -1)"
! grep -qi 'access-control-allow-origin: \*' <<<"$hdr" && ok "CORS is not wildcard" || bad "CORS wildcard"
code=$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS "$BASE/v1/whoami")
[ "$code" = "204" ] && ok "OPTIONS preflight -> 204" || bad "preflight" "got $code"
# body-size cap (config'd to 4 MiB for the test run)
head -c 5242880 /dev/zero > /tmp/hb_toobig
code=$(curl -s -o /dev/null -w '%{http_code}' "${A[@]}" -X PUT "$BASE/v1/files/$ROOT/content" --data-binary @/tmp/hb_toobig)
[ "$code" = "413" ] && ok "oversized body -> 413" || bad "body cap" "got $code"
rm -f /tmp/hb_toobig

echo "=========================================================="
echo " RESULTS:  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -gt 0 ] && { echo " Failed:"; printf '   - %s\n' "${FAILED[@]}"; }
echo "=========================================================="
[ "$FAIL" -eq 0 ]
