#!/bin/bash
# Live end-to-end OAuth2 verification against the REAL LDAP + gRPC core.
#
# Unlike test_oauth.sh (which stubs everything and skips the happy path), this
# starts a second bridge instance wired to the live directory/core, discovers a
# real user's email from LDAP, and drives the full flow including token issuance
# and a /whoami that must match the user's Basic-auth identity.
#
# Prereqs: the live LDAP (:1389) + gRPC core (:50051) running (as configured in
# http_bridge/.env), a built ./build/http_bridge, python3, curl, and either
# `ldapsearch` on PATH or a docker LDAP container (auto-detected). Override
# discovery with:  EMAIL=<email> USER=<uid> PASS=<pw> ./tests/test_oauth_live.sh
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/build/http_bridge"
PORT="${PORT:-8099}"
IDP_PORT="${IDP_PORT:-8096}"
BASE="http://localhost:$PORT"
IDP="http://127.0.0.1:$IDP_PORT"
RETURN_OK="http://localhost:3000/oauth/callback"

USER="${USER_NAME:-testuser}"
PASS="${PASS:-password}"
LDAP_BIND="${LDAP_BIND:-cn=admin,dc=rationalboxes,dc=com}"
LDAP_PW="${LDAP_PW:-admin}"
LDAP_BASE="${LDAP_BASE:-ou=users,dc=rationalboxes,dc=com}"

PASS_N=0; FAIL_N=0; FAILED=()
ok()  { PASS_N=$((PASS_N+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL_N=$((FAIL_N+1)); FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }

[ -x "$BIN" ] || { echo "build first: $BIN missing"; exit 1; }

# --- discover the user's mail from the live LDAP ---------------------------
discover_mail() {
  if [ -n "${EMAIL:-}" ]; then echo "$EMAIL"; return; fi
  if command -v ldapsearch >/dev/null 2>&1; then
    ldapsearch -x -LLL -H ldap://localhost:1389 -D "$LDAP_BIND" -w "$LDAP_PW" \
      -b "$LDAP_BASE" "(uid=$USER)" mail 2>/dev/null | awk -F': ' '/^mail:/{print $2; exit}'
    return
  fi
  local c
  # Pick the LDAP *server* container (image contains openldap/slapd), not the
  # web UI / user-manager which has no ldapsearch.
  c="$(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | awk -F'\t' 'tolower($2) ~ /openldap|slapd/ && tolower($1) !~ /ui|manager/ {print $1; exit}')"
  if [ -n "$c" ]; then
    docker exec "$c" ldapsearch -x -LLL -H ldap://localhost:1389 -D "$LDAP_BIND" -w "$LDAP_PW" \
      -b "$LDAP_BASE" "(uid=$USER)" mail 2>/dev/null | awk -F': ' '/^mail:/{print $2; exit}'
  fi
}

EMAIL="$(discover_mail | tr -d '\r')"
if [ -z "$EMAIL" ]; then
  echo "Could not discover an email for uid=$USER in $LDAP_BASE."
  echo "If the user has no 'mail' attribute, the OAuth happy path cannot map to LDAP."
  echo "Re-run with EMAIL=<email> once the user has a mail attribute."
  exit 1
fi
echo "Discovered $USER mail: $EMAIL"

TMP="$(mktemp -d)"
cleanup() {
  [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null
  [ -n "${IDP_PID:-}" ] && kill "$IDP_PID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- mock IdP that attests the real LDAP email -----------------------------
cat > "$TMP/idp.py" <<PY
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
EMAIL = "$EMAIL"
class H(BaseHTTPRequestHandler):
    def _j(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        if self.path.startswith("/token"): self._j(200, {"access_token":"tok","token_type":"Bearer"})
        else: self._j(404, {"error":"nope"})
    def do_GET(self):
        if self.path.startswith("/userinfo_unverified"):
            self._j(200, {"sub":"x","email":"nobody-no-match@example.com","email_verified":False})
        elif self.path.startswith("/userinfo"):
            self._j(200, {"sub":"x","email":EMAIL,"email_verified":True})
        elif self.path.startswith("/authorize"): self._j(200, {"ok":True})
        else: self._j(404, {"error":"nope"})
    def log_message(self,*a): pass
HTTPServer(("127.0.0.1", $IDP_PORT), H).serve_forever()
PY
python3 "$TMP/idp.py" & IDP_PID=$!

# --- second bridge instance: live LDAP/core (from .env) + OAuth (exported) ---
export HTTP_PORT="$PORT"
export OAUTH_REDIRECT_BASE="$BASE"
export OAUTH_RETURN_ALLOWLIST="http://localhost:3000/"
export OAUTH_PROVIDERS="mock,mockunverified"
export OAUTH_MOCK_KIND=oidc OAUTH_MOCK_CLIENT_ID=cid OAUTH_MOCK_CLIENT_SECRET=sec \
       OAUTH_MOCK_AUTH_URL="$IDP/authorize" OAUTH_MOCK_TOKEN_URL="$IDP/token" \
       OAUTH_MOCK_USERINFO_URL="$IDP/userinfo" OAUTH_MOCK_SCOPES="openid email"
export OAUTH_MOCKUNVERIFIED_KIND=oidc OAUTH_MOCKUNVERIFIED_CLIENT_ID=cid OAUTH_MOCKUNVERIFIED_CLIENT_SECRET=sec \
       OAUTH_MOCKUNVERIFIED_AUTH_URL="$IDP/authorize" OAUTH_MOCKUNVERIFIED_TOKEN_URL="$IDP/token" \
       OAUTH_MOCKUNVERIFIED_USERINFO_URL="$IDP/userinfo_unverified" OAUTH_MOCKUNVERIFIED_SCOPES="openid email"

# Run from the http_bridge dir so .env supplies the live LDAP/core config.
( cd "$HERE" && "$BIN" ) > "$TMP/bridge.log" 2>&1 & BRIDGE_PID=$!
for _ in $(seq 1 50); do curl -sf "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.1; done
curl -sf "$BASE/healthz" >/dev/null 2>&1 || { echo "bridge did not start"; cat "$TMP/bridge.log"; exit 1; }

echo "=========================================================="
echo " HTTP bridge — OAuth2 LIVE e2e   base=$BASE  user=$USER"
echo "=========================================================="

location() { curl -s -D - -o /dev/null "$1" | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}'; }
statuscode() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
mint_state() { location "$BASE/v1/auth/oauth/$1?return_to=$RETURN_OK" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p'; }

# Baseline: Basic-auth identity for the same user.
basic=$(curl -s -u "$USER:$PASS" "$BASE/v1/whoami")
echo "  basic /whoami: $basic"
grep -q "\"user\":\"$USER\"" <<<"$basic" && ok "Basic auth resolves $USER (live LDAP)" || bad "basic whoami" "$basic"

echo "[happy path: OAuth -> token -> whoami]"
st=$(mint_state mock)
[ -n "$st" ] && ok "authorize start issued state" || bad "start state" "(empty)"
loc=$(location "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st")
if grep -q '#token=' <<<"$loc"; then
  ok "callback redirects to return_to with token in fragment"
  grep -q "^$RETURN_OK" <<<"$loc" && ok "redirect target is the allowlisted return_to" || bad "return target" "$loc"
  tok=$(sed -n 's/.*#token=\([^&]*\).*/\1/p' <<<"$loc")
  oauth=$(curl -s -H "Authorization: Bearer $tok" "$BASE/v1/whoami")
  echo "  oauth /whoami: $oauth"
  grep -q "\"user\":\"$USER\"" <<<"$oauth" && ok "OAuth-issued token resolves the SAME user via LDAP" || bad "oauth whoami user" "$oauth"
  [ "$oauth" = "$basic" ] && ok "OAuth identity is byte-identical to Basic identity (uid+tenant+roles)" || bad "identity parity" "basic=$basic oauth=$oauth"
else
  bad "happy path token issuance" "no token in: ${loc:-<no redirect>}"
fi

echo "[negatives, live]"
st=$(mint_state mockunverified)
code=$(statuscode "$BASE/v1/auth/oauth/mockunverified/callback?code=abc&state=$st")
[ "$code" = "403" ] && ok "unverified email -> 403" || bad "unverified" "got $code"
st=$(mint_state mock)
curl -s -o /dev/null "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st"   # consume
code=$(statuscode "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st")     # replay
[ "$code" = "400" ] && ok "replayed state -> 400" || bad "replay" "got $code"
code=$(statuscode "$BASE/v1/auth/oauth/mock?return_to=https://evil.example/")
[ "$code" = "400" ] && ok "open-redirect return_to -> 400" || bad "open redirect" "got $code"

echo "=========================================================="
echo " RESULTS:  PASS=$PASS_N  FAIL=$FAIL_N"
[ "$FAIL_N" -gt 0 ] && { echo " Failed:"; printf '   - %s\n' "${FAILED[@]}"; }
echo "=========================================================="
[ "$FAIL_N" -eq 0 ]
