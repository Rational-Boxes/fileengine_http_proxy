#!/bin/bash
# Self-contained OAuth2/OIDC (BFF) tests for the HTTP bridge.
#
# Unlike test_e2e.sh, this script stands up its own mock IdP and its own bridge
# instance, so it needs NO live FileEngine core. A live LDAP is only needed for
# the happy-path token-issuance check (auto-skipped when absent); everything else
# — redirect/PKCE, state CSRF/replay, open-redirect rejection, code exchange +
# userinfo, email_verified enforcement — runs without LDAP.
#
# Requires: python3, curl, a built ./build/http_bridge.
# Usage: ./tests/test_oauth.sh

set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/build/http_bridge"
PORT="${PORT:-8097}"
IDP_PORT="${IDP_PORT:-8098}"
BASE="http://localhost:$PORT"
IDP="http://127.0.0.1:$IDP_PORT"
RETURN_OK="http://localhost:3000/oauth/callback"

PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31m✗\033[0m %s\n     %s\n' "$1" "${2:-}"; }

[ -x "$BIN" ] || { echo "build first: $BIN missing"; exit 1; }

TMP="$(mktemp -d)"
cleanup() {
    [ -n "${BRIDGE_PID:-}" ] && kill "$BRIDGE_PID" 2>/dev/null
    [ -n "${IDP_PID:-}" ] && kill "$IDP_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# ---- mock IdP -------------------------------------------------------------
cat > "$TMP/idp.py" <<PY
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _j(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        if self.path.startswith("/token"):
            self._j(200, {"access_token": "mock-access-token", "token_type": "Bearer"})
        else:
            self._j(404, {"error": "nope"})
    def do_GET(self):
        if self.path.startswith("/userinfo_unverified"):
            self._j(200, {"sub": "u2", "email": "unverified@example.com", "email_verified": False})
        elif self.path.startswith("/userinfo"):
            self._j(200, {"sub": "u1", "email": "oauthuser@example.com", "email_verified": True})
        elif self.path.startswith("/authorize"):
            self._j(200, {"ok": True})
        else:
            self._j(404, {"error": "nope"})
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", $IDP_PORT), H).serve_forever()
PY
python3 "$TMP/idp.py" & IDP_PID=$!

# ---- bridge instance (env-only config; unreachable LDAP/core are fine) -----
export HTTP_PORT="$PORT"
export FILEENGINE_GRPC_HOST=127.0.0.1 FILEENGINE_GRPC_PORT=59999  # no core needed here
export FILEENGINE_LDAP_ENDPOINT="ldap://127.0.0.1:59998"          # unreachable => 403 on lookup
export LOG_LEVEL=warn
export OAUTH_REDIRECT_BASE="$BASE"
export OAUTH_RETURN_ALLOWLIST="http://localhost:3000/"
export OAUTH_STATE_TTL_SECONDS=300
export OAUTH_PROVIDERS="mock,mockunverified"
export OAUTH_MOCK_KIND=oidc OAUTH_MOCK_CLIENT_ID=cid OAUTH_MOCK_CLIENT_SECRET=sec \
       OAUTH_MOCK_AUTH_URL="$IDP/authorize" OAUTH_MOCK_TOKEN_URL="$IDP/token" \
       OAUTH_MOCK_USERINFO_URL="$IDP/userinfo" OAUTH_MOCK_SCOPES="openid email"
export OAUTH_MOCKUNVERIFIED_KIND=oidc OAUTH_MOCKUNVERIFIED_CLIENT_ID=cid OAUTH_MOCKUNVERIFIED_CLIENT_SECRET=sec \
       OAUTH_MOCKUNVERIFIED_AUTH_URL="$IDP/authorize" OAUTH_MOCKUNVERIFIED_TOKEN_URL="$IDP/token" \
       OAUTH_MOCKUNVERIFIED_USERINFO_URL="$IDP/userinfo_unverified" OAUTH_MOCKUNVERIFIED_SCOPES="openid email"

( cd "$TMP" && "$BIN" ) > "$TMP/bridge.log" 2>&1 & BRIDGE_PID=$!

# wait for liveness
for _ in $(seq 1 50); do
    curl -sf "$BASE/healthz" >/dev/null 2>&1 && break
    sleep 0.1
done
curl -sf "$BASE/healthz" >/dev/null 2>&1 || { echo "bridge did not start"; cat "$TMP/bridge.log"; exit 1; }

echo "=========================================================="
echo " HTTP bridge — OAuth2 (BFF)   base=$BASE  idp=$IDP"
echo "=========================================================="

# Extract the Location header of a start request.
location() { curl -s -D - -o /dev/null "$1" | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}'; }
statuscode() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# Mint a fresh state for a provider; echo the state value.
mint_state() {
    local prov="$1"
    location "$BASE/v1/auth/oauth/$prov?return_to=$RETURN_OK" \
        | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p'
}

echo "[authorize / redirect]"
loc=$(location "$BASE/v1/auth/oauth/mock?return_to=$RETURN_OK")
[ -n "$loc" ] && grep -q '^'"$IDP"'/authorize' <<<"$loc" && ok "start -> 302 to IdP authorize" || bad "start redirect" "$loc"
grep -q 'state=' <<<"$loc" && ok "authorize URL carries state" || bad "state in authorize" "$loc"
grep -q 'code_challenge=' <<<"$loc" && grep -q 'code_challenge_method=S256' <<<"$loc" \
    && ok "authorize URL carries PKCE S256 challenge" || bad "PKCE in authorize" "$loc"
grep -q 'response_type=code' <<<"$loc" && ok "authorize URL is code flow" || bad "response_type" "$loc"

code=$(statuscode "$BASE/v1/auth/oauth/mock")  # no return_to -> falls back to allowlist[0]
[ "$code" = "302" ] && ok "start without return_to uses allowlist default -> 302" || bad "default return_to" "got $code"

echo "[guards]"
code=$(statuscode "$BASE/v1/auth/oauth/doesnotexist?return_to=$RETURN_OK")
[ "$code" = "404" ] && ok "unknown provider -> 404" || bad "unknown provider" "got $code"
code=$(statuscode "$BASE/v1/auth/oauth/mock?return_to=https://evil.example/")
[ "$code" = "400" ] && ok "open-redirect return_to rejected -> 400" || bad "open redirect" "got $code"

echo "[callback: state CSRF / replay]"
code=$(statuscode "$BASE/v1/auth/oauth/mock/callback?code=abc&state=boguszzz")
[ "$code" = "400" ] && ok "unknown state -> 400" || bad "unknown state" "got $code"

st=$(mint_state mock)
[ -n "$st" ] && ok "minted state for replay test" || bad "mint state" "(empty)"
# First use: state is consumed, flow proceeds to LDAP and 403s (no LDAP match).
c1=$(statuscode "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st")
# Second use: same state must now be rejected as already-consumed.
c2=$(statuscode "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st")
[ "$c1" != "400" ] && ok "first callback consumes state (got $c1, not 400)" || bad "first consume" "got $c1"
[ "$c2" = "400" ] && ok "replayed state -> 400 (one-shot consume)" || bad "replay" "got $c2"

st=$(mint_state mock)
code=$(statuscode "$BASE/v1/auth/oauth/mockunverified/callback?code=abc&state=$st")
[ "$code" = "400" ] && ok "state bound to provider (mismatch -> 400)" || bad "provider binding" "got $code"

echo "[callback: identity verification]"
# Verified email, exchange + userinfo succeed, but no LDAP entry -> 403 no match.
st=$(mint_state mock)
out=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st")
[ "$out" = "403" ] && ok "verified email, no LDAP match -> 403 (exchange+userinfo reached)" || bad "no-match 403" "got $out"
# Unverified email is rejected before any LDAP lookup.
st=$(mint_state mockunverified)
out=$(curl -s "$BASE/v1/auth/oauth/mockunverified/callback?code=abc&state=$st")
grep -q 'not verified' <<<"$out" && ok "email_verified=false -> rejected" || bad "email_verified" "$out"

echo "[happy path: requires live LDAP with mail=oauthuser@example.com]"
st=$(mint_state mock)
loc=$(location "$BASE/v1/auth/oauth/mock/callback?code=abc&state=$st")
if grep -q '#token=' <<<"$loc"; then
    tok=$(sed -n 's/.*#token=\([^&]*\).*/\1/p' <<<"$loc")
    grep -q '^'"$RETURN_OK" <<<"$loc" && ok "success redirects to allowlisted return_to" || bad "return redirect" "$loc"
    grep -q '"user"' <<<"$(curl -s -H "Authorization: Bearer $tok" "$BASE/v1/whoami")" \
        && ok "OAuth-issued bearer authenticates /v1/whoami" || bad "bearer whoami"
else
    echo "  (skipped: no LDAP match — got: ${loc:-<no redirect>})"
fi

echo "=========================================================="
echo " RESULTS:  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -gt 0 ] && { echo " Failed:"; printf '   - %s\n' "${FAILED[@]}"; }
echo "=========================================================="
[ "$FAIL" -eq 0 ]
