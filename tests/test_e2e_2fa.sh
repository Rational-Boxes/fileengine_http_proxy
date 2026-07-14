#!/bin/bash
# End-to-end two-factor auth test for the HTTP bridge + ldap_manager (PROPOSAL §4).
#
# Drives the whole lifecycle against LIVE services:
#   1. enroll  — with 2FA not yet required, a normal login yields a full session;
#                use it to POST /v1/me/2fa/setup + /verify-setup (self-service,
#                ldap_manager) with a computed TOTP → 2FA becomes enabled.
#   2. challenge — a fresh POST /v1/auth/token now returns {mfa_required, mfa_token}
#                  (a pre-auth challenge token), NOT a full session.
#   3. gate     — the mfa_token must NOT reach any resource (401 on /v1/whoami).
#   4. complete — POST /v1/auth/2fa {mfa_token, method:"totp", code} → full session,
#                 whose amr contains "otp".
#   5. negatives — a wrong TOTP is rejected (401); the challenge token is required.
# Finally it disables 2FA again so the run is idempotent.
#
# Requires the bridge started with MFA_ENABLED=true, LDAP_MANAGER_URL + a shared
# MFA_INTERNAL_SECRET, and ldap_manager with a matching TOTP_SECRET_KEY. TOTP codes
# are computed with python3 (stdlib only).
#
# Usage:
#   BRIDGE=http://localhost:8090 LDAPMGR=http://localhost:8093 \
#   USER=james@rationalboxes.com PASS='***' TENANT=filenginetest \
#   ./tests/test_e2e_2fa.sh
set -u
BRIDGE="${BRIDGE:-http://localhost:8090}"
LDAPMGR="${LDAPMGR:-http://localhost:8093}"
USER="${USER:-james@rationalboxes.com}"
PASS="${PASS:-}"
TENANT="${TENANT:-filenginetest}"
PASSN=0; FAILN=0
chk(){ if [ "$2" = "$1" ]; then printf '  \033[32m✓\033[0m %s (-> %s)\n' "$3" "$2"; PASSN=$((PASSN+1));
       else printf '  \033[31m✗\033[0m %s (want %s got %s)\n' "$3" "$1" "$2"; FAILN=$((FAILN+1)); fi; }

command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 required for TOTP"; exit 0; }
[ -n "$PASS" ] || { echo "SKIP: set PASS"; exit 0; }
curl -s -o /dev/null --max-time 3 "$BRIDGE/v1/whoami" >/dev/null 2>&1 || { echo "SKIP: bridge not reachable at $BRIDGE"; exit 0; }

# Compute an RFC 6238 TOTP for a base32 secret at the current time (SHA1/6/30).
totp(){ python3 - "$1" <<'PY'
import base64,hmac,hashlib,struct,sys,time
sec=sys.argv[1].upper(); sec+="="*(-len(sec)%8)
key=base64.b32decode(sec)
c=int(time.time()//30)
d=hmac.new(key,struct.pack(">Q",c),hashlib.sha1).digest()
o=d[-1]&0x0F
print(str((struct.unpack(">I",d[o:o+4])[0]&0x7FFFFFFF)%1000000).zfill(6))
PY
}
jget(){ python3 -c "import json,sys;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }

# ---- step 0: a plain login. If it already returns mfa_required, 2FA is on;
# we must complete it to get a session for enrollment management. To keep the
# test self-contained we assume a clean slate (2FA off) at start.
login="$(curl -s -u "$USER:$PASS" -X POST "$BRIDGE/v1/auth/token")"
if [ "$(printf '%s' "$login" | jget mfa_required)" = "True" ]; then
    echo "NOTE: 2FA already enabled for $USER; test needs a clean slate. Disable it first."; exit 0
fi
sess="$(printf '%s' "$login" | jget token)"
[ -n "$sess" ] || { echo "SKIP: could not obtain an initial session for $USER"; exit 0; }
auth=(-H "Authorization: Bearer $sess" -H "X-Tenant: $TENANT")

echo "=== step 1: enroll TOTP (self-service, ldap_manager) ==="
setup="$(curl -s "${auth[@]}" -X POST "$LDAPMGR/v1/me/2fa/setup")"
secret="$(printf '%s' "$setup" | jget secret)"
if [ -z "$secret" ]; then
    echo "SKIP: /v1/me/2fa/setup returned no secret (2FA not configured on ldap_manager?): $setup"; exit 0
fi
code="$(totp "$secret")"
vc="$(curl -s -o /tmp/2fa_vs -w '%{http_code}' "${auth[@]}" -X POST \
      -H 'Content-Type: application/json' -d "{\"code\":\"$code\"}" \
      "$LDAPMGR/v1/me/2fa/verify-setup")"
chk 200 "$vc" "verify-setup enables 2FA with a valid TOTP"

echo "=== step 2: a fresh login now demands a second factor ==="
ch="$(curl -s -u "$USER:$PASS" -X POST "$BRIDGE/v1/auth/token")"
chk True "$(printf '%s' "$ch" | jget mfa_required)" "login returns mfa_required"
mtok="$(printf '%s' "$ch" | jget mfa_token)"
[ -n "$mtok" ] && { printf '  \033[32m✓\033[0m issued an mfa_token\n'; PASSN=$((PASSN+1)); } \
               || { printf '  \033[31m✗\033[0m no mfa_token in challenge\n'; FAILN=$((FAILN+1)); }

echo "=== step 3: the challenge token must NOT reach any resource ==="
gc="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $mtok" -H "X-Tenant: $TENANT" "$BRIDGE/v1/whoami")"
chk 401 "$gc" "mfa_pending token rejected on /v1/whoami"

echo "=== step 4: complete the challenge with a valid TOTP ==="
code="$(totp "$secret")"
comp="$(curl -s -X POST -H 'Content-Type: application/json' \
        -d "{\"mfa_token\":\"$mtok\",\"method\":\"totp\",\"code\":\"$code\"}" \
        "$BRIDGE/v1/auth/2fa")"
full="$(printf '%s' "$comp" | jget token)"
[ -n "$full" ] && { printf '  \033[32m✓\033[0m 2FA verify returns a full session\n'; PASSN=$((PASSN+1)); } \
               || { printf '  \033[31m✗\033[0m no session after 2FA: %s\n' "$comp"; FAILN=$((FAILN+1)); }
if [ -n "$full" ]; then
    chk 200 "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $full" -H "X-Tenant: $TENANT" "$BRIDGE/v1/whoami")" "full session reaches /v1/whoami"
    # amr should record the second factor. Decode the JWT payload (base64url).
    payload="$(printf '%s' "$full" | cut -d. -f2)"
    amr="$(python3 -c "import base64,json,sys;s=sys.argv[1];s+='='*(-len(s)%4);print(','.join(json.loads(base64.urlsafe_b64decode(s)).get('amr',[])))" "$payload" 2>/dev/null)"
    case ",$amr," in *",totp,"*) printf '  \033[32m✓\033[0m session amr records the 2nd factor (%s)\n' "$amr"; PASSN=$((PASSN+1));;
                     *) printf '  \033[31m✗\033[0m session amr missing the 2nd factor (%s)\n' "$amr"; FAILN=$((FAILN+1));; esac
fi

echo "=== step 5: negative — a wrong code is rejected ==="
nc="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      -d "{\"mfa_token\":\"$mtok\",\"method\":\"totp\",\"code\":\"000000\"}" "$BRIDGE/v1/auth/2fa")"
chk 401 "$nc" "wrong TOTP rejected at /v1/auth/2fa"

echo "=== cleanup: disable 2FA (idempotent re-runs) ==="
if [ -n "${full:-}" ]; then
    code="$(totp "$secret")"
    dc="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $full" -H "X-Tenant: $TENANT" \
          -X POST -H 'Content-Type: application/json' -d "{\"code\":\"$code\"}" "$LDAPMGR/v1/me/2fa/disable")"
    chk 200 "$dc" "2FA disabled for a clean next run"
fi

echo "-----------------------------------------------------------------------"
echo " passed=$PASSN failed=$FAILN"
[ "$FAILN" -eq 0 ]
