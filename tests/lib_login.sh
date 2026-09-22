# Shared login for the e2e scripts. Source it; do not execute it.
#
#   fe_login <user> <password> [tenant]   -> echoes a session bearer, or fails
#
# A password login has two shapes, and a test that handles only the first cannot
# run against a fixture where 2FA is on: a tenant with 2FA off answers
# /v1/auth/token with the session outright, while one that requires it answers
# with an MfaPending challenge that has to be completed first. Several suites
# each needed this and got it separately — webdav_bridge/test_webdav.sh grew its
# own copy, this repo's security suite had none and reported one useless failure
# for the whole run — so it lives in one place now.
#
# EMAIL is the method used, deliberately. Completing a TOTP challenge needs the
# enrolled secret, which a harness has no way to know; the emailed code can be
# read back from MailHog, so this works for any enrolled user without holding
# their factor.
#
# Env:
#   BASE          bridge base URL              (default http://localhost:8090)
#   MAILHOG_URL   MailHog base URL             (default http://localhost:8025)
#
# Note for repeated runs: the bridge caps code sends (3 per 15 min) and locks out
# after 5 wrong attempts, and both present as a failed login rather than as a
# rate limit. A suite that logs in once per run stays well inside that.

fe_login() {
    local user="$1" pass="$2" tenant="${3:-}"
    local base="${BASE:-http://localhost:8090}"
    local mailhog="${MAILHOG_URL:-http://localhost:8025}"
    local hdr=() resp tok mfatok code

    [ -n "$tenant" ] && hdr=(-H "X-Tenant: $tenant")

    resp=$(curl -s -u "$user:$pass" "${hdr[@]}" -X POST "$base/v1/auth/token" --max-time 20)
    tok=$(printf '%s' "$resp" | _fe_jget token)
    if [ -n "$tok" ]; then printf '%s' "$tok"; return 0; fi

    mfatok=$(printf '%s' "$resp" | _fe_jget mfa_token)
    if [ -z "$mfatok" ]; then
        echo "fe_login: no session and no MFA challenge for $user: $resp" >&2
        return 1
    fi

    # Clear the mailbox FIRST, so the code that arrives is unambiguously ours.
    curl -s -X DELETE "$mailhog/api/v1/messages" >/dev/null
    curl -s -X POST "$base/v1/auth/2fa" -H 'Content-Type: application/json' \
         -d "{\"mfa_token\":\"$mfatok\",\"action\":\"send\",\"method\":\"email\"}" >/dev/null
    sleep 1
    code=$(curl -s "$mailhog/api/v2/messages" | python3 -c "
import sys,json,re,quopri
items=json.load(sys.stdin).get('items',[])
b=quopri.decodestring(items[0]['Content']['Body']).decode('utf-8','ignore') if items else ''
print((re.findall(r'\b(\d{6})\b', b) or [''])[0])" 2>/dev/null)
    if [ -z "$code" ]; then
        echo "fe_login: no 2FA code in MailHog at $mailhog (is it running?)" >&2
        return 1
    fi
    local done_resp
    done_resp=$(curl -s -X POST "$base/v1/auth/2fa" -H 'Content-Type: application/json' \
                -d "{\"mfa_token\":\"$mfatok\",\"method\":\"email\",\"code\":\"$code\"}")
    tok=$(printf '%s' "$done_resp" | _fe_jget token)
    if [ -z "$tok" ]; then
        echo "fe_login: the 2FA completion returned no session for $user: $done_resp" >&2
        # A freshly delivered code that comes back "invalid or expired" is usually
        # not a wrong code: ldap_manager rate-limits /internal/2fa/verify and
        # answers 429, which the bridge relays as a 401 with that same message. It
        # is indistinguishable from a bad code from out here, and it is what a run
        # of several suites back to back produces. Give it a few minutes.
        case "$done_resp" in
          *"invalid or expired second factor"*)
            echo "fe_login: the code came from MailHog seconds earlier, so suspect the" >&2
            echo "          verify RATE LIMIT (ldap_manager answers 429; the bridge" >&2
            echo "          reports it as this 401) rather than the code itself." >&2 ;;
        esac
        return 1
    fi
    printf '%s' "$tok"
}

_fe_jget() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }
