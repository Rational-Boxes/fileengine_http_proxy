# OAuth2 / OIDC Login — Administrator Setup Guide

The HTTP bridge can authenticate users through external identity providers (IdPs)
using a **server-side (BFF) OAuth2 authorization-code + PKCE flow**. The browser
never sees a client secret or an IdP token; the bridge does the code exchange,
maps the verified email to an LDAP user (for roles), and issues its own opaque
bearer token — the same token type the `POST /v1/auth/token` Basic flow returns.

This guide explains how to register the bridge with common providers and fill in
the `.env` configuration.

---

## How the flow works

```
Browser ─GET /v1/auth/oauth/{provider}?return_to=<spa>──▶ bridge
  bridge 302 ─────────────────────────────────────────▶ IdP login + consent
IdP 302 ─GET /v1/auth/oauth/{provider}/callback?code&state──▶ bridge
  bridge ──(server-side, with client_secret + PKCE)──▶ IdP /token, /userinfo
  bridge: email → LDAP uid + roles → issue bearer token
  bridge 302 ─▶ <spa>#token=<bearer>&token_type=Bearer&expires_in=<ttl>
Browser ─Authorization: Bearer <bearer>──▶ bridge /v1/...
```

Two things every provider needs from you:

1. **Redirect / callback URL** — register this exact URL with the IdP:
   ```
   <OAUTH_REDIRECT_BASE>/v1/auth/oauth/<provider>/callback
   ```
   e.g. `https://files.example.com/v1/auth/oauth/google/callback`.
   It must match byte-for-byte; a trailing-slash or scheme mismatch is rejected.
2. **Client ID + Client secret** — issued when you register the app; go into
   `OAUTH_<PROVIDER>_CLIENT_ID` / `OAUTH_<PROVIDER>_CLIENT_SECRET`.

> The user must also exist in LDAP with a `mail` attribute equal to the email the
> IdP returns. The IdP proves *who* the user is; **LDAP supplies their roles and
> uid**. An authenticated IdP user with no matching LDAP entry gets `403`.

---

## Global configuration (`.env`)

| Variable | Example | Meaning |
|---|---|---|
| `OAUTH_REDIRECT_BASE` | `https://login.example.com/api` | Public base URL of **this bridge** — the ONE handshake URL shared by every provider (see [One handshake URL](#one-handshake-url-every-provider)). Empty disables OAuth. |
| `OAUTH_RETURN_ALLOWLIST` | `https://login.example.com/` | CSV of allowed return-URL prefixes, matched with a boundary guard; no wildcards. A `return_to` not matching one is rejected (anti open-redirect). With the shared sign-in origin this is **one entry**, not one per tenant. Never shorten an entry to a bare scheme — see [Multi-tenant deployments](#multi-tenant-deployments-one-idp-app-many-subdomains). |
| `LOGIN_SUBDOMAIN` | `login` | DNS label of the shared sign-in origin. **Reserved** — a tenant may never carry this name. No hyphen. |
| `OAUTH_PROVIDERS` | `google,microsoft,linkedin` | CSV of enabled providers. Google, Microsoft and LinkedIn need only a client id and secret — their endpoints are built in. Empty disables federated login, and the login screen then shows no provider buttons. |
| `OAUTH_STATE_TTL_SECONDS` | `300` | How long a started login may sit before the callback must arrive. |

Per provider (`<P>` = the upper-cased name from `OAUTH_PROVIDERS`):

| Variable | Notes |
|---|---|
| `OAUTH_<P>_KIND` | `oidc` (default) or `github` |
| `OAUTH_<P>_CLIENT_ID` / `_CLIENT_SECRET` | from the IdP app registration |
| `OAUTH_<P>_AUTH_URL` | IdP authorization endpoint |
| `OAUTH_<P>_TOKEN_URL` | IdP token endpoint |
| `OAUTH_<P>_USERINFO_URL` | OIDC userinfo (or GitHub `/user`) |
| `OAUTH_<P>_EMAILS_URL` | GitHub only: `/user/emails` |
| `OAUTH_<P>_SCOPES` | space-separated; OIDC needs `openid email` to get a verified email |

> **`email_verified` is required.** For `oidc` providers the userinfo response
> must include `"email_verified": true`. Providers that omit it (see Atlassian
> notes) need the workaround described in their section.

> **TLS must validate.** Outbound calls to the IdP validate certificates against
> the system CA store; this is what lets the bridge trust the userinfo response
> without verifying id_token signatures. Keep the bridge host's CA bundle current.

---

## Google (`kind=oidc`)

1. Google Cloud Console → **APIs & Services → Credentials → Create credentials →
   OAuth client ID**.
2. Application type **Web application**.
3. **Authorized redirect URIs** → add
   `<OAUTH_REDIRECT_BASE>/v1/auth/oauth/google/callback`.
4. Copy the **Client ID** and **Client secret**.

```bash
OAUTH_GOOGLE_KIND=oidc
OAUTH_GOOGLE_CLIENT_ID=xxxxxxxx.apps.googleusercontent.com
OAUTH_GOOGLE_CLIENT_SECRET=********
OAUTH_GOOGLE_AUTH_URL=https://accounts.google.com/o/oauth2/v2/auth
OAUTH_GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
OAUTH_GOOGLE_USERINFO_URL=https://openidconnect.googleapis.com/v1/userinfo
OAUTH_GOOGLE_SCOPES=openid email profile
```

---

## GitHub (`kind=github`)

GitHub is **not** OIDC, so `KIND=github`: the bridge calls `/user` for the stable
id and `/user/emails` for the verified primary email.

1. GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**
   (or an org's settings for an org-owned app).
2. **Authorization callback URL** →
   `<OAUTH_REDIRECT_BASE>/v1/auth/oauth/github/callback`.
3. Generate a **client secret**; copy the **Client ID** too.

```bash
OAUTH_GITHUB_KIND=github
OAUTH_GITHUB_CLIENT_ID=Iv1.xxxxxxxx
OAUTH_GITHUB_CLIENT_SECRET=********
OAUTH_GITHUB_AUTH_URL=https://github.com/login/oauth/authorize
OAUTH_GITHUB_TOKEN_URL=https://github.com/login/oauth/access_token
OAUTH_GITHUB_USERINFO_URL=https://api.github.com/user
OAUTH_GITHUB_EMAILS_URL=https://api.github.com/user/emails
OAUTH_GITHUB_SCOPES=read:user user:email
```

> The user's GitHub primary email must be **verified** and must match an LDAP
> `mail` value.

---

## Microsoft / Outlook (Azure AD / Entra ID) (`kind=oidc`)

1. Azure Portal → **Microsoft Entra ID → App registrations → New registration**.
2. **Redirect URI** → platform **Web** →
   `<OAUTH_REDIRECT_BASE>/v1/auth/oauth/microsoft/callback`.
3. **Certificates & secrets → New client secret**; copy the value.
4. Copy the **Application (client) ID**. Decide the tenant segment in the URLs:
   `common` (any Microsoft account), `organizations`, or your specific tenant GUID.

The endpoints are built in, so the minimum is three lines:

```bash
OAUTH_MICROSOFT_CLIENT_ID=00000000-0000-0000-0000-000000000000
OAUTH_MICROSOFT_CLIENT_SECRET=********
OAUTH_MICROSOFT_TENANT=common      # or your tenant GUID; default: common
```

`OAUTH_MICROSOFT_TENANT` is substituted into the authorize, token and JWKS URLs.
Set it to your tenant GUID to restrict logins to your organization. Any of
`AUTH_URL`, `TOKEN_URL`, `USERINFO_URL`, `JWKS_URI`, `ISSUER` or `SCOPES` can
still be set explicitly and will override the built-in value.

> **Why no `ISSUER` by default.** With `tenant=common` the `id_token`'s `iss`
> claim names the user's OWN tenant GUID, not `common` — so a fixed issuer
> string would reject every legitimate login. The check is therefore left off
> for the multi-tenant endpoints. If you have pinned a single tenant GUID, set
> `OAUTH_MICROSOFT_ISSUER=https://login.microsoftonline.com/<guid>/v2.0`, where
> the check is both possible and worth having.

---

## LinkedIn (`kind=oidc`)

Use **"Sign In with LinkedIn using OpenID Connect"**.

1. LinkedIn Developers → **Create app** (linked to a Company Page).
2. **Products** → add *Sign In with LinkedIn using OpenID Connect*.
3. **Auth** tab → **Authorized redirect URLs** →
   `<OAUTH_REDIRECT_BASE>/v1/auth/oauth/linkedin/callback`.
4. Copy the **Client ID** and **Client Secret**.

The endpoints are built in, so the minimum is two lines:

```bash
OAUTH_LINKEDIN_CLIENT_ID=********
OAUTH_LINKEDIN_CLIENT_SECRET=********
```

> The built-in scopes are `openid profile email` — the OIDC product. The older
> `r_liteprofile` / `r_emailaddress` scopes belong to the retired Sign In
> product and return no `id_token`, so do not set them.

> LinkedIn's userinfo includes `email` and `email_verified`. LinkedIn historically
> ignores the PKCE parameters; that is harmless here because the exchange is also
> authenticated with the client secret.

---

## Atlassian (Jira/Confluence cloud) (`kind=oidc`)

Atlassian's authorize endpoint needs an `audience` (and usually `prompt=consent`).
Append those directly to the `AUTH_URL` — the bridge preserves an existing query
string and adds its own parameters with `&`.

1. [developer.atlassian.com](https://developer.atlassian.com) → **OAuth 2.0 (3LO)**
   integration → create app.
2. **Authorization → Callback URL** →
   `<OAUTH_REDIRECT_BASE>/v1/auth/oauth/atlassian/callback`.
3. Add scopes (at minimum the OpenID scopes `openid email profile`).
4. Copy the **Client ID** and **Secret**.

```bash
OAUTH_ATLASSIAN_KIND=oidc
OAUTH_ATLASSIAN_CLIENT_ID=********
OAUTH_ATLASSIAN_CLIENT_SECRET=********
OAUTH_ATLASSIAN_AUTH_URL=https://auth.atlassian.com/authorize?audience=api.atlassian.com&prompt=consent
OAUTH_ATLASSIAN_TOKEN_URL=https://auth.atlassian.com/oauth/token
OAUTH_ATLASSIAN_USERINFO_URL=https://api.atlassian.com/me
OAUTH_ATLASSIAN_SCOPES=openid email profile
```

> **Caveat:** Atlassian's `/me` returns `email` but may not return
> `email_verified`. Because the bridge requires a verified email, Atlassian logins
> can be rejected. If your Atlassian directory guarantees verified emails, treat
> this as a deployment decision and adjust accordingly (the check lives in
> `oauthCallback()` in `src/http_server.cpp`).

---

## Any other OIDC provider (Okta, Auth0, Keycloak, …) (`kind=oidc`)

Read the provider's **discovery document** at
`https://<issuer>/.well-known/openid-configuration` and copy three fields:
`authorization_endpoint` → `AUTH_URL`, `token_endpoint` → `TOKEN_URL`,
`userinfo_endpoint` → `USERINFO_URL`. Register the callback URL, request scopes
`openid email profile`, and ensure userinfo returns `email_verified`.

```bash
OAUTH_OKTA_KIND=oidc
OAUTH_OKTA_CLIENT_ID=********
OAUTH_OKTA_CLIENT_SECRET=********
OAUTH_OKTA_AUTH_URL=https://<your>.okta.com/oauth2/v1/authorize
OAUTH_OKTA_TOKEN_URL=https://<your>.okta.com/oauth2/v1/token
OAUTH_OKTA_USERINFO_URL=https://<your>.okta.com/oauth2/v1/userinfo
OAUTH_OKTA_SCOPES=openid email profile
```

---

## One handshake URL, every provider

There is a single configurable base URL for the whole OAuth handshake, shared by
every provider. Only the last path segment differs:

```
OAUTH_REDIRECT_BASE=https://login.example.com/api      # ONE setting

  https://login.example.com/api/v1/auth/oauth/google/callback
  https://login.example.com/api/v1/auth/oauth/microsoft/callback
  https://login.example.com/api/v1/auth/oauth/linkedin/callback
```

So adding a provider is: register that one URL with the IdP, set its client id
and secret, add its name to `OAUTH_PROVIDERS`. Nothing else — no new host, no
DNS, no certificate, no allowlist entry, and no SPA rebuild (the login screen
asks the bridge which providers exist).

In the unified stack the base defaults to
`https://<LOGIN_SUBDOMAIN>.<BASE_DOMAIN>/api` and rarely needs setting. Pointing
it at the sign-in origin is deliberate: nginx path-proxies `/api` on every host,
so any of them *could* serve the callback — but using the sign-in origin is what
keeps this at one URL instead of one per tenant.

`OAUTH_RETURN_ALLOWLIST` defaults to that same origin, for the same reason.

---

## Multi-tenant deployments (one IdP app, many subdomains)

FileEngine resolves the tenant from the host subdomain, so the login screen
appears on every tenant's origin — `acme.example.com`, `someco.example.com`, and
so on. That raises the obvious worry: does each subdomain need its own IdP app,
or a wildcard redirect URI?

**Neither. You register ONE redirect URI per provider.**

`OAUTH_REDIRECT_BASE` is a single fixed host, so every provider has exactly one
callback URL no matter how many tenants exist:

```
https://<redirect-base>/v1/auth/oauth/<provider>/callback
```

**Wildcards would not work anyway.** OAuth redirect-URI matching is exact string
comparison by specification (RFC 6749 §3.1.2.3). Google and LinkedIn reject
wildcard redirect URIs outright; Microsoft's limited support carries caveats and
does not cover every app type. That strictness is deliberate — wildcard redirects
are a known token-theft vector.

### How the tenant survives the round trip

The tenant is captured at the START of the flow, on the tenant's own subdomain,
and carried through the signed state to the callback:

1. User is on `acme.example.com/login` and presses the button.
2. The bridge records `tenant=acme` (resolved from that host) in the OAuth state,
   along with the `return_to`.
3. The IdP sends the user back to the single registered callback.
4. The bridge mints the token using **the tenant from the state**, not from the
   callback's own host, and redirects to `return_to`.

So a user who starts on `acme.example.com` lands back there with an `acme` token.
Nothing about adding a tenant touches the IdP configuration.

### The allowlist, and why the shared origin keeps it at one entry

`OAUTH_RETURN_ALLOWLIST` is the check that stops `return_to` becoming an open
redirect. **With the shared sign-in origin it holds a single entry**, because
every flow returns there and the session is then handed on to whichever
workspace the user chose:

```bash
OAUTH_RETURN_ALLOWLIST=https://login.example.com/
```

Only if you bypass the sign-in origin — returning users directly to their tenant
— does this grow, and then every tenant origin must be listed and the bridge
restarted whenever one is added:

```bash
# the arrangement the shared origin exists to avoid
OAUTH_RETURN_ALLOWLIST=https://acme.example.com/,https://someco.example.com/
```

Matching is **prefix-based with a boundary guard**, and there is no wildcard
syntax. A prefix matches only when it ends at an origin or path boundary, so:

| Allowlist entry | URL | Result |
|---|---|---|
| `https://app.example.com` | `https://app.example.com/oauth/callback` | allowed |
| `https://app.example.com` | `https://app.example.com.evil.com/cb` | **rejected** |
| `https://app.example.com` | `https://app.example.com:8443/cb` | **rejected** (different port) |
| `https://app.example.com` | `https://evil.com/app.example.com` | **rejected** |
| `https://app.example.com/spa/` | `https://app.example.com/spa/page` | allowed |
| *(empty)* | anything | **rejected** |

> **Do not shorten an entry to a scheme.** `https://` — or `https:/`, or
> `https:` — ends on a boundary and therefore matches **every URL on that
> scheme**, turning the allowlist into an open redirect. It reads like "allow
> HTTPS" and means "allow anywhere". Always list full origins.

There is no wildcard syntax, which is precisely why the shared origin matters:
without it, adding a tenant means editing this variable and restarting the
bridge.

### Restricting WHICH accounts may sign in

FileEngine's tenant decides where a session lands; it does not decide who the IdP
lets through. With `OAUTH_MICROSOFT_TENANT=common`, any Microsoft account can
authenticate and will be mapped to whichever FileEngine tenant they started from.
If sign-in should be limited to one directory, pin the tenant GUID — the
restriction that matters is the IdP's, not ours.

The same applies generally: the IdP attests an email address, and FileEngine maps
that address to LDAP roles. A user with no matching LDAP account authenticates
successfully at the IdP and still has no access here.

---

## What the login screen shows

The SPA asks the bridge which providers are configured and renders a button for
each — nothing more:

```bash
curl -s https://app.example.com/api/v1/auth/providers
{"providers":["microsoft","linkedin"]}
```

Unauthenticated by necessity: the login screen reads it before anyone has a
token. It returns names only — never client ids, secrets or endpoints.

A provider appears **only if a sign-in could actually succeed**: it must be in
`OAUTH_PROVIDERS` *and* have a client id, a client secret and both endpoints. A
half-finished block is omitted rather than shown, because a button whose only
outcome is an error is worse than no button.

If nothing is configured the endpoint returns an empty list and the SPA shows no
buttons and no divider at all — the username/password form becomes the whole
login screen. The same is true if the bridge cannot be reached: the failure is
closed, never a guess.

> This replaced a build-time `VITE_OAUTH_PROVIDERS` list in the SPA. That could
> not work for the packaged image, which is built once and run by many
> deployments: every one of them was offered the same buttons regardless of what
> it had set up.

---

## Verifying a provider

```bash
B=https://files.example.com

# 1) Start: should 302 to the IdP with state + PKCE in the Location header.
curl -s -D - -o /dev/null "$B/v1/auth/oauth/google?return_to=https://app.example.com/oauth/callback"
#    Location: https://accounts.google.com/...&state=...&code_challenge=...&code_challenge_method=S256

# 2) Complete the login in a real browser; the final redirect lands on
#    https://app.example.com/oauth/callback#token=<bearer>&token_type=Bearer&expires_in=3600

# 3) Use the bearer just like a Basic-issued token:
curl -s -H "Authorization: Bearer <bearer>" "$B/v1/whoami"
#    {"user":"alice","tenant":"default","roles":["editor"]}
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `return_to not allowed` (400) | `return_to` doesn't match any `OAUTH_RETURN_ALLOWLIST` prefix |
| `unknown provider` (404) | name not in `OAUTH_PROVIDERS`, or its block is missing `CLIENT_ID`/`AUTH_URL`/`TOKEN_URL` |
| `invalid or expired state` (400) | callback arrived after `OAUTH_STATE_TTL_SECONDS`, or state was already used (replay) |
| `token exchange failed` (502) | redirect URI mismatch at the IdP, wrong client secret, or no network/TLS path to the token endpoint |
| `email not verified by provider` (403) | the account's email isn't verified, or userinfo lacks `email_verified` |
| `no matching user` (403) | no LDAP entry with `mail` = the IdP email |
| TLS errors in logs on exchange | system CA bundle missing/stale on the bridge host |
