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
| `OAUTH_REDIRECT_BASE` | `https://files.example.com` | Public base URL of **this bridge**. Empty disables OAuth. |
| `OAUTH_RETURN_ALLOWLIST` | `https://app.example.com/,http://localhost:3000/` | CSV of allowed SPA return-URL prefixes. A `return_to` not matching one of these is rejected (anti open-redirect). |
| `OAUTH_PROVIDERS` | `google,github,microsoft` | CSV of enabled providers; each needs an `OAUTH_<NAME>_*` block. |
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

```bash
OAUTH_MICROSOFT_KIND=oidc
OAUTH_MICROSOFT_CLIENT_ID=00000000-0000-0000-0000-000000000000
OAUTH_MICROSOFT_CLIENT_SECRET=********
OAUTH_MICROSOFT_AUTH_URL=https://login.microsoftonline.com/common/oauth2/v2.0/authorize
OAUTH_MICROSOFT_TOKEN_URL=https://login.microsoftonline.com/common/oauth2/v2.0/token
OAUTH_MICROSOFT_USERINFO_URL=https://graph.microsoft.com/oidc/userinfo
OAUTH_MICROSOFT_SCOPES=openid email profile
```

> Replace `common` with your tenant GUID to restrict logins to your organization.

---

## LinkedIn (`kind=oidc`)

Use **"Sign In with LinkedIn using OpenID Connect"**.

1. LinkedIn Developers → **Create app** (linked to a Company Page).
2. **Products** → add *Sign In with LinkedIn using OpenID Connect*.
3. **Auth** tab → **Authorized redirect URLs** →
   `<OAUTH_REDIRECT_BASE>/v1/auth/oauth/linkedin/callback`.
4. Copy the **Client ID** and **Client Secret**.

```bash
OAUTH_LINKEDIN_KIND=oidc
OAUTH_LINKEDIN_CLIENT_ID=********
OAUTH_LINKEDIN_CLIENT_SECRET=********
OAUTH_LINKEDIN_AUTH_URL=https://www.linkedin.com/oauth/v2/authorization
OAUTH_LINKEDIN_TOKEN_URL=https://www.linkedin.com/oauth/v2/accessToken
OAUTH_LINKEDIN_USERINFO_URL=https://api.linkedin.com/v2/userinfo
OAUTH_LINKEDIN_SCOPES=openid email profile
```

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
