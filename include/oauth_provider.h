// Copyright (C) 2026 James Hickman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#ifndef HTTP_BRIDGE_OAUTH_PROVIDER_H
#define HTTP_BRIDGE_OAUTH_PROVIDER_H

#include <map>
#include <string>

#include "http_client.h"

namespace httpbridge {

// One configured identity provider.
struct OAuthProviderConfig {
    enum Kind { OIDC, GITHUB };

    std::string name;
    Kind kind = OIDC;
    std::string client_id;
    std::string client_secret;
    std::string auth_url;       // IdP authorization endpoint
    std::string token_url;      // IdP token endpoint (code -> tokens)
    std::string userinfo_url;   // OIDC userinfo / GitHub /user
    std::string emails_url;     // GitHub /user/emails (kind == GITHUB)
    std::string scopes;         // space-separated
    std::string redirect_uri;   // our callback, registered with the IdP
    std::string issuer;         // OIDC issuer (discovery + id_token `iss` check)
    std::string jwks_uri;       // OIDC JWKS endpoint (id_token signature keys)
    bool verify_id_token = true;// OIDC: verify the signed id_token (JWKS + nonce)
};

// The verified identity the IdP attests to. We trust these fields because they
// were fetched directly from the IdP over validated TLS in a server-side code
// flow (see HttpClient) — no browser-supplied tokens are ever accepted.
struct VerifiedIdentity {
    std::string email;
    std::string subject;        // IdP `sub` / GitHub numeric id
    bool email_verified = false;
};

// Holds the provider registry and performs the server-side OAuth2 steps. The
// only component that makes outbound calls to identity providers.
class OAuthProvider {
public:
    // Builds the registry from the environment. `OAUTH_PROVIDERS` is a CSV of
    // provider names; each name <P> is configured from OAUTH_<P>_* variables.
    // `redirect_base` is the public base URL of the bridge (e.g.
    // https://files.example.com) used to form each provider's redirect_uri.
    static OAuthProvider fromEnv(const std::string& redirect_base);

    bool has(const std::string& name) const { return providers_.count(name) > 0; }
    const OAuthProviderConfig* get(const std::string& name) const;

    // Assembles the IdP authorize URL (PKCE S256, given the precomputed
    // challenge, the opaque state, and the OIDC `nonce` binding the id_token).
    std::string buildAuthorizeUrl(const OAuthProviderConfig& cfg,
                                  const std::string& state,
                                  const std::string& code_challenge,
                                  const std::string& nonce) const;

    // Exchanges the authorization code for an access token + id_token (server-side,
    // with the client secret + PKCE verifier). `id_token` may be empty for a non-
    // OIDC provider. Returns false and sets `err` on failure.
    bool exchangeCode(const OAuthProviderConfig& cfg, const std::string& code,
                      const std::string& code_verifier, std::string& access_token,
                      std::string& id_token, std::string& err) const;

    // Resolves a verified identity from the access token (OIDC userinfo, or
    // GitHub /user + /user/emails). Returns false and sets `err` on failure.
    bool fetchIdentity(const OAuthProviderConfig& cfg, const std::string& access_token,
                       VerifiedIdentity& out, std::string& err) const;

    // Verifies a signed OIDC id_token against the provider's JWKS (fetched + cached
    // from `jwks_uri`) and the expected `nonce`, and maps its claims into a
    // VerifiedIdentity. Returns false and sets `err` on any verification failure.
    bool verifyIdToken(const OAuthProviderConfig& cfg, const std::string& id_token,
                       const std::string& expected_nonce, VerifiedIdentity& out,
                       std::string& err) const;

private:
    bool fetchIdentityGithub(const OAuthProviderConfig& cfg, const std::string& access_token,
                             VerifiedIdentity& out, std::string& err) const;
    // Fills any unset endpoints/jwks_uri from the IdP's OIDC discovery document.
    bool discoverEndpoints(OAuthProviderConfig& cfg, std::string& err);
    // JWKS JSON for `jwks_uri`, cached; `force` bypasses the cache (key rotation).
    std::string fetchJwks(const std::string& jwks_uri, bool force, std::string& err) const;

    std::map<std::string, OAuthProviderConfig> providers_;
    mutable std::map<std::string, std::string> jwks_cache_;  // jwks_uri -> JSON
    HttpClient http_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_OAUTH_PROVIDER_H
