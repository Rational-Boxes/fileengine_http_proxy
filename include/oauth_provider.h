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
    // challenge and the opaque state).
    std::string buildAuthorizeUrl(const OAuthProviderConfig& cfg,
                                  const std::string& state,
                                  const std::string& code_challenge) const;

    // Exchanges the authorization code for an access token (server-side, with the
    // client secret + PKCE verifier). Returns false and sets `err` on failure.
    bool exchangeCode(const OAuthProviderConfig& cfg, const std::string& code,
                      const std::string& code_verifier, std::string& access_token,
                      std::string& err) const;

    // Resolves a verified identity from the access token (OIDC userinfo, or
    // GitHub /user + /user/emails). Returns false and sets `err` on failure.
    bool fetchIdentity(const OAuthProviderConfig& cfg, const std::string& access_token,
                       VerifiedIdentity& out, std::string& err) const;

private:
    bool fetchIdentityGithub(const OAuthProviderConfig& cfg, const std::string& access_token,
                             VerifiedIdentity& out, std::string& err) const;

    std::map<std::string, OAuthProviderConfig> providers_;
    HttpClient http_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_OAUTH_PROVIDER_H
