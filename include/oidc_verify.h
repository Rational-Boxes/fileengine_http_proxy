#ifndef HTTP_BRIDGE_OIDC_VERIFY_H
#define HTTP_BRIDGE_OIDC_VERIFY_H

#include <string>

namespace httpbridge {

// The identity claims taken from a *verified* OIDC id_token.
struct IdTokenClaims {
    std::string subject;         // `sub`
    std::string email;           // `email` (may be empty — not all IdPs include it)
    bool email_verified = false;
};

// Verify a signed OIDC id_token (RS256) against the provider's published JWKS.
//
// Pure and offline: the JWKS JSON is supplied by the caller (the OAuthProvider
// fetches + caches it), so this function is deterministic and unit-testable. It
// checks, in order: the token is a well-formed 3-part JWT; the header `alg` is
// RS256; a JWKS key matches the header `kid`; the RSA signature over
// "<header>.<payload>" verifies; `iss` == issuer; `aud` == client_id (string or
// array); `exp` is in the future (60s leeway); and — when `expected_nonce` is
// non-empty — the `nonce` claim matches. On success it fills `out` and returns
// true; on any failure it sets `err` and returns false.
//
// `now_epoch` overrides "now" for tests; 0 means use the current time.
bool verifyIdToken(const std::string& id_token,
                   const std::string& issuer,
                   const std::string& client_id,
                   const std::string& expected_nonce,
                   const std::string& jwks_json,
                   IdTokenClaims& out,
                   std::string& err,
                   long now_epoch = 0);

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_OIDC_VERIFY_H
