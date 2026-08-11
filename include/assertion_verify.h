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

#ifndef HTTP_BRIDGE_ASSERTION_VERIFY_H
#define HTTP_BRIDGE_ASSERTION_VERIFY_H

#include <string>
#include <vector>

namespace httpbridge {

// Claims taken from a *verified* integration assertion (RFC 7523 client
// authentication / token exchange). The signature is proven against the
// integration's imported public key before any of these are trusted.
struct IntegrationClaims {
    std::string issuer;      // `iss` — the integration id (must match the configured integration)
    std::string subject;     // `sub` — delegated end-user uid, or the integration's service principal
    std::string tenant;      // custom `tenant` claim (optional; the target tenant)
    std::string scope;       // custom `scope` claim (optional; space-delimited)
    std::string jti;         // `jti` — unique id, for replay rejection by the caller
    std::string token_type;  // custom `token_type` claim: "delegated" | "service" (optional)
    std::vector<std::string> amr;  // `amr` — auth methods the integration asserts (RFC 8176),
                                   //  e.g. ["pwd","otp"]; propagates the integration's 2FA trust
    long expires_at = 0;     // `exp` (unix epoch) — echoed for the caller's bookkeeping
};

// Verify an integration assertion signed with the integration's asymmetric key
// (RS256 or ES256) against its imported PEM public key.
//
// Pure and offline: the public key is supplied by the caller (loaded from the
// deployment's integration registry), so this is deterministic and unit-testable.
// It checks, in order: the assertion is a well-formed 3-part JWT; the header `alg`
// is RS256 or ES256; the signature over "<header>.<payload>" verifies against the
// PEM key; `iss` == expected_issuer; `aud` contains expected_audience (string or
// array); `exp` is present and in the future (60s leeway); and `sub` is non-empty.
// On success it fills `out` and returns true; on any failure it sets `err` and
// returns false. Replay rejection (`jti`) and IP allow-listing are the caller's job.
//
// `now_epoch` overrides "now" for tests; 0 means use the current time.
bool verifyIntegrationAssertion(const std::string& assertion,
                                const std::string& expected_issuer,
                                const std::string& expected_audience,
                                const std::string& pem_public_key,
                                IntegrationClaims& out,
                                std::string& err,
                                long now_epoch = 0);

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_ASSERTION_VERIFY_H
