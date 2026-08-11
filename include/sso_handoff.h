#pragma once
// One-time SSO hand-off code (§5.5 deep-link SSO). A host app that already holds a
// FileEngine session can mint a SHORT-LIVED, SINGLE-USE code and deep-link the user into
// the official SPA carrying it; the SPA redeems the code for a fresh session. The code is
// a stateless signed JWT (HS256, the bridge secret) marked `sso:"handoff"` — so redeem is
// a signature + expiry check plus a replay guard on the `jti` (single use). It authorizes
// a session for exactly the same sub/tenant the authenticated caller already had, so it
// can never escalate. Header-only + Poco::JSON so the claim shape is unit-testable.
#include <ctime>
#include <string>

#include <Poco/JSON/Object.h>

namespace httpbridge {

inline Poco::JSON::Object::Ptr buildHandoffClaims(
    const std::string& issuer, const std::string& subject, const std::string& tenant,
    const std::string& jti, long now, long ttl) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("iss", issuer);
    c->set("sub", subject);
    c->set("tenant", tenant);
    c->set("sso", "handoff");                       // marks a one-time hand-off code, not a session
    c->set("iat", static_cast<Poco::Int64>(now));
    c->set("exp", static_cast<Poco::Int64>(now + ttl));
    c->set("jti", jti);
    return c;
}

}  // namespace httpbridge
