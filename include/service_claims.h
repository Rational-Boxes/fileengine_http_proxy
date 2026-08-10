#pragma once
// Claims for an integration-SERVICE token (§14.2, the non-delegated exchange path).
// Unlike a delegated user session, a service token represents the integration acting as
// itself: its roles are the deployment's CONFIGURED service roles (never resolved from
// LDAP — the service principal is not an LDAP user), and it is marked `svc:true` +
// `amr:["integration"]`. The {tenant:[roles]} shape mirrors a user token so downstream
// ACL evaluation is uniform. Header-only + dependency-light (Poco::JSON) so it is
// unit-testable independently of the request handler.
#include <ctime>
#include <string>
#include <vector>

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

namespace httpbridge {

inline Poco::JSON::Object::Ptr buildServiceClaims(
    const std::string& issuer, const std::string& subject, const std::string& tenant,
    const std::vector<std::string>& roles, const std::string& aip,
    const std::string& scope, const std::string& jti, long now, long ttl) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("iss", issuer);
    c->set("sub", subject);
    c->set("tenant", tenant);
    c->set("iat", static_cast<Poco::Int64>(now));
    c->set("exp", static_cast<Poco::Int64>(now + ttl));
    c->set("jti", jti);
    c->set("svc", true);                 // marks a service token (not a user session)
    if (!aip.empty()) c->set("aip", aip);
    if (!scope.empty()) c->set("scope", scope);

    Poco::JSON::Array::Ptr roleArr = new Poco::JSON::Array();
    for (const auto& r : roles) roleArr->add(r);
    Poco::JSON::Object::Ptr rolesObj = new Poco::JSON::Object();
    rolesObj->set(tenant, roleArr);      // {tenant: [roles]} — same shape as a user token
    c->set("roles", rolesObj);

    Poco::JSON::Array::Ptr amr = new Poco::JSON::Array();
    amr->add("integration");
    c->set("amr", amr);
    return c;
}

}  // namespace httpbridge
