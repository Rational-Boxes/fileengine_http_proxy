// Tests for the integration-service token claim builder (include/service_claims.h).
// Signs + verifies the claims via jwt.h to prove a real round-trip.
#include <gtest/gtest.h>
#include "service_claims.h"
#include "jwt.h"

#include <sstream>
#include <Poco/JSON/Parser.h>

using httpbridge::buildServiceClaims;

namespace {
Poco::JSON::Object::Ptr stringifyParse(const Poco::JSON::Object::Ptr& o) {
    std::ostringstream os; o->stringify(os);
    Poco::JSON::Parser p;
    return p.parse(os.str()).extract<Poco::JSON::Object::Ptr>();
}
}

TEST(ServiceClaims, CarriesConfiguredRolesUnderTenantAndSvcMarker) {
    auto c = buildServiceClaims("fileengine-bridge", "svc:acme", "acme",
                                {"integration_writer", "classifier_admin"},
                                "203.0.113.9", "files.write", "jti-1", 1000, 900);
    auto j = stringifyParse(c);
    EXPECT_EQ(j->getValue<std::string>("iss"), "fileengine-bridge");
    EXPECT_EQ(j->getValue<std::string>("sub"), "svc:acme");
    EXPECT_EQ(j->getValue<std::string>("tenant"), "acme");
    EXPECT_TRUE(j->getValue<bool>("svc"));
    EXPECT_EQ(j->getValue<std::string>("aip"), "203.0.113.9");
    EXPECT_EQ(j->getValue<std::string>("scope"), "files.write");
    EXPECT_EQ(static_cast<long>(j->getValue<double>("exp")), 1900);

    auto roles = j->getObject("roles");
    ASSERT_FALSE(roles.isNull());
    auto arr = roles->getArray("acme");
    ASSERT_FALSE(arr.isNull());
    ASSERT_EQ(arr->size(), 2u);
    EXPECT_EQ(arr->getElement<std::string>(0), "integration_writer");

    auto amr = j->getArray("amr");
    ASSERT_FALSE(amr.isNull());
    EXPECT_EQ(amr->getElement<std::string>(0), "integration");
}

TEST(ServiceClaims, OmitsAipAndScopeWhenEmpty) {
    auto j = stringifyParse(buildServiceClaims("iss", "svc", "t", {}, "", "", "jti", 1000, 60));
    EXPECT_FALSE(j->has("aip"));
    EXPECT_FALSE(j->has("scope"));
    // Empty roles still produce a {tenant: []} object so the claim shape is stable.
    EXPECT_EQ(j->getObject("roles")->getArray("t")->size(), 0u);
}

TEST(ServiceClaims, SignsAndVerifiesRoundTrip) {
    const std::string secret = "unit-test-shared-secret-value-32b!";
    auto c = buildServiceClaims("fileengine-bridge", "svc:acme", "acme",
                                {"integration_writer"}, "", "", "jti-9", 1000, 900);
    std::string token = httpbridge::jwt::sign(c, secret);

    Poco::JSON::Object::Ptr out;
    std::string err;
    // now=1500 is within [iat=1000, exp=1900]
    ASSERT_TRUE(httpbridge::jwt::verify(token, secret, 1500, out, err)) << err;
    EXPECT_EQ(out->getValue<std::string>("sub"), "svc:acme");
    EXPECT_TRUE(out->getValue<bool>("svc"));

    // Expired at now=2000 (>= exp).
    EXPECT_FALSE(httpbridge::jwt::verify(token, secret, 2000, out, err));
}
