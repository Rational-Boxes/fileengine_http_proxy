// Tests for the SSO hand-off code claims (include/sso_handoff.h) + sign/verify roundtrip.
#include <gtest/gtest.h>
#include "sso_handoff.h"
#include "jwt.h"

#include <sstream>
#include <Poco/JSON/Parser.h>

using httpbridge::buildHandoffClaims;

namespace {
const std::string SECRET = "unit-test-shared-secret-value-32b!";
Poco::JSON::Object::Ptr parse(const std::string& s) {
    Poco::JSON::Parser p; return p.parse(s).extract<Poco::JSON::Object::Ptr>();
}
}

TEST(SsoHandoff, ClaimShape) {
    auto c = buildHandoffClaims("fileengine-bridge", "alice@acme", "acme", "jti-1", 1000, 60);
    std::ostringstream os; c->stringify(os);
    auto j = parse(os.str());
    EXPECT_EQ(j->getValue<std::string>("iss"), "fileengine-bridge");
    EXPECT_EQ(j->getValue<std::string>("sub"), "alice@acme");
    EXPECT_EQ(j->getValue<std::string>("tenant"), "acme");
    EXPECT_EQ(j->getValue<std::string>("sso"), "handoff");
    EXPECT_EQ(static_cast<long>(j->getValue<double>("exp")), 1060);
    EXPECT_EQ(j->getValue<std::string>("jti"), "jti-1");
}

TEST(SsoHandoff, SignsAndVerifies_ThenExpires) {
    auto c = buildHandoffClaims("fileengine-bridge", "alice@acme", "acme", "jti-9", 1000, 60);
    std::string code = httpbridge::jwt::sign(c, SECRET);

    Poco::JSON::Object::Ptr out; std::string err;
    ASSERT_TRUE(httpbridge::jwt::verify(code, SECRET, 1030, out, err)) << err;  // within [1000,1060)
    EXPECT_EQ(out->getValue<std::string>("sub"), "alice@acme");
    EXPECT_EQ(out->getValue<std::string>("sso"), "handoff");
    EXPECT_FALSE(httpbridge::jwt::verify(code, SECRET, 1100, out, err));         // expired (>= exp)
}

TEST(SsoHandoff, CarriesAmrForTwoFactorTrust) {
    auto c = buildHandoffClaims("iss", "alice@acme", "acme", "jti-a", 1000, 60, {"pwd", "otp"});
    std::ostringstream os; c->stringify(os);
    auto j = parse(os.str());
    auto arr = j->getArray("amr");
    ASSERT_FALSE(arr.isNull());
    ASSERT_EQ(arr->size(), 2u);
    EXPECT_EQ(arr->getElement<std::string>(0), "pwd");
    EXPECT_EQ(arr->getElement<std::string>(1), "otp");
}

TEST(SsoHandoff, AmrEmptyByDefault) {
    auto c = buildHandoffClaims("iss", "u", "t", "j", 1000, 60);
    std::ostringstream os; c->stringify(os);
    EXPECT_EQ(parse(os.str())->getArray("amr")->size(), 0u);
}

TEST(SsoHandoff, WrongSecretRejected) {
    auto c = buildHandoffClaims("iss", "u", "t", "j", 1000, 60);
    std::string code = httpbridge::jwt::sign(c, SECRET);
    Poco::JSON::Object::Ptr out; std::string err;
    EXPECT_FALSE(httpbridge::jwt::verify(code, "a-different-secret-value-here!!", 1010, out, err));
}
