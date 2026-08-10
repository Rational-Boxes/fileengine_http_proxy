// Tests for the non-secret integration status document (include/integration_status.h).
#include <gtest/gtest.h>
#include "integration_status.h"

using httpbridge::integrationStatusJson;
using httpbridge::jsonEscapeStatus;

TEST(IntegrationStatus, EnabledWhenIssuerAndKeyPresent) {
    auto j = integrationStatusJson("acme-integration", "https://f/v1/auth/exchange", true, {});
    EXPECT_NE(j.find("\"enabled\":true"), std::string::npos);
    EXPECT_NE(j.find("\"issuer\":\"acme-integration\""), std::string::npos);
    EXPECT_NE(j.find("\"audience\":\"https://f/v1/auth/exchange\""), std::string::npos);
    EXPECT_NE(j.find("\"key_present\":true"), std::string::npos);
    EXPECT_NE(j.find("\"ip_allowlist_enforced\":false"), std::string::npos);
}

TEST(IntegrationStatus, DisabledWhenKeyMissing) {
    auto j = integrationStatusJson("acme-integration", "aud", false, {});
    EXPECT_NE(j.find("\"enabled\":false"), std::string::npos);
    EXPECT_NE(j.find("\"key_present\":false"), std::string::npos);
}

TEST(IntegrationStatus, DisabledWhenIssuerEmpty) {
    auto j = integrationStatusJson("", "aud", true, {});
    EXPECT_NE(j.find("\"enabled\":false"), std::string::npos);
}

TEST(IntegrationStatus, AllowlistEchoedAndFlagged) {
    auto j = integrationStatusJson("i", "a", true, {"203.0.113.5", "198.51.100.0/24"});
    EXPECT_NE(j.find("\"ip_allowlist_enforced\":true"), std::string::npos);
    EXPECT_NE(j.find("\"203.0.113.5\""), std::string::npos);
    EXPECT_NE(j.find("\"198.51.100.0/24\""), std::string::npos);
}

TEST(IntegrationStatus, AllowServiceReflected) {
    EXPECT_NE(integrationStatusJson("i", "a", true, {}, true).find("\"allow_service\":true"), std::string::npos);
    EXPECT_NE(integrationStatusJson("i", "a", true, {}).find("\"allow_service\":false"), std::string::npos);
}

TEST(IntegrationStatus, NeverContainsKeyMaterial) {
    // The builder takes only a bool for the key; there is no path for PEM bytes to leak.
    auto j = integrationStatusJson("i", "a", true, {});
    EXPECT_EQ(j.find("BEGIN PUBLIC KEY"), std::string::npos);
    EXPECT_EQ(j.find("PRIVATE"), std::string::npos);
}

TEST(IntegrationStatus, EscapesQuotesAndControlChars) {
    EXPECT_EQ(jsonEscapeStatus("a\"b\\c"), "a\\\"b\\\\c");
    EXPECT_EQ(jsonEscapeStatus(std::string("x\ny", 3)), "x\\ny");
    // A raw quote in the issuer must not break out of the JSON string.
    auto j = integrationStatusJson("ev\"il", "a", true, {});
    EXPECT_NE(j.find("\"issuer\":\"ev\\\"il\""), std::string::npos);
}
