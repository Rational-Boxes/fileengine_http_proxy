// Unit tests for the multi-origin CORS allow-list (include/cors.h). Exact-match
// only, never "*", no wildcard/prefix matching — a look-alike origin must not pass.
#include <gtest/gtest.h>
#include "cors.h"

using webdav::matchCorsOrigin;

TEST(Cors, ExactMatchEchoesOrigin) {
    std::vector<std::string> allow = {"https://a.example.com", "https://b.example.com"};
    EXPECT_EQ(matchCorsOrigin(allow, "https://a.example.com"), "https://a.example.com");
    EXPECT_EQ(matchCorsOrigin(allow, "https://b.example.com"), "https://b.example.com");
}

TEST(Cors, NonMemberIsRejected) {
    std::vector<std::string> allow = {"https://a.example.com"};
    EXPECT_EQ(matchCorsOrigin(allow, "https://c.example.com"), "");
}

TEST(Cors, EmptyOriginAndEmptyListNeverMatch) {
    std::vector<std::string> allow = {"https://a.example.com"};
    EXPECT_EQ(matchCorsOrigin(allow, ""), "");           // no Origin header
    EXPECT_EQ(matchCorsOrigin({}, "https://a.example.com"), "");  // CORS disabled
}

TEST(Cors, NoPrefixOrSuffixOrPortConfusion) {
    std::vector<std::string> allow = {"https://host.example.com"};
    // Suffix attack, subdomain-of-attacker, scheme mismatch, and port mismatch all fail.
    EXPECT_EQ(matchCorsOrigin(allow, "https://host.example.com.evil.test"), "");
    EXPECT_EQ(matchCorsOrigin(allow, "https://evil.host.example.com"), "");
    EXPECT_EQ(matchCorsOrigin(allow, "http://host.example.com"), "");
    EXPECT_EQ(matchCorsOrigin(allow, "https://host.example.com:8443"), "");
}

TEST(Cors, WildcardIsNeverReturned) {
    // "*" is only matched if literally allow-listed (which deployments must not do);
    // an arbitrary origin never yields "*".
    std::vector<std::string> allow = {"https://a.example.com"};
    EXPECT_EQ(matchCorsOrigin(allow, "*"), "");
    EXPECT_NE(matchCorsOrigin(allow, "https://a.example.com"), "*");
}
