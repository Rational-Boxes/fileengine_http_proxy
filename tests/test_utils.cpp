// Unit tests for the pure utility functions in src/utils.cpp. These need no
// gRPC/LDAP/Postgres and no mocks, so they run fast and deterministically.
#include <gtest/gtest.h>
#include "../include/utils.h"

using namespace webdav;

// --- extractTenantFromHostname -------------------------------------------
// The leading DNS label is the tenant; the label is split on '-' and only the
// first segment is kept (the "<tenant>-<interface>" convention). Only "www" is
// reserved here (the bridge's policy), plus bare hosts and IPv4 literals.

TEST(ExtractTenantFromHostname, BareLabelIsTheTenant) {
    EXPECT_EQ(extractTenantFromHostname("acme.example.com"), "acme");
    EXPECT_EQ(extractTenantFromHostname("filenginetest.ngrok.io"), "filenginetest");
}

TEST(ExtractTenantFromHostname, SplitsOnFirstHyphen) {
    EXPECT_EQ(extractTenantFromHostname("acme-drive.example.com"), "acme");
    EXPECT_EQ(extractTenantFromHostname("acme-staging-eu.example.com"), "acme");
    EXPECT_EQ(extractTenantFromHostname("filenginetest-drive.ngrok.io"), "filenginetest");
}

TEST(ExtractTenantFromHostname, ReservedAndNonTenantHosts) {
    EXPECT_EQ(extractTenantFromHostname("www.example.com"), "");      // reserved
    EXPECT_EQ(extractTenantFromHostname("www-drive.example.com"), ""); // reserved after split
    EXPECT_EQ(extractTenantFromHostname("localhost"), "");            // bare host
    EXPECT_EQ(extractTenantFromHostname(""), "");                     // empty
    EXPECT_EQ(extractTenantFromHostname("127.0.0.1"), "");            // IPv4 literal
}

TEST(ExtractTenantFromHostname, StripsPortAndTrailingDot) {
    EXPECT_EQ(extractTenantFromHostname("acme.example.com:8088"), "acme");
    EXPECT_EQ(extractTenantFromHostname("localhost:8088"), "");
}

TEST(ExtractTenantFromHostname, OnlyWwwIsReservedNotAppApi) {
    // The bridge (unlike the SPA) reserves only "www".
    EXPECT_EQ(extractTenantFromHostname("app.example.com"), "app");
    EXPECT_EQ(extractTenantFromHostname("api.example.com"), "api");
}

// --- splitString ----------------------------------------------------------

TEST(SplitString, SplitsAndPreservesEmptyInteriorTokens) {
    EXPECT_EQ(splitString("a,b,c", ',').size(), 3u);
    EXPECT_EQ(splitString("google,github", ','), (std::vector<std::string>{"google", "github"}));
    EXPECT_EQ(splitString("a,,b", ','), (std::vector<std::string>{"a", "", "b"}));
    EXPECT_EQ(splitString("solo", ','), (std::vector<std::string>{"solo"}));
    EXPECT_TRUE(splitString("", ',').empty());
}

// --- trim -----------------------------------------------------------------

TEST(Trim, StripsSurroundingWhitespace) {
    EXPECT_EQ(trim("  hi  "), "hi");
    EXPECT_EQ(trim("\t\n x \r\f"), "x");
    EXPECT_EQ(trim("no-edges"), "no-edges");
    EXPECT_EQ(trim("   "), "");
    EXPECT_EQ(trim(""), "");
}

// --- urlDecode / urlEncode ------------------------------------------------

TEST(UrlDecode, DecodesPercentAndPlus) {
    EXPECT_EQ(urlDecode("%20"), " ");
    EXPECT_EQ(urlDecode("a+b"), "a b");
    EXPECT_EQ(urlDecode("%2Fpath%2Fto"), "/path/to");
    EXPECT_EQ(urlDecode("100%25"), "100%");
    EXPECT_EQ(urlDecode("plain"), "plain");
}

TEST(UrlEncode, EscapesReservedKeepsUnreserved) {
    EXPECT_EQ(urlEncode("a b"), "a%20b");
    EXPECT_EQ(urlEncode("/"), "%2F");
    EXPECT_EQ(urlEncode("safe-_.~AZ09"), "safe-_.~AZ09");
}

TEST(UrlCodec, RoundTrips) {
    const std::string raw = "hello world/?&=:@";
    EXPECT_EQ(urlDecode(urlEncode(raw)), raw);
}

// --- HTTP Digest auth (RFC 2617 §3.5 canonical example) -------------------

TEST(Digest, MatchesRfc2617VectorsAndIsLowercase) {
    // RFC 2617 requires lowercase hex digests; assert the exact (lowercase)
    // values so a regression back to uppercase fails here.
    const std::string ha1 = calculateHA1("Mufasa", "testrealm@host.com", "Circle Of Life");
    EXPECT_EQ(ha1, "939e7578ed9e3c518a452acee763bce9");

    const std::string ha2 = calculateHA2("GET", "/dir/index.html");
    EXPECT_EQ(ha2, "39aff3a2bab6126f332b942af96d3366");

    const std::string resp = calculateDigestResponse(
        ha1, "dcd98b7102dd2f0e8b11d0f600bfb0c093", "00000001", "0a4f113b", "auth", ha2);
    EXPECT_EQ(resp, "6629fae49393a05397450978507c4ef1");
}

TEST(Digest, Ha1AliasesGenerateDigestHashAndIsDeterministic) {
    EXPECT_EQ(calculateHA1("u", "r", "p"), generateDigestHash("u", "r", "p"));
    EXPECT_EQ(calculateHA1("u", "r", "p"), calculateHA1("u", "r", "p"));
    EXPECT_NE(calculateHA1("u", "r", "p"), calculateHA1("u", "r", "p2"));
}
