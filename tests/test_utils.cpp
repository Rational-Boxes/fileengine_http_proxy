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

// --- resolveTenant (X-Tenant header > host subdomain > "default") ---------

TEST(ResolveTenant, ExplicitHeaderWins) {
    EXPECT_EQ(resolveTenant("acme", "other.example.com"), "acme");
    EXPECT_EQ(resolveTenant("acme", "localhost"), "acme");
}

TEST(ResolveTenant, FallsBackToHostSubdomain) {
    EXPECT_EQ(resolveTenant("", "acme.example.com"), "acme");
    EXPECT_EQ(resolveTenant("", "acme-drive.example.com"), "acme");  // hyphen split
}

TEST(ResolveTenant, FallsBackToDefault) {
    EXPECT_EQ(resolveTenant("", "localhost"), "default");      // no subdomain
    EXPECT_EQ(resolveTenant("", "www.example.com"), "default"); // reserved label
    EXPECT_EQ(resolveTenant("", ""), "default");               // no host
}

// --- reserved tenant labels ----------------------------------------------

TEST(ReservedTenantLabel, TheLabelIsConfigurable) {
    // A deployment may be unable to reserve "login" on its domain — on a shared
    // host it is very likely taken — so the name is settable.
    setLoginLabel("signin");
    EXPECT_TRUE(isReservedTenantLabel("signin"));
    EXPECT_FALSE(isReservedTenantLabel("login"));   // no longer special
    EXPECT_EQ(extractTenantFromHostname("signin.example.com"), "");
    EXPECT_EQ(extractTenantFromHostname("login.example.com"), "login");

    // Case-insensitive whichever name is configured.
    setLoginLabel("SignIn");
    EXPECT_TRUE(isReservedTenantLabel("signin"));

    // Empty restores the default rather than reserving everything: an empty
    // label would compare equal to nothing useful and could disable the guard.
    setLoginLabel("");
    EXPECT_TRUE(isReservedTenantLabel("login"));
    EXPECT_FALSE(isReservedTenantLabel("signin"));

    // "www" is unconditional, whatever the sign-in label is.
    setLoginLabel("signin");
    EXPECT_TRUE(isReservedTenantLabel("www"));
    setLoginLabel("login");   // restore for the tests that follow
}

// --- LOGIN_SUBDOMAIN validation ------------------------------------------
// The reservation is a string comparison against a host's leading label, so a
// label no hostname can equal reserves NOTHING and the failure is silent. These
// pin that a bad value is refused instead of adopted.

TEST(LoginLabelValidation, RejectsAnInlineCommentFromDotEnv) {
    // The real incident: a .env value runs to end of line, so
    //   LOGIN_SUBDOMAIN=filenginelogin        # ngrok
    // set the label to "filenginelogin          # ngrok". No host equals that,
    // so filenginelogin.ngrok.io stopped being reserved and resolved as an
    // ordinary tenant — an unauthenticated fail-OPEN from a plausible typo.
    setLoginLabel("login");
    std::string why;
    EXPECT_FALSE(setLoginLabel("filenginelogin        # ngrok", &why));
    EXPECT_FALSE(why.empty());
    // The previous label must survive a rejection; adopting a broken one is the
    // outcome being prevented.
    EXPECT_EQ(loginLabel(), "login");
    EXPECT_TRUE(isReservedTenantLabel("login"));
}

TEST(LoginLabelValidation, RejectsAHyphenatedLabel) {
    // Stricter than DNS deliberately. The leading label is split on '-' to
    // separate "<tenant>-<interface>", so "filenginetest-login" would resolve
    // to the TENANT "filenginetest" and the sign-in origin would double as a
    // tenant host.
    setLoginLabel("login");
    std::string why;
    EXPECT_FALSE(setLoginLabel("filenginetest-login", &why));
    EXPECT_NE(why.find('-'), std::string::npos);   // the reason names the cause
    EXPECT_EQ(loginLabel(), "login");
    // Demonstrate the breakage the rule prevents, so the rule is not mistaken
    // for arbitrary strictness: had it been accepted, this host would resolve
    // to a tenant.
    EXPECT_EQ(extractTenantFromHostname("filenginetest-login.ngrok.io"), "filenginetest");
}

TEST(LoginLabelValidation, AcceptsAnArbitraryHyphenFreeLabel) {
    // The point of the setting: "login" is often unreservable on a shared
    // domain, so any bare label must work.
    std::string why;
    EXPECT_TRUE(setLoginLabel("filenginelogin", &why));
    EXPECT_EQ(loginLabel(), "filenginelogin");
    EXPECT_TRUE(isReservedTenantLabel("filenginelogin"));
    EXPECT_EQ(extractTenantFromHostname("filenginelogin.ngrok.io"), "");
    // ...while ordinary tenants on the same domain are untouched.
    EXPECT_EQ(extractTenantFromHostname("filenginetest.ngrok.io"), "filenginetest");
    setLoginLabel("login");
}

TEST(LoginLabelValidation, RejectsOtherUnmatchableShapes) {
    setLoginLabel("login");
    EXPECT_FALSE(setLoginLabel("has space"));
    EXPECT_FALSE(setLoginLabel("under_score"));       // legal in an env var, not in DNS
    EXPECT_FALSE(setLoginLabel("dotted.label"));      // a label, not a hostname
    EXPECT_FALSE(setLoginLabel("trailing "));
    EXPECT_FALSE(setLoginLabel(std::string(64, 'a')));  // over the 63-char DNS limit
    EXPECT_FALSE(setLoginLabel("123"));               // collides with the IPv4 check
    EXPECT_EQ(loginLabel(), "login");                 // none of them took
    EXPECT_EQ(std::string(63, 'a').size(), 63u);
    EXPECT_TRUE(setLoginLabel(std::string(63, 'a')));   // exactly at the limit is fine
    setLoginLabel("login");
}

TEST(LoginLabelValidation, EmptyStillRestoresTheDefault) {
    // Unchanged behaviour, pinned: empty must not be treated as "invalid, keep
    // the old one" — it is how a deployment asks for the default back.
    setLoginLabel("signin");
    std::string why;
    EXPECT_TRUE(setLoginLabel("", &why));
    EXPECT_EQ(loginLabel(), "login");
}

TEST(ReservedTenantLabel, LoginAndWwwAreNeverTenants) {
    EXPECT_TRUE(isReservedTenantLabel("login"));
    EXPECT_TRUE(isReservedTenantLabel("www"));
    // DNS labels are case-insensitive and X-Tenant is client-supplied, so a
    // check that only knew "login" would be bypassable with "Login".
    EXPECT_TRUE(isReservedTenantLabel("LOGIN"));
    EXPECT_TRUE(isReservedTenantLabel("Login"));
    EXPECT_FALSE(isReservedTenantLabel("acme"));
    EXPECT_FALSE(isReservedTenantLabel("logins"));   // not a prefix match
    EXPECT_FALSE(isReservedTenantLabel(""));
}

TEST(ReservedTenantLabel, TheLoginHostResolvesToNoTenant) {
    // The whole point: every OAuth flow returns to this ONE origin, so the
    // return allowlist holds a single entry however many tenants exist.
    EXPECT_EQ(extractTenantFromHostname("login.example.com"), "");
    EXPECT_EQ(resolveTenant("", "login.example.com"), "default");
    // There is no such host in practice — WebDAV is per-tenant and `login` is
    // not a tenant — but if one were ever pointed at the stack it must not
    // become a tenant called "login" via the <tenant>-<interface> convention.
    EXPECT_EQ(extractTenantFromHostname("login-drive.example.com"), "");
    // A real tenant is unaffected.
    EXPECT_EQ(extractTenantFromHostname("acme.example.com"), "acme");
}

TEST(ReservedTenantLabel, TheHeaderCannotClaimIt) {
    // X-Tenant is attacker-controlled; guarding only the hostname would leave
    // the reservation trivially bypassable.
    // A reserved header is IGNORED, not honoured: resolution falls through to
    // the host exactly as if the header had not been sent.
    EXPECT_EQ(resolveTenant("login", "acme.example.com"), "acme");
    EXPECT_EQ(resolveTenant("LOGIN", "acme.example.com"), "acme");
    // Both reserved -> the ordinary default, never "login".
    EXPECT_EQ(resolveTenant("login", "login.example.com"), "default");
    // A legitimate header still overrides the host.
    EXPECT_EQ(resolveTenant("acme", "login.example.com"), "acme");
}

// --- returnUrlAllowed (OAuth return-URL allowlist) ------------------------

TEST(ReturnUrlAllowed, MatchesAtAnOriginOrPathBoundary) {
    const std::string allow = "https://app.example.com,https://admin.example.com";
    EXPECT_TRUE(returnUrlAllowed(allow, "https://app.example.com"));              // exact
    EXPECT_TRUE(returnUrlAllowed(allow, "https://app.example.com/oauth/callback")); // '/'
    EXPECT_TRUE(returnUrlAllowed(allow, "https://app.example.com?next=/x"));      // '?'
    EXPECT_TRUE(returnUrlAllowed(allow, "https://app.example.com#frag"));         // '#'
    EXPECT_TRUE(returnUrlAllowed(allow, "https://admin.example.com/"));
    // A path-prefix entry (ends in '/') matches anything beneath it.
    EXPECT_TRUE(returnUrlAllowed("https://app.example.com/spa/", "https://app.example.com/spa/page"));
}

TEST(ReturnUrlAllowed, RejectsConfusableHostsAndDifferentPorts) {
    // The hardening: a confusable host that merely *starts with* the prefix.
    EXPECT_FALSE(returnUrlAllowed("https://app.example.com", "https://app.example.com.evil.com/cb"));
    EXPECT_FALSE(returnUrlAllowed("https://app.example.com", "https://app.example.comX"));
    // A different port is a different origin.
    EXPECT_FALSE(returnUrlAllowed("https://app.example.com", "https://app.example.com:8443/cb"));
}

TEST(ReturnUrlAllowed, RejectsNonMatchingOrEmptyAllowlist) {
    EXPECT_FALSE(returnUrlAllowed("https://app.example.com", "https://evil.com/app.example.com"));
    // A SCHEME-ONLY entry matches every URL on that scheme — "allow https" is
    // really "allow anywhere", and is the one way to turn this allowlist into
    // an open redirect. True for every truncation that lands on a boundary,
    // which is all three of these.
    EXPECT_TRUE(returnUrlAllowed("https://", "https://evil.com/steal"));
    EXPECT_TRUE(returnUrlAllowed("https:/",  "https://evil.com/steal"));
    EXPECT_TRUE(returnUrlAllowed("https:",   "https://evil.com/steal"));
    // A prefix that stops MID-TOKEN does not: 's' is not a boundary.
    EXPECT_FALSE(returnUrlAllowed("http", "https://evil.com/steal"));

    EXPECT_FALSE(returnUrlAllowed("", "https://app.example.com/cb"));   // empty allowlist
    EXPECT_FALSE(returnUrlAllowed("   ", "https://app.example.com/cb")); // blank-only entry
}

TEST(ReturnUrlAllowed, TrimsWhitespaceAroundPrefixes) {
    EXPECT_TRUE(returnUrlAllowed("  https://a.com , https://b.com ", "https://b.com/cb"));
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

// ---------------------------------------------------------------------------
// Core error -> HTTP status.
//
// The core reports failures as prose and the door classifies them by what they
// say, so this mapping decides whether a caller is told "you got it wrong" or
// "we broke". Getting it wrong is invisible: the request still returns, just
// with the wrong meaning, and a 500 for an ordinary condition is a page at 3am
// for something working as designed.
// ---------------------------------------------------------------------------

TEST(CoreErrorStatus, PermissionFailuresAreForbidden) {
    EXPECT_EQ(webdav::httpStatusForCoreError("Insufficient permission to read"), 403);
}

TEST(CoreErrorStatus, MissingThingsAreNotFound) {
    EXPECT_EQ(webdav::httpStatusForCoreError("File does not exist"), 404);
    EXPECT_EQ(webdav::httpStatusForCoreError("version not found"), 404);
}

TEST(CoreErrorStatus, ConflictsAreConflicts) {
    EXPECT_EQ(webdav::httpStatusForCoreError("cannot move into its own subtree"), 409);
    EXPECT_EQ(webdav::httpStatusForCoreError("File has already been erased: abc"), 409);
}

TEST(CoreErrorStatus, AFileWithNoContentIsNotAServerFault) {
    // THE BUG. Reading an ERASED file's content answered
    // 500 {"error":"No versions available for file"} — erasure destroys every
    // version by design, so the feature working as intended raised a server
    // error on every subsequent read.
    EXPECT_EQ(webdav::httpStatusForCoreError("No versions available for file"), 404);
}

TEST(CoreErrorStatus, TheSourceFormOfThatErrorIsAlsoNotAServerFault) {
    // Copy/move from a file with nothing in it reports its own variant.
    EXPECT_EQ(webdav::httpStatusForCoreError("No versions available for source file"), 404);
}

TEST(CoreErrorStatus, AnUnrecognisedFailureStaysAServerError) {
    // The important half of the change: only the understood cases move off 500.
    // Reclassifying the unknown would hide real breakage behind a tidy 4xx.
    EXPECT_EQ(webdav::httpStatusForCoreError("connection reset by peer"), 500);
    EXPECT_EQ(webdav::httpStatusForCoreError(""), 500);
}

TEST(CoreErrorStatus, TheRootDirectoryGuardIsARefusalNotAFault) {
    // The core refuses this in its own words, without the word "permission", so
    // it fell through to 500. A non-admin creating at the root got a server
    // error for being told no — which also means every such attempt looked like
    // breakage to whoever watches the 5xx rate.
    EXPECT_EQ(webdav::httpStatusForCoreError(
        "Only an admin (system_admin or tenant_admin) can create in the root directory"), 403);
}
