// Security regression tests for the bridge's HS256 JWT session tokens (jwt.h).
//
// These pin the security-critical properties of token verification so a future
// refactor cannot silently reintroduce a bypass:
//   - signature is required and secret-bound (no forgery without the secret)
//   - the algorithm is pinned to HS256 (no "alg":"none", no RS256 alg-confusion)
//   - tampering with header or payload invalidates the token
//   - expiry (exp) is enforced
//   - malformed tokens are rejected, not accepted
//
// The suite is header-only (jwt.h) + Poco + OpenSSL; it needs no gRPC/LDAP and
// runs offline via CTest (`ctest -R security_tests`).

#include <gtest/gtest.h>

#include <string>

#include <Poco/JSON/Object.h>

#include "jwt.h"

using httpbridge::jwt::sign;
using httpbridge::jwt::verify;
using httpbridge::jwt::b64urlEncode;
using httpbridge::jwt::hmac256;

namespace {

const std::string kSecret = "correct-horse-battery-staple-super-secret";
const long kNow = 1'700'000'000;  // fixed "now" so tests are deterministic

// Build a standard, currently-valid token for `user` expiring 1h after kNow.
std::string makeToken(const std::string& secret, const std::string& user, long exp) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("sub", user);
    c->set("tenant", "acme");
    c->set("iat", static_cast<Poco::Int64>(kNow));
    c->set("exp", static_cast<Poco::Int64>(exp));
    return sign(c, secret);
}

}  // namespace

// A token signed with the right secret verifies and yields its claims.
TEST(JwtSecurity, ValidTokenVerifies) {
    std::string tok = makeToken(kSecret, "alice", kNow + 3600);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    ASSERT_TRUE(verify(tok, kSecret, kNow, claims, err)) << err;
    EXPECT_EQ(claims->optValue<std::string>("sub", ""), "alice");
}

// A token minted with a different secret must NOT verify against ours — this is
// the core "can't forge without the secret" guarantee.
TEST(JwtSecurity, WrongSecretRejected) {
    std::string tok = makeToken("attacker-guessed-secret", "alice", kNow + 3600);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
    EXPECT_EQ(err, "bad signature");
}

// Flipping a byte of the payload (e.g. escalating a claim) breaks the signature.
TEST(JwtSecurity, TamperedPayloadRejected) {
    std::string tok = makeToken(kSecret, "alice", kNow + 3600);
    // Corrupt a character in the payload segment (between the two dots).
    size_t p1 = tok.find('.');
    size_t p2 = tok.find('.', p1 + 1);
    ASSERT_NE(p1, std::string::npos);
    ASSERT_NE(p2, std::string::npos);
    tok[p1 + 1] = (tok[p1 + 1] == 'A') ? 'B' : 'A';
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
    EXPECT_EQ(err, "bad signature");
}

// "alg":"none" style unsigned tokens: an attacker crafts header+payload with an
// empty or bogus signature. Because verify() recomputes the HMAC with the
// secret and compares, no signature the attacker can produce will match.
TEST(JwtSecurity, AlgNoneUnsignedRejected) {
    const std::string header = R"({"alg":"none","typ":"JWT"})";
    const std::string payload = R"({"sub":"attacker","tenant":"acme","exp":99999999999})";
    std::string tok = b64urlEncode(header) + "." + b64urlEncode(payload) + ".";  // empty sig
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
}

// alg-confusion: a token with a valid HS256 signature but whose header advertises
// a different algorithm must be rejected by the pinned-alg check.
TEST(JwtSecurity, NonHs256AlgRejected) {
    const std::string header = R"({"alg":"RS256","typ":"JWT"})";
    const std::string payload = R"({"sub":"alice","exp":99999999999})";
    std::string signingInput = b64urlEncode(header) + "." + b64urlEncode(payload);
    // Sign with the real secret so the signature is *valid*; only the alg is wrong.
    std::string tok = signingInput + "." + b64urlEncode(hmac256(kSecret, signingInput));
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
    EXPECT_EQ(err, "unsupported alg");
}

// An expired token (now >= exp) is rejected even with a valid signature.
TEST(JwtSecurity, ExpiredTokenRejected) {
    std::string tok = makeToken(kSecret, "alice", kNow - 1);  // expired 1s ago
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
    EXPECT_EQ(err, "expired");
}

// A token that is valid *now* stops verifying once we advance past its exp.
TEST(JwtSecurity, TokenExpiresAtBoundary) {
    long exp = kNow + 100;
    std::string tok = makeToken(kSecret, "alice", exp);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_TRUE(verify(tok, kSecret, exp - 1, claims, err));   // just before
    EXPECT_FALSE(verify(tok, kSecret, exp, claims, err));      // exactly at exp (now >= exp)
    EXPECT_FALSE(verify(tok, kSecret, exp + 1, claims, err));  // after
}

// Structurally malformed tokens (not three dot-separated segments) are rejected.
TEST(JwtSecurity, MalformedTokenRejected) {
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify("not-a-jwt", kSecret, kNow, claims, err));
    EXPECT_FALSE(verify("only.two", kSecret, kNow, claims, err));
    EXPECT_FALSE(verify("a.b.c.d", kSecret, kNow, claims, err));
    EXPECT_FALSE(verify("", kSecret, kNow, claims, err));
}

// SECURITY NOTE (documented gap, not a failure): verify() only enforces exp when
// the claim is present. A token minted without an exp never expires. Tokens are
// always issued with exp today, so this is latent; if hardened, flip this to
// EXPECT_FALSE. Captured here so the behavior is visible and intentional.
TEST(JwtSecurity, TokenWithoutExpIsCurrentlyAccepted) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("sub", "alice");
    std::string tok = sign(c, kSecret);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_TRUE(verify(tok, kSecret, kNow, claims, err))
        << "If exp is later made mandatory, update this expectation to EXPECT_FALSE.";
}
