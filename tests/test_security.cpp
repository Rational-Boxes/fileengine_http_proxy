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
#include <vector>

#include <Poco/JSON/Object.h>

#include "jwt.h"
#include "client_ip.h"

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

// ---------------------------------------------------------------------------
// Two-factor auth token contract (PROPOSAL §4.6). These pin the security-visible
// shape of the pre-auth `mfa_pending` challenge token and the `amr` claim, so a
// refactor can't silently weaken the gate. The verify() layer treats these like
// any other claims; the enforcement (resource gate rejects mfa_pending, IP
// binding) is in http_server authenticate()/verifyMfa — see test_e2e_2fa.sh for
// the end-to-end assertion. Here we ensure the claims survive a sign/verify
// round-trip intact and are secret-bound (unforgeable).

// A challenge token expressing the §4.6 contract: mfa_pending marker, IP binding
// (mip), amr=["pwd"], and NO roles map — so even if the gate missed it, it
// authorizes nothing.
static std::string makeMfaPending(const std::string& secret, const std::string& ip, long exp) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("sub", "alice");
    c->set("tenant", "acme");
    c->set("exp", static_cast<Poco::Int64>(exp));
    c->set("mfa_pending", true);
    c->set("mip", ip);
    Poco::JSON::Array::Ptr amr = new Poco::JSON::Array();
    amr->add("pwd");
    c->set("amr", amr);
    return sign(c, secret);
}

TEST(MfaToken, PendingClaimsRoundTrip) {
    std::string tok = makeMfaPending(kSecret, "203.0.113.9", kNow + 300);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    ASSERT_TRUE(verify(tok, kSecret, kNow, claims, err)) << err;
    EXPECT_TRUE(claims->optValue<bool>("mfa_pending", false));
    EXPECT_EQ(claims->optValue<std::string>("mip", ""), "203.0.113.9");
    // No roles: a pending token grants access to nothing on its own.
    EXPECT_FALSE(claims->has("roles"));
    auto amr = claims->getArray("amr");
    ASSERT_FALSE(amr.isNull());
    ASSERT_EQ(amr->size(), 1u);
    EXPECT_EQ(amr->getElement<std::string>(0), "pwd");
}

// The challenge token is secret-bound: an attacker can't forge one (e.g. to flip
// mfa_pending off or rebind mip to their own IP) without the signing secret.
TEST(MfaToken, PendingIsUnforgeableWithoutSecret) {
    std::string tok = makeMfaPending("attacker-secret", "10.0.0.1", kNow + 300);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
    EXPECT_EQ(err, "bad signature");
}

// Tampering the mip binding (to complete a stolen challenge from another IP)
// breaks the signature — the binding cannot be edited in place.
TEST(MfaToken, TamperedIpBindingRejected) {
    std::string tok = makeMfaPending(kSecret, "203.0.113.9", kNow + 300);
    size_t p1 = tok.find('.'), p2 = tok.find('.', tok.find('.') + 1);
    tok[p1 + 1] = (tok[p1 + 1] == 'A') ? 'B' : 'A';  // corrupt payload
    (void)p2;
    Poco::JSON::Object::Ptr claims;
    std::string err;
    EXPECT_FALSE(verify(tok, kSecret, kNow, claims, err));
}

// A completed session records the second factor in amr (["pwd","otp"], etc.),
// and that survives the round-trip so downstream can reason about it.
TEST(MfaToken, CompletedAmrRoundTrip) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("sub", "alice");
    c->set("tenant", "acme");
    c->set("exp", static_cast<Poco::Int64>(kNow + 900));
    Poco::JSON::Array::Ptr amr = new Poco::JSON::Array();
    amr->add("pwd");
    amr->add("otp");
    c->set("amr", amr);
    std::string tok = sign(c, kSecret);
    Poco::JSON::Object::Ptr claims;
    std::string err;
    ASSERT_TRUE(verify(tok, kSecret, kNow, claims, err)) << err;
    auto got = claims->getArray("amr");
    ASSERT_FALSE(got.isNull());
    ASSERT_EQ(got->size(), 2u);
    EXPECT_EQ(got->getElement<std::string>(1), "otp");
    EXPECT_FALSE(claims->optValue<bool>("mfa_pending", false));
}

// ---------------------------------------------------------------------------
// Trusted-proxy real-client-IP resolution (client_ip.h). These pin that the
// hardened path cannot be fooled by a spoofed X-Forwarded-For, and that the dev
// path is unchanged.

using httpbridge::resolveClientIp;

// Development (no trusted proxies): the first XFF hop is trusted; else the peer.
TEST(ClientIp, DevTrustsFirstHopOrPeer) {
    EXPECT_EQ(resolveClientIp("127.0.0.1", "203.0.113.9, 10.0.0.1", {}), "203.0.113.9");
    EXPECT_EQ(resolveClientIp("198.51.100.7", "", {}), "198.51.100.7");
}

// Hardened: XFF from a trusted proxy peer -> the right-most NON-trusted hop is the
// real client (proxies to its right are stripped, spoofed entries to its left are
// ignored).
TEST(ClientIp, HardenedReturnsRealClient) {
    std::vector<std::string> trusted = {"10.0.0.0/8", "127.0.0.1"};
    // peer is the proxy; XFF = "<client>, <proxy>"
    EXPECT_EQ(resolveClientIp("10.0.0.5", "203.0.113.9, 10.0.0.5", trusted), "203.0.113.9");
    // chained proxies: real client is left of the trusted chain
    EXPECT_EQ(resolveClientIp("127.0.0.1", "203.0.113.9, 10.1.2.3, 10.0.0.5", trusted),
              "203.0.113.9");
}

// Spoofing: a client injects a fake left-most XFF entry. The resolver must ignore
// it and return the address the trusted proxy actually observed.
TEST(ClientIp, HardenedIgnoresSpoofedLeftmost) {
    std::vector<std::string> trusted = {"10.0.0.0/8"};
    // Attacker sent "9.9.9.9"; the trusted proxy appended the real peer 203.0.113.9.
    EXPECT_EQ(resolveClientIp("10.0.0.5", "9.9.9.9, 203.0.113.9, 10.0.0.5", trusted),
              "203.0.113.9");
}

// A direct connection (peer is NOT a trusted proxy) cannot spoof via XFF at all —
// the socket peer wins, the header is ignored.
TEST(ClientIp, HardenedUntrustedPeerIgnoresXff) {
    std::vector<std::string> trusted = {"10.0.0.0/8"};
    EXPECT_EQ(resolveClientIp("203.0.113.50", "1.2.3.4", trusted), "203.0.113.50");
}

// CIDR + plain-IP matching sanity.
TEST(ClientIp, CidrMatching) {
    EXPECT_TRUE(httpbridge::ipInCidr("10.1.2.3", "10.0.0.0/8"));
    EXPECT_FALSE(httpbridge::ipInCidr("11.1.2.3", "10.0.0.0/8"));
    EXPECT_TRUE(httpbridge::ipInCidr("127.0.0.1", "127.0.0.1"));
    EXPECT_FALSE(httpbridge::ipInCidr("garbage", "10.0.0.0/8"));  // fail-closed
}
