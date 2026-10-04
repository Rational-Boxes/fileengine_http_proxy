// Download and playback tickets — the two URL-borne credentials (ticket_claims.h).
//
// A browser cannot attach an Authorization header to a navigation or to a
// <video src>, so both carry their credential in the query string. That is why
// each is scoped to ONE file, short-lived, and refused outright as a session.
// The playback ticket exists because a viewing outlives the download ticket's
// seconds: a <video> issues a fresh Range request every time it buffers or
// seeks. Its lifetime is capped at 30 minutes (decided 2026-10-03), whatever is
// configured.
#include <gtest/gtest.h>
#include "ticket_claims.h"
#include "jwt.h"

#include <sstream>
#include <Poco/JSON/Parser.h>

using namespace httpbridge;

namespace {
const std::string SECRET = "unit-test-shared-secret-value-32b!";
Poco::JSON::Object::Ptr roundTrip(const Poco::JSON::Object::Ptr& c) {
    std::ostringstream os; c->stringify(os);
    Poco::JSON::Parser p; return p.parse(os.str()).extract<Poco::JSON::Object::Ptr>();
}
Poco::JSON::Object::Ptr ticket(const std::string& typ, long ttl, const std::string& sid = "sess-1") {
    return buildTicketClaims("fileengine-bridge", "ann@acme", "acme", {"users"},
                             "file-123", typ, sid, 1000, ttl);
}
}  // namespace

TEST(TicketClaims, PlaybackShape) {
    auto j = roundTrip(ticket("playback", 1800));
    EXPECT_EQ(j->getValue<std::string>("typ"), "playback");
    EXPECT_EQ(j->getValue<std::string>("dl"), "file-123");
    EXPECT_EQ(j->getValue<std::string>("sub"), "ann@acme");
    EXPECT_EQ(j->getValue<std::string>("tenant"), "acme");
    EXPECT_EQ(j->getValue<std::string>("sid"), "sess-1");      // the minting session
    EXPECT_EQ(static_cast<long>(j->getValue<double>("exp")), 2800);
}

TEST(TicketClaims, DownloadShapeIsUnchanged) {
    auto j = roundTrip(ticket("download", 30));
    EXPECT_EQ(j->getValue<std::string>("typ"), "download");
    EXPECT_EQ(static_cast<long>(j->getValue<double>("exp")), 1030);
}

TEST(TicketClaims, NoSessionMeansNoSidClaim) {
    auto j = roundTrip(ticket("playback", 1800, ""));
    EXPECT_FALSE(j->has("sid"));
}

TEST(TicketClaims, PlaybackLifetimeIsCappedAtThirtyMinutes) {
    EXPECT_EQ(kPlaybackTicketMaxTtl, 1800);
    EXPECT_EQ(clampPlaybackTtl(7200), 1800);    // a configured 2 h is clamped
    EXPECT_EQ(clampPlaybackTtl(1800), 1800);
    EXPECT_EQ(clampPlaybackTtl(600), 600);      // shorter is allowed
    EXPECT_EQ(clampPlaybackTtl(0), 1800);       // unset → the cap
    EXPECT_EQ(clampPlaybackTtl(-5), 1800);
}

TEST(TicketClaims, ExpiresAtItsTtl) {
    std::string t = jwt::sign(ticket("playback", 1800), SECRET);
    Poco::JSON::Object::Ptr out; std::string err;
    EXPECT_TRUE(jwt::verify(t, SECRET, 2799, out, err)) << err;
    EXPECT_FALSE(jwt::verify(t, SECRET, 2800, out, err));
}

TEST(TicketClaims, OpensOnlyTheFileItNames) {
    auto c = roundTrip(ticket("playback", 1800));
    EXPECT_EQ(checkTicketClaims(c, "file-123"), TicketCheck::Ok);
    EXPECT_EQ(checkTicketClaims(c, "file-999"), TicketCheck::WrongUid);
}

TEST(TicketClaims, OnlyTicketTypesPass) {
    auto c = roundTrip(ticket("playback", 1800));
    c->set("typ", std::string("session"));
    EXPECT_EQ(checkTicketClaims(c, "file-123"), TicketCheck::WrongType);
    c->remove("typ");
    EXPECT_EQ(checkTicketClaims(c, "file-123"), TicketCheck::WrongType);
}

TEST(TicketClaims, BothKindsAreTicketsAndNothingElseIs) {
    EXPECT_TRUE(isTicketType("download"));
    EXPECT_TRUE(isTicketType("playback"));
    EXPECT_FALSE(isTicketType(""));
    EXPECT_FALSE(isTicketType("session"));
    EXPECT_FALSE(isTicketType("Playback"));
}
