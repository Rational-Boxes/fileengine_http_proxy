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

/**
 * The denylist decides whether someone stays signed in, so the parts that make
 * that decision — the cache and the unreachable-store policy — are tested here
 * with the Redis backend replaced. The point is not that hiredis works; it is
 * that an unanswerable lookup refuses, which is the property the whole feature
 * rests on and the one that is easiest to get quietly backwards.
 */
#include <gtest/gtest.h>

#include <set>
#include <string>

#include "token_denylist.h"

using httpbridge::Revocation;
using httpbridge::TokenDenylist;

namespace {

// A stand-in store whose reachability the test controls.
struct FakeRedis {
    std::set<std::string> revoked;
    bool reachable = true;
    int lookups = 0;

    TokenDenylist::Lookup lookup() {
        return [this](const std::string& jti) {
            ++lookups;
            if (!reachable) return Revocation::Unknown;
            return revoked.count(jti) ? Revocation::Revoked : Revocation::Allowed;
        };
    }
    TokenDenylist::Store store() {
        return [this](const std::string& jti, int) {
            if (!reachable) return false;
            revoked.insert(jti);
            return true;
        };
    }
    TokenDenylist::Ping ping() {
        return [this]() { return reachable; };
    }
};

TokenDenylist::Options opts(int cache_ttl = 0, bool fail_open = false) {
    TokenDenylist::Options o;
    o.enabled = true;
    o.cache_ttl = cache_ttl;   // 0 = ask every time, so tests are not clock-bound
    o.fail_open = fail_open;
    return o;
}

TokenDenylist make(FakeRedis& r, int cache_ttl = 0, bool fail_open = false) {
    return TokenDenylist(opts(cache_ttl, fail_open), r.lookup(), r.store(), r.ping());
}

}  // namespace

TEST(TokenDenylist, PermitsATokenNobodySignedOut) {
    FakeRedis r;
    auto d = make(r);
    EXPECT_TRUE(d.permits("jti-live"));
    EXPECT_EQ(d.check("jti-live"), Revocation::Allowed);
}

TEST(TokenDenylist, RefusesATokenAfterItIsRevoked) {
    // The whole point: signing out has to stop the token, not merely note that
    // someone asked.
    FakeRedis r;
    auto d = make(r);
    ASSERT_TRUE(d.permits("jti-1"));
    ASSERT_TRUE(d.revoke("jti-1", 900));
    EXPECT_FALSE(d.permits("jti-1"));
    EXPECT_EQ(d.check("jti-1"), Revocation::Revoked);
}

TEST(TokenDenylist, RevocationIsPerTokenNotGlobal) {
    FakeRedis r;
    auto d = make(r);
    ASSERT_TRUE(d.revoke("jti-1", 900));
    EXPECT_FALSE(d.permits("jti-1"));
    EXPECT_TRUE(d.permits("jti-2"));   // another live session is unaffected
}

TEST(TokenDenylist, AnAlreadyExpiredTokenNeedsNoEntry) {
    // exp is in the past, so exp-now is <= 0. Writing it would be dead weight:
    // the token is refused on exp alone.
    FakeRedis r;
    auto d = make(r);
    EXPECT_TRUE(d.revoke("jti-expired", 0));
    EXPECT_TRUE(d.revoke("jti-expired", -30));
    EXPECT_TRUE(r.revoked.empty());
}

TEST(TokenDenylist, ATokenWithNoJtiCannotBeRevokedAndIsStillPermitted) {
    // Download tickets carry no jti — they are scoped to one file and live for
    // seconds. Refusing every jti-less token here would break them; claiming to
    // have revoked one would be a lie.
    FakeRedis r;
    auto d = make(r);
    EXPECT_TRUE(d.permits(""));
    EXPECT_FALSE(d.revoke("", 900));
}

// ---- the part that matters: an unreachable store ---------------------------

TEST(TokenDenylist, RefusesWhenTheStoreCannotBeReached) {
    // FAIL CLOSED. A verdict we could not obtain is not a token we may honour:
    // honouring it restores exactly the behaviour this class removes, and does it
    // invisibly.
    FakeRedis r;
    auto d = make(r);
    r.reachable = false;
    EXPECT_EQ(d.check("jti-1"), Revocation::Unknown);
    EXPECT_FALSE(d.permits("jti-1"));
}

TEST(TokenDenylist, FailOpenHonoursAnUnknownVerdictWhenAskedTo) {
    // Only on an explicit choice, never by default.
    FakeRedis r;
    auto d = make(r, /*cache_ttl=*/0, /*fail_open=*/true);
    r.reachable = false;
    EXPECT_EQ(d.check("jti-1"), Revocation::Unknown);
    EXPECT_TRUE(d.permits("jti-1"));
}

TEST(TokenDenylist, ReportsAFailedRevocationRatherThanSwallowingIt) {
    // The caller answers 503 on this, instead of a 204 that says the session
    // ended when it did not.
    FakeRedis r;
    r.reachable = false;
    auto d = make(r);
    EXPECT_FALSE(d.revoke("jti-1", 900));
}

TEST(TokenDenylist, DisabledMeansDisabled) {
    // Nothing claims to be revoking, so nothing is refused and revoke() does not
    // report a failure it was never trying to avoid.
    FakeRedis r;
    auto o = opts();
    o.enabled = false;
    TokenDenylist d(o, r.lookup(), r.store(), r.ping());
    EXPECT_TRUE(d.permits("jti-1"));
    EXPECT_TRUE(d.revoke("jti-1", 900));
    EXPECT_EQ(r.lookups, 0);           // and it does not touch Redis at all
}

// ---- the cache --------------------------------------------------------------

TEST(TokenDenylist, CachesAVerdictInsteadOfAskingEveryRequest) {
    // Without this, every authenticated request would queue on one Redis
    // connection — the reason a per-request check is affordable at all.
    FakeRedis r;
    auto d = make(r, /*cache_ttl=*/60);
    EXPECT_TRUE(d.permits("jti-1"));
    EXPECT_TRUE(d.permits("jti-1"));
    EXPECT_TRUE(d.permits("jti-1"));
    EXPECT_EQ(r.lookups, 1);
}

TEST(TokenDenylist, ZeroCacheTtlAsksEveryTime) {
    FakeRedis r;
    auto d = make(r, /*cache_ttl=*/0);
    d.permits("jti-1");
    d.permits("jti-1");
    EXPECT_EQ(r.lookups, 2);
}

TEST(TokenDenylist, RevokingStopsTheTokenOnThisInstanceImmediately) {
    // Not after cache_ttl. The instance that served the logout must not go on
    // honouring the token it just revoked because it cached "allowed" a moment
    // earlier — which is the ONE case where the cache could be actively wrong.
    FakeRedis r;
    auto d = make(r, /*cache_ttl=*/300);
    ASSERT_TRUE(d.permits("jti-1"));     // caches Allowed for 300s
    ASSERT_TRUE(d.revoke("jti-1", 900));
    EXPECT_FALSE(d.permits("jti-1"));
}

TEST(TokenDenylist, NeverCachesAnUnknown) {
    // Unknown is the absence of an answer. Caching it would stretch one
    // unreachable moment across the whole window — and, under fail-open, would
    // keep honouring a token that Redis could by then have told us was revoked.
    FakeRedis r;
    auto d = make(r, /*cache_ttl=*/300);
    r.reachable = false;
    EXPECT_FALSE(d.permits("jti-1"));
    r.reachable = true;
    r.revoked.insert("jti-1");
    EXPECT_EQ(r.lookups, 1);
    EXPECT_FALSE(d.permits("jti-1"));    // asked again, now definitively revoked
    EXPECT_EQ(r.lookups, 2);
}

TEST(TokenDenylist, HealthyFollowsTheStore) {
    FakeRedis r;
    auto d = make(r);
    EXPECT_TRUE(d.healthy());
    r.reachable = false;
    EXPECT_FALSE(d.healthy());
}
