// Tests for the assertion-jti replay guard (include/replay_guard.h).
#include <gtest/gtest.h>
#include "replay_guard.h"

using httpbridge::ReplayGuard;

TEST(ReplayGuard, FirstUseAcceptedReplayRefused) {
    ReplayGuard g;
    EXPECT_TRUE(g.accept("jti-1", /*exp*/ 2000, /*now*/ 1000));   // first use ok
    EXPECT_FALSE(g.accept("jti-1", 2000, 1000));                  // replay within life
    EXPECT_TRUE(g.accept("jti-2", 2000, 1000));                   // distinct jti ok
}

TEST(ReplayGuard, AcceptedAgainOnceRecordExpires) {
    ReplayGuard g;
    EXPECT_TRUE(g.accept("jti-1", /*exp*/ 1500, /*now*/ 1000));
    EXPECT_FALSE(g.accept("jti-1", 1500, 1400));  // still live
    // now past the record's expiry: the key is free again (and old records purged).
    EXPECT_TRUE(g.accept("jti-1", 3000, 1600));
}

TEST(ReplayGuard, EmptyJtiNeverStoredAlwaysAccepted) {
    ReplayGuard g;
    EXPECT_TRUE(g.accept("", 2000, 1000));
    EXPECT_TRUE(g.accept("", 2000, 1000));
    EXPECT_EQ(g.size(), 0u);
}

TEST(ReplayGuard, ExpiredRecordsArePurged) {
    ReplayGuard g;
    g.accept("a", 1100, 1000);
    g.accept("b", 1200, 1000);
    EXPECT_EQ(g.size(), 2u);
    // A later accept triggers a purge of everything expired by then.
    g.accept("c", 5000, 4000);
    EXPECT_EQ(g.size(), 1u);  // a and b purged, only c remains
}
