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

// Which tenant states admit a login (§3.4c).
//
// Written BEFORE the state is used for anything, which is what §3.4c asks for:
// "a test per door asserting that a suspended tenant is refused — written before
// the state is ever used for anything, because the door that nobody wrote a test
// for is the door that will still be open."
//
// Offline, because the policy is header-only and shared verbatim between the
// doors. The point of the shared header is that there is one answer to "does
// this state admit"; the point of these tests is that the answer cannot drift.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "tenant_state_policy.h"

using namespace fileengine::tenant_state;

// ── only live admits ───────────────────────────────────────────────────────

TEST(TenantStatePolicy, OnlyLiveAdmits) {
    EXPECT_TRUE(admits(kLive));
    for (const char* s : {kRequested, kAwaitingDns, kProvisioning, kSuspended,
                          kDecommissioning, kDecommissioned}) {
        EXPECT_FALSE(admits(s)) << s << " must not admit a login";
    }
}

TEST(TenantStatePolicy, ASuspendedTenantIsRefused) {
    // The headline case, stated on its own so a regression names itself.
    EXPECT_FALSE(admits(kSuspended));
    EXPECT_FALSE(admits_or_refuses_unknown(kSuspended, /*lookup_succeeded=*/true));
}

TEST(TenantStatePolicy, AHalfBuiltTenantIsNotReachable) {
    // `provisioning` looks like an edge case and is not: the schema may exist
    // while roles, ACLs or the vhost do not.
    EXPECT_FALSE(admits(kProvisioning));
    EXPECT_FALSE(admits(kRequested));
    EXPECT_FALSE(admits(kAwaitingDns));
}

TEST(TenantStatePolicy, ADecommissionedTenantIsNotAWayBackIn) {
    // The registry row outlives the data so the name cannot be silently reused.
    // It must not become a route to the schema that replaced it.
    EXPECT_FALSE(admits(kDecommissioned));
    EXPECT_FALSE(admits(kDecommissioning));
}

// ── fail closed ────────────────────────────────────────────────────────────

TEST(TenantStatePolicy, AFailedLookupRefuses) {
    // §3.4c property 1. "The failure that matters is a suspended tenant admitted
    // because a lookup errored — and 'allow on error' is how that happens."
    EXPECT_FALSE(admits_or_refuses_unknown(kLive, /*lookup_succeeded=*/false));
    EXPECT_FALSE(admits_or_refuses_unknown("", false));
}

TEST(TenantStatePolicy, AnUnknownStateRefuses) {
    // A state this build does not recognise is not a state it may admit. The
    // allowlist-of-one makes this automatic: a state added to the registry later
    // is refused until this build learns about it, rather than admitted by
    // default.
    EXPECT_FALSE(known("archived"));
    EXPECT_FALSE(admits_or_refuses_unknown("archived", true));
    EXPECT_FALSE(admits_or_refuses_unknown("LIVE", true)) << "case matters; do not guess";
}

TEST(TenantStatePolicy, AnEmptyStateRefuses) {
    EXPECT_FALSE(admits(""));
    EXPECT_FALSE(admits_or_refuses_unknown("", true));
}

TEST(TenantStatePolicy, LiveWithASuccessfulLookupIsTheOnlyWayThrough) {
    EXPECT_TRUE(admits_or_refuses_unknown(kLive, true));
}

// ── the refusal says why, and says the right why ───────────────────────────

TEST(TenantStatePolicy, ASuspensionSaysSoRatherThanLookingLikeBadCredentials) {
    // §3.4c property 4: "a user told 'invalid credentials' will try again, then
    // call support, who will also not know."
    EXPECT_EQ(refusal_reason(kSuspended, true), "this tenant is suspended");
    EXPECT_EQ(refusal_code(kSuspended, true), "tenant_suspended");
}

TEST(TenantStatePolicy, AFailedLookupDoesNotClaimASuspension) {
    // The distinction an operator needs: nobody should go hunting for a
    // suspension that does not exist.
    const std::string reason = refusal_reason(kLive, false);
    EXPECT_NE(reason.find("could not be determined"), std::string::npos);
    EXPECT_EQ(reason.find("suspended"), std::string::npos);
    EXPECT_EQ(refusal_code(kLive, false), "tenant_state_unknown");
}

TEST(TenantStatePolicy, EveryRefusingStateHasItsOwnReason) {
    for (const char* s : {kRequested, kAwaitingDns, kProvisioning, kSuspended,
                          kDecommissioning, kDecommissioned}) {
        EXPECT_FALSE(refusal_reason(s, true).empty()) << s << " needs a reason";
        EXPECT_FALSE(refusal_code(s, true).empty()) << s << " needs a code";
    }
}

TEST(TenantStatePolicy, LiveHasNoRefusalToReport) {
    EXPECT_TRUE(refusal_reason(kLive, true).empty());
    EXPECT_TRUE(refusal_code(kLive, true).empty());
}

TEST(TenantStatePolicy, NoReasonCanNameATenant) {
    // It is the caller's own tenant's status and nothing else. The property is
    // structural rather than textual: refusal_reason is never GIVEN a tenant
    // name, so it cannot put one in the message however it is worded. What the
    // wording must do is refer to the caller's own tenant deictically — "this
    // tenant" — so the sentence is about them and not about the estate.
    //
    // An earlier version of this test asserted the reason contained no "tenant "
    // at all, which "this tenant is suspended" trivially fails. That was the
    // test being wrong about its own point.
    for (const char* s : {kRequested, kAwaitingDns, kProvisioning, kSuspended,
                          kDecommissioning, kDecommissioned}) {
        const std::string r = refusal_reason(s, true);
        EXPECT_NE(r.find("this tenant"), std::string::npos)
            << "'" << r << "' should speak about THIS tenant";
    }
}

// ── the enum is complete ───────────────────────────────────────────────────

TEST(TenantStatePolicy, EveryDocumentedStateIsKnown) {
    for (const char* s : {kRequested, kAwaitingDns, kProvisioning, kLive,
                          kSuspended, kDecommissioning, kDecommissioned}) {
        EXPECT_TRUE(known(s)) << s;
    }
}

TEST(TenantStatePolicy, TheNamesMatchTheCoresSpelling) {
    // These strings cross a wire. The core writes them into the registry and the
    // door compares against them, so a rename on one side without the other
    // would silently refuse every login — or silently admit a suspended tenant.
    EXPECT_STREQ(kLive, "live");
    EXPECT_STREQ(kSuspended, "suspended");
    EXPECT_STREQ(kProvisioning, "provisioning");
    EXPECT_STREQ(kRequested, "requested");
    EXPECT_STREQ(kAwaitingDns, "awaiting_dns");
    EXPECT_STREQ(kDecommissioning, "decommissioning");
    EXPECT_STREQ(kDecommissioned, "decommissioned");
}
