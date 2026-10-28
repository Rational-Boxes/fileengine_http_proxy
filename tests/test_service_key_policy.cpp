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

// Offline tests for the generated key:secret session rules (service_key_policy.h).
// The live flow — mint, refresh, rotate, revoke, sign-out — is
// tests/test_e2e_api_key.sh; these pin the decisions it depends on.

#include <gtest/gtest.h>

#include "service_key_policy.h"

using fileengine::service_key::KeyVerdict;
using fileengine::service_key::classifyVerifyAnswer;
using fileengine::service_key::isServiceKeyId;
using fileengine::service_key::mayRefresh;
using fileengine::service_key::rolesForKeySession;
using fileengine::session_amr::satisfiesSecondFactor;

TEST(ServiceKeyPolicy, OnlyTheMintedPrefixTakesTheKeyPath) {
    EXPECT_TRUE(isServiceKeyId("fesk_6QRxFHYwWrniksq6"));
    // A directory uid — the password path — must never be routed to key checks.
    EXPECT_FALSE(isServiceKeyId("testuser@rationalboxes.com"));
    EXPECT_FALSE(isServiceKeyId("FESK_upper"));
    EXPECT_FALSE(isServiceKeyId("xfesk_embedded"));
    EXPECT_FALSE(isServiceKeyId("fesks_this_is_a_secret_not_a_key"));
    EXPECT_FALSE(isServiceKeyId(""));
}

TEST(ServiceKeyPolicy, KeySessionHoldsTheKeysTenantOnly) {
    const std::map<std::string, std::vector<std::string>> all = {
        {"default", {"users", "administrators"}},
        {"filenginetest", {"users"}},
    };
    auto only = rolesForKeySession(all, "default");
    ASSERT_EQ(only.size(), 1u);
    EXPECT_EQ(only.at("default"), (std::vector<std::string>{"users", "administrators"}));
    EXPECT_EQ(only.count("filenginetest"), 0u);
    // Not a member of the key's tenant: nothing at all, not a fallback tenant.
    EXPECT_TRUE(rolesForKeySession(all, "bigcorp").empty());
}

TEST(ServiceKeyPolicy, OnlyA401MeansABadCredential) {
    EXPECT_EQ(classifyVerifyAnswer(200, "alice", "0123456789abcdef"), KeyVerdict::Valid);
    EXPECT_EQ(classifyVerifyAnswer(401, "", ""), KeyVerdict::Invalid);
    // Configuration and availability faults are the deployment's, not the key's.
    for (int st : {0, 403, 404, 422, 500, 502, 503})
        EXPECT_EQ(classifyVerifyAnswer(st, "", ""), KeyVerdict::Unavailable) << st;
}

TEST(ServiceKeyPolicy, A200WithoutUidOrGenerationIsNotValid) {
    // An ldap_manager too old to send a generation cannot support a safe refresh.
    EXPECT_EQ(classifyVerifyAnswer(200, "alice", ""), KeyVerdict::Unavailable);
    EXPECT_EQ(classifyVerifyAnswer(200, "", "0123456789abcdef"), KeyVerdict::Unavailable);
}

namespace {
const std::vector<std::string> kTenants = {"default", "filenginetest"};
}

TEST(ServiceKeyPolicy, RefreshWhileTheKeyIsLive) {
    EXPECT_TRUE(mayRefresh(KeyVerdict::Valid, "alice", "gen1", "alice", "gen1", kTenants,
                           "default"));
}

TEST(ServiceKeyPolicy, RefreshStopsWhenTheKeyIsRevokedOrUnavailable) {
    EXPECT_FALSE(mayRefresh(KeyVerdict::Invalid, "", "", "alice", "gen1", kTenants, "default"));
    EXPECT_FALSE(mayRefresh(KeyVerdict::Unavailable, "alice", "gen1", "alice", "gen1", kTenants,
                            "default"));
}

TEST(ServiceKeyPolicy, RefreshStopsWhenTheSecretWasRegenerated) {
    // Same key_id, new secret: the generation moved on.
    EXPECT_FALSE(mayRefresh(KeyVerdict::Valid, "alice", "gen2", "alice", "gen1", kTenants,
                            "default"));
    // A session with no generation recorded is never renewable as a key session.
    EXPECT_FALSE(mayRefresh(KeyVerdict::Valid, "alice", "", "alice", "", kTenants, "default"));
}

TEST(ServiceKeyPolicy, RefreshStopsForAnotherUserOrALostMembership) {
    EXPECT_FALSE(mayRefresh(KeyVerdict::Valid, "mallory", "gen1", "alice", "gen1", kTenants,
                            "default"));
    EXPECT_FALSE(mayRefresh(KeyVerdict::Valid, "alice", "gen1", "alice", "gen1", {"filenginetest"},
                            "default"));
    EXPECT_FALSE(mayRefresh(KeyVerdict::Valid, "alice", "gen1", "alice", "gen1", {}, "default"));
}

TEST(SessionAmr, KeySessionSatisfiesATenantsSecondFactorRequirement) {
    EXPECT_TRUE(satisfiesSecondFactor({"svc"}));
    EXPECT_TRUE(satisfiesSecondFactor({"pwd", "totp"}));
    EXPECT_TRUE(satisfiesSecondFactor({"pwd", "email"}));
    EXPECT_TRUE(satisfiesSecondFactor({"oauth"}));
    // Password alone does not, and neither does nothing.
    EXPECT_FALSE(satisfiesSecondFactor({"pwd"}));
    EXPECT_FALSE(satisfiesSecondFactor({}));
    EXPECT_FALSE(satisfiesSecondFactor({"integration"}));
}
