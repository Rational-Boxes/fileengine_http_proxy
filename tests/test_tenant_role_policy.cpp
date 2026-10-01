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

// Where a tenant door may look for roles, and which names it must refuse.
//
// These exist because the defect they cover was not subtle and still survived:
// extractRolesFromGroups searched a LIST of bases that included the directory
// root, ou=groups, ou=Roles and ou=users, and it did not stop at the first one
// that answered — it unioned them. Every groupOfNames anywhere in the directory
// naming the user became a role of theirs in tenant context.
//
// Nothing asserted on it because the policy lived inside a function that needs
// a live LDAP connection to call. So the policy now lives in a header, and this
// suite runs offline like test_security.cpp does for the JWT rules.
//
// DEPLOYMENT_MANAGEMENT_INTERFACE.md §6.2. This must agree with
// admin_master_control/src/admin_master_control/roles.py.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "tenant_role_policy.h"

using namespace fileengine::tenant_roles;

namespace {
const std::string kDomain = "dc=rationalboxes,dc=com";
const std::string kTenants = "ou=tenants,dc=rationalboxes,dc=com";
}  // namespace

// ── the namespace ──────────────────────────────────────────────────────────

TEST(TenantRolePolicy, RecognisesTheDeploymentNamespace) {
    EXPECT_TRUE(isDeploymentRole("system_owner"));
    EXPECT_TRUE(isDeploymentRole("system_security"));
    EXPECT_TRUE(isDeploymentRole("system_billing"));
}

TEST(TenantRolePolicy, RefusesARoleAddedBeforeAnyCodeKnowsIt) {
    // The point of matching a prefix rather than a list: the directory can gain
    // a role today and this code learn about it next release. It must be
    // refused for the whole of that gap.
    EXPECT_TRUE(isDeploymentRole("system_something_nobody_has_written_yet"));
}

TEST(TenantRolePolicy, LeavesOrdinaryTenantRolesAlone) {
    EXPECT_FALSE(isDeploymentRole("administrators"));
    EXPECT_FALSE(isDeploymentRole("contributors"));
    EXPECT_FALSE(isDeploymentRole("erasure_admins"));
    EXPECT_FALSE(isDeploymentRole("file_services"));
    EXPECT_FALSE(isDeploymentRole(""));
}

TEST(TenantRolePolicy, DoesNotMatchOnASubstring) {
    // "subsystem_owner" is not in the namespace; only a PREFIX is.
    EXPECT_FALSE(isDeploymentRole("subsystem_owner"));
    EXPECT_FALSE(isDeploymentRole("my_system_owner"));
}

TEST(TenantRolePolicy, StripsOnlyTheDeploymentRolesAndKeepsOrder) {
    const std::vector<std::string> in = {
        "users", "system_security", "contributors", "system_owner", "erasure_admins"};
    EXPECT_EQ(stripDeploymentRoles(in),
              (std::vector<std::string>{"users", "contributors", "erasure_admins"}));
}

TEST(TenantRolePolicy, StrippingAnAllDeploymentSetLeavesNothing) {
    // Fails CLOSED: a user whose only groups are deployment roles gets no
    // tenant roles, rather than being handed them.
    const std::vector<std::string> in = {"system_owner", "system_billing"};
    EXPECT_TRUE(stripDeploymentRoles(in).empty());
}

// ── the search base ────────────────────────────────────────────────────────

TEST(TenantRolePolicy, TheOnlySearchBaseIsTheTenantSubtree) {
    EXPECT_EQ(roleSearchBase(kTenants, kDomain), kTenants);
}

TEST(TenantRolePolicy, RefusesTheDirectoryRootAsABase) {
    // THE REGRESSION. A tenant base equal to the root turns every tenant-scoped
    // search into a whole-directory one, which is exactly what the old fallback
    // list did explicitly. Empty means refuse, not "search the root".
    EXPECT_EQ(roleSearchBase(kDomain, kDomain), std::string());
}

TEST(TenantRolePolicy, RefusesAnUnsetBaseRatherThanWidening) {
    EXPECT_EQ(roleSearchBase("", kDomain), std::string());
}

TEST(TenantRolePolicy, TheDefaultBaseIsNeverTheRoot) {
    // The old constructor defaulted tenant_base_ to ldap_domain when unset, so
    // a deployment that simply did not set it searched the whole directory and
    // nobody chose that.
    const std::string d = defaultTenantBase(kDomain);
    EXPECT_EQ(d, kTenants);
    EXPECT_NE(d, kDomain);
    EXPECT_NE(roleSearchBase(d, kDomain), std::string());
}

// ── scope ──────────────────────────────────────────────────────────────────

TEST(TenantRolePolicy, TenantOusAreWithinScope) {
    EXPECT_TRUE(isWithinTenantScope(kTenants, kTenants));
    EXPECT_TRUE(isWithinTenantScope("ou=acme,ou=tenants,dc=rationalboxes,dc=com", kTenants));
    EXPECT_TRUE(isWithinTenantScope(
        "cn=administrators,ou=acme,ou=tenants,dc=rationalboxes,dc=com", kTenants));
}

TEST(TenantRolePolicy, TheBasesTheOldCodeSearchedAreOutOfScope) {
    // Each of these was in the old fallback list, and a group under any of them
    // became a tenant role.
    for (const char* base : {"dc=rationalboxes,dc=com",
                             "ou=groups,dc=rationalboxes,dc=com",
                             "ou=Group,dc=rationalboxes,dc=com",
                             "ou=Roles,dc=rationalboxes,dc=com",
                             "ou=role,dc=rationalboxes,dc=com",
                             "ou=users,dc=rationalboxes,dc=com",
                             "ou=services,dc=rationalboxes,dc=com"}) {
        EXPECT_FALSE(isWithinTenantScope(base, kTenants)) << base << " must not be searchable";
    }
}

TEST(TenantRolePolicy, ScopeIsCaseInsensitiveLikeTheDirectory) {
    EXPECT_TRUE(isWithinTenantScope("OU=Acme,OU=Tenants,DC=rationalboxes,DC=com", kTenants));
}

// ── the two layers together ────────────────────────────────────────────────

TEST(TenantRolePolicy, ADeploymentGroupMisplacedInsideATenantIsStillRefused) {
    // The layered defence §6.2 asks for. Scoping the SEARCH depends on
    // directory layout, and layout is configuration: a system_* group moved
    // into a tenant OU by mistake sits inside a base this code is entitled to
    // search. The name filter is what catches it then.
    const std::string misplaced = "cn=system_security,ou=acme,ou=tenants,dc=rationalboxes,dc=com";
    EXPECT_TRUE(isWithinTenantScope(misplaced, kTenants)) << "the search would reach it";
    EXPECT_TRUE(isDeploymentRole("system_security")) << "and the filter must refuse it";
    EXPECT_TRUE(stripDeploymentRoles({"system_security"}).empty());
}
