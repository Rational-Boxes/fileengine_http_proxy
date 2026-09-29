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

#pragma once

// Where a tenant door may look for roles, and which names it must refuse.
//
// Header-only and free of LDAP so the policy can be tested offline, like the
// JWT rules in test_security.cpp. The bug this exists to prevent was not a
// subtle one — it was a list of search bases that included the directory root —
// and it survived because nothing could assert on it without a live directory.
//
// DEPLOYMENT_MANAGEMENT_INTERFACE.md §6.2. Mirrors
// admin_master_control/src/admin_master_control/roles.py; the two must agree,
// and the prefix is the thing they agree on.

#include <algorithm>
#include <string>
#include <vector>

namespace fileengine {
namespace tenant_roles {

//: Deployment-tier roles live in this namespace and are resolved by the system
//: administration tier. A tenant door must never hand one to the core.
constexpr const char* kDeploymentRolePrefix = "system_";

//: Prefix match, deliberately — not membership of a known-role list.
//
// A role added to the directory before it is added to any code must still be
// refused. Matching a list would welcome it for exactly as long as the list
// lagged, and the lag is measured in releases.
inline bool isDeploymentRole(const std::string& role) {
    return role.rfind(kDeploymentRolePrefix, 0) == 0;
}

//: Everything that is not a deployment role, order preserved.
inline std::vector<std::string> stripDeploymentRoles(const std::vector<std::string>& roles) {
    std::vector<std::string> kept;
    kept.reserve(roles.size());
    for (const std::string& r : roles) {
        if (!isDeploymentRole(r)) kept.push_back(r);
    }
    return kept;
}

//: The ONE base a tenant door may search for roles, or empty to refuse.
//
// Returns empty when the configured tenant base is missing or equal to the
// directory root. Both are refusals rather than fallbacks: a root search is the
// defect this policy exists to stop, and "just this once" is how it came back.
//
// SUBTREE scope from ou=tenants already covers every ou=<tenant> beneath it,
// which is what the old widening list of bases was reaching for by accident —
// while also reaching ou=groups, ou=Roles, ou=users and the root itself.
inline std::string roleSearchBase(const std::string& tenant_base,
                                  const std::string& ldap_domain) {
    if (tenant_base.empty()) return std::string();
    if (!ldap_domain.empty() && tenant_base == ldap_domain) return std::string();
    return tenant_base;
}

//: The base a deployment with no explicit tenant_base should use.
//
// Never the directory root. The old default WAS the root, which turned every
// tenant-scoped search into a whole-directory one without anyone choosing it.
inline std::string defaultTenantBase(const std::string& ldap_domain) {
    if (ldap_domain.empty()) return std::string();
    return "ou=tenants," + ldap_domain;
}

//: True when `base` sits inside the tenant subtree — the property every role
//: search must satisfy. Case-insensitive on the attribute names, because
//: directories are.
inline bool isWithinTenantScope(const std::string& base, const std::string& tenant_base) {
    if (base.empty() || tenant_base.empty()) return false;
    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        return s;
    };
    const std::string b = lower(base);
    const std::string t = lower(tenant_base);
    if (b.size() < t.size()) return false;
    // Either the tenant base itself, or something beneath it.
    return b == t || b.compare(b.size() - t.size(), t.size(), t) == 0;
}

}  // namespace tenant_roles
}  // namespace fileengine
