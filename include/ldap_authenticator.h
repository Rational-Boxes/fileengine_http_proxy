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

#ifndef LDAP_AUTHENTICATOR_H
#define LDAP_AUTHENTICATOR_H

#include <ldap.h>
#include <map>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

#include "circuit_breaker.h"

namespace webdav {

struct UserInfo {
    std::string dn;              // Distinguished Name
    std::string user_id;         // User ID
    std::vector<std::string> roles;  // User roles
    std::string tenant;          // User's tenant
    bool authenticated;          // Whether authentication was successful
};

class LDAPAuthenticator {
public:
    LDAPAuthenticator(
        const std::string& ldap_endpoint,
        const std::string& ldap_domain,
        const std::string& bind_dn,
        const std::string& bind_password,
        const std::string& tenant_base = "",
        const std::string& user_base = "",
        // Read-only replica directory for disconnect fault tolerance
        // (REPLICATION_FAILOVER.md). Empty disables failover. When the master is
        // unreachable, auth (read-only) fails over to this replica.
        const std::string& replica_endpoint = "",
        double failover_cooldown_s = 30.0
    );
    
    ~LDAPAuthenticator();
    
    // Authenticate user with username and password
    UserInfo authenticateUser(const std::string& username, const std::string& password);
    
    // Resolve a user already authenticated by an external IdP (OAuth/OIDC) from
    // their email address. Returns the LDAP-resolved identity (real uid + roles)
    // so an OAuth login maps to exactly the same gRPC identity as a Basic login.
    // `authenticated` is false if no single matching entry exists.
    UserInfo getUserInfoByEmail(const std::string& email);

    // Enumerate the tenants a user has access to. A user has access to a tenant
    // when they are a member of any group under that tenant's subtree
    // (ou=<tenant>,<tenant_base>). Returns the sorted, de-duplicated tenant
    // names; empty if the user or their memberships cannot be resolved.
    std::vector<std::string> getTenantsForUser(const std::string& username);

    // Type-ahead user search for the ACL editor. Returns up to `limit` distinct
    // uids whose uid, cn, or mail begins with `prefix` (LDAP substring matching
    // is case-insensitive for these attributes). `prefix` is escaped, so raw
    // user input is safe. An empty prefix returns the first `limit` users. A
    // limit <= 0 applies a sane internal cap.
    std::vector<std::string> searchUsers(const std::string& prefix, int limit);

    // Type-ahead role search for the ACL editor. Returns up to `limit` distinct
    // role names (the cn of groupOfNames entries) under the given tenant's subtree
    // whose cn begins with `prefix`. This is the SAME set authorization resolves
    // from and the admin console manages — so LDAP-created roles are assignable.
    // Scoped to the tenant's subtree to avoid cross-tenant leakage. `prefix` is
    // escaped; an empty prefix returns the first `limit` roles.
    std::vector<std::string> searchRoles(const std::string& tenant,
                                         const std::string& prefix, int limit);

    // Resolve EVERY tenant the user has roles in, mapped to their roles in that
    // tenant, by bucketing the user's groupOfNames memberships by the tenant
    // parsed from each group DN. Backs the JWT's {tenant:[roles]} claim.
    std::map<std::string, std::vector<std::string>>
    getRolesByTenant(const std::string& username);

private:
    std::string ldap_endpoint_;
    std::string ldap_domain_;
    std::string bind_dn_;
    std::string bind_password_;
    std::string tenant_base_;
    std::string user_base_;
    std::string replica_endpoint_;       // empty => failover disabled
    CircuitBreaker breaker_;             // master availability (guarded by ldap_mutex_)

    mutable std::mutex ldap_mutex_;  // Protect LDAP operations

    // Connect to the master, or fail over to the read-only replica when the master
    // is unreachable (master-only when no replica is configured).
    LDAP* connectToLDAP();

    // Bind a service connection to a specific endpoint; nullptr on failure.
    LDAP* connectToEndpoint(const std::string& endpoint);
    
    // Helper function to search for a user by an arbitrary filter. `display_id`
    // is used only for logging; the real uid is read from the matched entry.
    UserInfo searchUserByFilter(LDAP* ld, const std::string& filter, const std::string& display_id);

    // Helper function to search for a user by uid.
    UserInfo searchUser(LDAP* ld, const std::string& username);
    
    // Helper function to extract tenant from user's DN
    std::string extractTenantFromUserDN(const std::string& user_dn);
    
    // Helper function to extract roles from user's group memberships
    std::vector<std::string> extractRolesFromGroups(LDAP* ld, const std::string& user_dn);
};

} // namespace webdav

#endif // LDAP_AUTHENTICATOR_H