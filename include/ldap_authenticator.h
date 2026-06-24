#ifndef LDAP_AUTHENTICATOR_H
#define LDAP_AUTHENTICATOR_H

#include <ldap.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

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
        const std::string& user_base = ""
    );
    
    ~LDAPAuthenticator();
    
    // Authenticate user with username and password
    UserInfo authenticateUser(const std::string& username, const std::string& password);
    
    // Authenticate user with digest authentication
    bool authenticateDigest(const std::string& username, const std::string& realm, 
                           const std::string& nonce, const std::string& uri, 
                           const std::string& response, const std::string& method);
    
    // Get user information without authenticating (for already authenticated users)
    UserInfo getUserInfo(const std::string& username);

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

private:
    std::string ldap_endpoint_;
    std::string ldap_domain_;
    std::string bind_dn_;
    std::string bind_password_;
    std::string tenant_base_;
    std::string user_base_;

    mutable std::mutex ldap_mutex_;  // Protect LDAP operations
    
    // Helper function to connect to LDAP server
    LDAP* connectToLDAP();
    
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