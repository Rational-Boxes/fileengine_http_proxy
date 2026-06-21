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
    
    // Helper function to search for a user
    UserInfo searchUser(LDAP* ld, const std::string& username);
    
    // Helper function to extract tenant from user's DN
    std::string extractTenantFromUserDN(const std::string& user_dn);
    
    // Helper function to extract roles from user's group memberships
    std::vector<std::string> extractRolesFromGroups(LDAP* ld, const std::string& user_dn);
};

} // namespace webdav

#endif // LDAP_AUTHENTICATOR_H