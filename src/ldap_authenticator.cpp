#define LDAP_DEPRECATED 1

#include "ldap_authenticator.h"
#include "utils.h"  // For logging functions
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <cctype>
#include <ldap.h>

namespace webdav {

LDAPAuthenticator::LDAPAuthenticator(
    const std::string& ldap_endpoint,
    const std::string& ldap_domain,
    const std::string& bind_dn,
    const std::string& bind_password,
    const std::string& tenant_base,
    const std::string& user_base)
    : ldap_endpoint_(ldap_endpoint),
      ldap_domain_(ldap_domain),
      bind_dn_(bind_dn),
      bind_password_(bind_password),
      tenant_base_(tenant_base.empty() ? ldap_domain : tenant_base),
      user_base_(user_base.empty() ? ldap_domain : user_base) {
}

LDAPAuthenticator::~LDAPAuthenticator() {
}

UserInfo LDAPAuthenticator::authenticateUser(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lock(ldap_mutex_);
    webdav::debugLog("LDAPAuthenticator::authenticateUser: Starting authentication for user: " + username);

    LDAP* ld = connectToLDAP();
    if (!ld) {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: Failed to connect to LDAP server");
        return { "", "", {}, "", false };
    }

    // First, try to bind with the user's credentials
    std::string user_dn;
    LDAPMessage* result = nullptr;

    // Search for the user's DN
    std::string search_filter = "(uid=" + username + ")";
    webdav::debugLog("LDAPAuthenticator::authenticateUser: Searching for user with base: " + user_base_ + " and filter: " + search_filter);

    int ldap_result = ldap_search_s(
        ld,
        user_base_.c_str(),  // Use the configured user base
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: LDAP search failed: " + std::string(ldap_err2string(ldap_result)));
        webdav::errorLog("LDAPAuthenticator::authenticateUser: Search base: " + user_base_ + ", Filter: " + search_filter);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    int count = ldap_count_entries(ld, result);
    if (count != 1) {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: User not found or multiple entries found (count: " + std::to_string(count) + ")");
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: Failed to get LDAP entry");
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    char* dn = ldap_get_dn(ld, entry);
    if (!dn) {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: Failed to get DN");
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }

    user_dn = std::string(dn);
    ldap_memfree(dn);
    webdav::debugLog("LDAPAuthenticator::authenticateUser: Found user DN: " + user_dn);

    // Now try to bind with the user's DN and provided password
    struct berval cred;
    cred.bv_val = const_cast<char*>(password.c_str());
    cred.bv_len = password.length();

    ldap_result = ldap_sasl_bind_s(
        ld,
        user_dn.c_str(),
        LDAP_SASL_SIMPLE,
        &cred,
        nullptr,
        nullptr,
        nullptr
    );

    if (ldap_result != LDAP_SUCCESS) {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: User authentication failed: " + std::string(ldap_err2string(ldap_result)));
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return { "", "", {}, "", false };
    }
    webdav::debugLog("LDAPAuthenticator::authenticateUser: User password authentication successful");

    // Authentication successful, now get user info
    // We need to search for the user again to get their roles
    UserInfo user_info;
    user_info.dn = user_dn;
    user_info.user_id = username;
    user_info.tenant = extractTenantFromUserDN(user_dn);
    webdav::debugLog("LDAPAuthenticator::authenticateUser: Extracting roles for user from groups...");

    // Perform group search with admin credentials to ensure proper permissions
    // The user connection may not have permission to search for group memberships
    LDAP* admin_ld = connectToLDAP();  // Connect with admin credentials
    if (admin_ld) {
        user_info.roles = extractRolesFromGroups(admin_ld, user_dn);  // Extract roles from groups
        ldap_unbind_ext_s(admin_ld, nullptr, nullptr);  // Clean up admin connection
    } else {
        webdav::errorLog("LDAPAuthenticator::authenticateUser: Failed to create admin connection for role extraction, assigning default 'users' role");
        user_info.roles.push_back("users");  // Fallback to default role
    }

    user_info.authenticated = true;

    webdav::debugLog("LDAPAuthenticator::authenticateUser: User authenticated: " + username + " with " + std::to_string(user_info.roles.size()) + " roles");
    for (size_t i = 0; i < user_info.roles.size(); ++i) {
        webdav::debugLog("LDAPAuthenticator::authenticateUser:   Role " + std::to_string(i+1) + ": " + user_info.roles[i]);
    }

    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, nullptr, nullptr);
    webdav::debugLog("LDAPAuthenticator::authenticateUser: Completed authentication for user: " + username);
    return user_info;
}

bool LDAPAuthenticator::authenticateDigest(const std::string& username, const std::string& realm, 
                                          const std::string& nonce, const std::string& uri, 
                                          const std::string& response, const std::string& method) {
    // For digest authentication, we need to retrieve the user's password hash from LDAP
    // This is a simplified implementation - in practice, you'd need to retrieve the HA1 hash
    // from the LDAP directory if it stores it, or compute it from the plain text password
    
    std::lock_guard<std::mutex> lock(ldap_mutex_);
    
    LDAP* ld = connectToLDAP();
    if (!ld) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return false;
    }

    // Search for the user's DN
    std::string search_filter = "(uid=" + username + ")";
    LDAPMessage* result = nullptr;
    int ldap_result = ldap_search_s(
        ld,
        ldap_domain_.c_str(),
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "LDAP search failed: " << ldap_err2string(ldap_result) << std::endl;
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    int count = ldap_count_entries(ld, result);
    if (count != 1) {
        std::cerr << "User not found or multiple entries found" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        std::cerr << "Failed to get LDAP entry" << std::endl;
        ldap_msgfree(result);
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return false;
    }

    // In a real implementation, we would retrieve the HA1 hash from the LDAP directory
    // For now, we'll just return false as this requires specific LDAP schema setup
    // that stores digest authentication hashes
    
    ldap_msgfree(result);
    ldap_unbind_ext_s(ld, nullptr, nullptr);
    
    // Placeholder implementation - would need to retrieve HA1 hash from LDAP
    // and compare with the expected response
    return false;
}

UserInfo LDAPAuthenticator::getUserInfo(const std::string& username) {
    std::lock_guard<std::mutex> lock(ldap_mutex_);
    
    LDAP* ld = connectToLDAP();
    if (!ld) {
        std::cerr << "Failed to connect to LDAP server" << std::endl;
        return { "", "", {}, "", false };
    }

    UserInfo user_info = searchUser(ld, username);
    user_info.authenticated = true; // Assume user is already authenticated

    ldap_unbind_ext_s(ld, nullptr, nullptr);
    return user_info;
}

LDAP* LDAPAuthenticator::connectToLDAP() {
    LDAP* ld = nullptr;
    int version = LDAP_VERSION3;

    int rc = ldap_initialize(&ld, ldap_endpoint_.c_str());
    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to initialize LDAP connection: " << ldap_err2string(rc) << std::endl;
        return nullptr;
    }

    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Bind with service account
    struct berval cred;
    cred.bv_val = const_cast<char*>(bind_password_.c_str());
    cred.bv_len = bind_password_.length();

    rc = ldap_sasl_bind_s(
        ld,
        bind_dn_.c_str(),
        LDAP_SASL_SIMPLE,
        &cred,
        nullptr,
        nullptr,
        nullptr
    );

    if (rc != LDAP_SUCCESS) {
        std::cerr << "Failed to bind to LDAP server: " << ldap_err2string(rc) << std::endl;
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return nullptr;
    }

    return ld;
}

UserInfo LDAPAuthenticator::searchUser(LDAP* ld, const std::string& username) {
    std::string search_filter = "(uid=" + username + ")";
    LDAPMessage* result = nullptr;

    std::cout << "[DEBUG] Searching for user with base: " << user_base_ << " and filter: " << search_filter << std::endl;

    int ldap_result = ldap_search_s(
        ld,
        user_base_.c_str(),  // Use the configured user base
        LDAP_SCOPE_SUBTREE,
        search_filter.c_str(),
        nullptr,
        false,
        &result
    );

    if (ldap_result != LDAP_SUCCESS) {
        std::cerr << "[ERROR] User search failed: " << ldap_err2string(ldap_result) << std::endl;
        std::cerr << "[ERROR] Search base: " << user_base_ << ", Filter: " << search_filter << std::endl;
        return { "", "", {}, "", false };
    }

    int count = ldap_count_entries(ld, result);
    if (count != 1) {
        std::cerr << "[ERROR] User not found or multiple entries found (count: " << count << ")" << std::endl;
        ldap_msgfree(result);
        return { "", "", {}, "", false };
    }

    LDAPMessage* entry = ldap_first_entry(ld, result);
    if (!entry) {
        std::cerr << "[ERROR] Failed to get LDAP entry" << std::endl;
        ldap_msgfree(result);
        return { "", "", {}, "", false };
    }

    char* dn = ldap_get_dn(ld, entry);
    if (!dn) {
        std::cerr << "[ERROR] Failed to get DN" << std::endl;
        ldap_msgfree(result);
        return { "", "", {}, "", false };
    }

    UserInfo user_info;
    user_info.dn = std::string(dn);
    user_info.user_id = username;
    user_info.tenant = extractTenantFromUserDN(user_info.dn);

    std::cout << "[DEBUG] Found user: " << user_info.user_id << " with DN: " << user_info.dn << std::endl;
    std::cout << "[DEBUG] Extracting roles for user from groups..." << std::endl;

    // Extract roles from groups the user belongs to
    user_info.roles = extractRolesFromGroups(ld, user_info.dn);
    user_info.authenticated = false; // Will be set by caller

    ldap_memfree(dn);
    ldap_msgfree(result);

    std::cout << "[DEBUG] User roles extracted: " << user_info.roles.size() << " roles" << std::endl;
    for (size_t i = 0; i < user_info.roles.size(); ++i) {
        std::cout << "[DEBUG]   Role " << i+1 << ": " << user_info.roles[i] << std::endl;
    }

    return user_info;
}

std::string LDAPAuthenticator::extractTenantFromUserDN(const std::string& user_dn) {
    // Example: if user DN is "uid=john,ou=users,ou=tenant1,dc=example,dc=com"
    // we want to extract "tenant1" from the ou=tenant1 part
    
    size_t pos = user_dn.find(",ou=");
    if (pos != std::string::npos) {
        pos += 4; // Skip ",ou="
        size_t end_pos = user_dn.find(",", pos);
        if (end_pos != std::string::npos) {
            std::string org_unit = user_dn.substr(pos, end_pos - pos);
            
            // If the org unit contains a hyphen, only take the part before it
            size_t hyphen_pos = org_unit.find("-");
            if (hyphen_pos != std::string::npos) {
                return org_unit.substr(0, hyphen_pos);
            }
            
            return org_unit;
        }
    }
    
    // Default to empty tenant if not found
    return "";
}

std::vector<std::string> LDAPAuthenticator::extractRolesFromGroups(LDAP* ld, const std::string& user_dn) {
    std::vector<std::string> roles;

    // Search for groupOfNames entities the user belongs to
    // Using member attribute to find groups that contain this user
    std::string search_filter = "(&(objectClass=groupOfNames)(member=" + user_dn + "))";
    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Starting group search for user: " + std::string(user_dn));
    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Tenant base: '" + tenant_base_ + "'");
    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: LDAP domain: '" + ldap_domain_ + "'");

    // Based on your information, the groups are under ou=default,ou=tenants,dc=rationalboxes,dc=com
    // So let's make sure we search there specifically
    std::vector<std::string> possible_bases;

    // Add the specific location where groups are known to exist
    possible_bases.push_back("ou=default,ou=tenants," + ldap_domain_);

    // Add tenant-specific base if configured
    if (!tenant_base_.empty()) {
        possible_bases.push_back(tenant_base_);
        // Also try tenant base without specific tenant (for default tenant)
        if (tenant_base_.find("ou=default") == std::string::npos) {
            possible_bases.push_back("ou=default," + tenant_base_);
        }
    }

    // Add domain base
    possible_bases.push_back(ldap_domain_);

    // Add common organizational unit patterns
    possible_bases.push_back("ou=groups," + ldap_domain_);
    possible_bases.push_back("ou=Group," + ldap_domain_);
    possible_bases.push_back("ou=Roles," + ldap_domain_);
    possible_bases.push_back("ou=role," + ldap_domain_);
    possible_bases.push_back("ou=tenants," + ldap_domain_);
    possible_bases.push_back("ou=users," + ldap_domain_);

    LDAPMessage* result = nullptr;
    int ldap_result = LDAP_NO_SUCH_OBJECT; // Initialize to error state

    // Try each possible base until we find groups or exhaust options
    for (const std::string& search_base : possible_bases) {
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Trying search base: '" + search_base + "'");
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Using search filter: '" + search_filter + "'");
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: About to call ldap_search_s with base: " + search_base + ", filter: " + search_filter);

        ldap_result = ldap_search_s(
            ld,
            search_base.c_str(),
            LDAP_SCOPE_SUBTREE,
            search_filter.c_str(),
            nullptr,
            false,
            &result
        );

        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: ldap_search_s returned: " + std::to_string(ldap_result) + ", result pointer: " + (result ? "valid" : "NULL"));

        if (ldap_result == LDAP_SUCCESS) {
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Group search successful with base: " + search_base);

            // Count entries first to see how many were found
            int total_entries = ldap_count_entries(ld, result);
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Total entries found in this base: " + std::to_string(total_entries));

            // Process all entries in this base
            int group_count = 0;
            LDAPMessage* entry = ldap_first_entry(ld, result);
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: ldap_first_entry returned: " + std::string(entry ? "valid entry" : "NULL"));

            while (entry != nullptr) {
                group_count++;
                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Processing entry " + std::to_string(group_count) + " in base " + search_base);

                // Get the DN of this entry for debugging
                char* entry_dn = ldap_get_dn(ld, entry);
                if (entry_dn) {
                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Entry DN: " + std::string(entry_dn));
                    ldap_memfree(entry_dn);
                }

                BerElement* ber = nullptr;
                char* attr = ldap_first_attribute(ld, entry, &ber);
                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: First attribute: " + std::string(attr ? attr : "NULL"));

                // Look for various attributes that might contain the role name
                while (attr != nullptr) {
                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Processing attribute: " + std::string(attr));

                    // Check for common role/group name attributes
                    if (strcmp(attr, "cn") == 0 || strcmp(attr, "ou") == 0 || strcmp(attr, "name") == 0 || strcmp(attr, "gid") == 0) {
                        berval** vals = ldap_get_values_len(ld, entry, attr);
                        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: ldap_get_values_len returned: " + std::string(vals ? "valid values" : "NULL"));

                        if (vals != nullptr) {
                            int val_count = 0;
                            for (int i = 0; vals[i] != nullptr; i++) {
                                val_count++;
                                std::string role_name(vals[i]->bv_val);
                                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Value " + std::to_string(i) + " for attribute " + std::string(attr) + ": " + role_name);

                                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Found group with role name: " + role_name);

                                // Convert to lowercase for consistency and add to roles
                                std::transform(role_name.begin(), role_name.end(), role_name.begin(), ::tolower);
                                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Transformed role name to lowercase: " + role_name);

                                // Only add if not already in the list to avoid duplicates
                                bool found = false;
                                for (const std::string& existing_role : roles) {
                                    if (existing_role == role_name) {
                                        found = true;
                                        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Role " + role_name + " already exists in roles list");
                                        break;
                                    }
                                }
                                if (!found) {
                                    roles.push_back(role_name);
                                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Assigned role: " + role_name + " to user, total roles now: " + std::to_string(roles.size()));
                                } else {
                                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Skipped duplicate role: " + role_name);
                                }
                            }
                            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Processed " + std::to_string(val_count) + " values for attribute " + std::string(attr));
                            ldap_value_free_len(vals);
                        } else {
                            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: No values found for attribute: " + std::string(attr));
                        }
                    } else {
                        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Skipping attribute (not in target list): " + std::string(attr));
                    }

                    char* next_attr = ldap_next_attribute(ld, entry, ber);
                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Next attribute: " + std::string(next_attr ? next_attr : "NULL"));
                    ldap_memfree(attr);
                    attr = next_attr;
                }

                if (ber != nullptr) {
                    ber_free(ber, 0);
                }

                LDAPMessage* next_entry = ldap_next_entry(ld, entry);
                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Next entry: " + std::string(next_entry ? "valid" : "NULL"));
                entry = next_entry;
            }

            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Processed " + std::to_string(group_count) + " group(s) in base " + search_base);

            // Continue to other bases to collect all possible roles
            ldap_msgfree(result);
            result = nullptr; // Reset for next iteration
        } else {
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Group search failed with base " + search_base + ": " + std::string(ldap_err2string(ldap_result)));
            if (result) {
                ldap_msgfree(result);
                result = nullptr;
            }
        }
    }

    // If we didn't find any roles from any base, try a broader search
    if (roles.empty()) {
        // Try searching with a more generic filter that might catch different group types
        std::string alt_search_filter = "(member=" + user_dn + ")";
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Trying alternative search with filter: '" + alt_search_filter + "'");

        // Specifically try the known location again with the broader filter
        std::string known_location = "ou=default,ou=tenants," + ldap_domain_;
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Trying known location: " + known_location);

        ldap_result = ldap_search_s(
            ld,
            known_location.c_str(),
            LDAP_SCOPE_SUBTREE,
            alt_search_filter.c_str(),
            nullptr,
            false,
            &result
        );

        if (ldap_result == LDAP_SUCCESS) {
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Alternative search successful in known location: " + known_location);

            int total_entries = ldap_count_entries(ld, result);
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Total entries found in alternative search: " + std::to_string(total_entries));

            int group_count = 0;
            LDAPMessage* entry = ldap_first_entry(ld, result);
            while (entry != nullptr) {
                group_count++;

                // Get the group DN to extract potential role name
                char* group_dn = ldap_get_dn(ld, entry);
                if (group_dn) {
                    std::string group_dn_str(group_dn);
                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Processing group DN: " + group_dn_str);

                    // Try to extract role name from DN
                    size_t pos = group_dn_str.find("cn=");
                    if (pos != std::string::npos) {
                        pos += 3; // Skip "cn="
                        size_t end_pos = group_dn_str.find(",", pos);
                        if (end_pos == std::string::npos) {
                            end_pos = group_dn_str.length();
                        }
                        std::string role_name = group_dn_str.substr(pos, end_pos - pos);

                        std::transform(role_name.begin(), role_name.end(), role_name.begin(), ::tolower);

                        // Only add if not already in the list
                        bool found = false;
                        for (const std::string& existing_role : roles) {
                            if (existing_role == role_name) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            roles.push_back(role_name);
                            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Assigned role from DN: " + role_name + " to user");
                        }
                    }

                    ldap_memfree(group_dn);
                }

                // Also check attributes as before
                BerElement* ber = nullptr;
                char* attr = ldap_first_attribute(ld, entry, &ber);
                while (attr != nullptr) {
                    if (strcmp(attr, "cn") == 0 || strcmp(attr, "ou") == 0 || strcmp(attr, "name") == 0 || strcmp(attr, "gid") == 0) {
                        berval** vals = ldap_get_values_len(ld, entry, attr);
                        if (vals != nullptr) {
                            for (int i = 0; vals[i] != nullptr; i++) {
                                std::string role_name(vals[i]->bv_val);

                                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Found group with role name: " + role_name);

                                std::transform(role_name.begin(), role_name.end(), role_name.begin(), ::tolower);

                                bool found = false;
                                for (const std::string& existing_role : roles) {
                                    if (existing_role == role_name) {
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    roles.push_back(role_name);
                                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Assigned role: " + role_name + " to user");
                                }
                            }
                            ldap_value_free_len(vals);
                        }
                    }

                    char* next_attr = ldap_next_attribute(ld, entry, ber);
                    ldap_memfree(attr);
                    attr = next_attr;
                }

                if (ber != nullptr) {
                    ber_free(ber, 0);
                }

                entry = ldap_next_entry(ld, entry);
            }

            ldap_msgfree(result);
        } else {
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Alternative search failed in known location: " + known_location + ", error: " + std::string(ldap_err2string(ldap_result)));
        }
    }

    // If still no roles found, try a different approach - maybe the groups have different objectClass
    if (roles.empty()) {
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: No roles found with groupOfNames, trying groupMembership/uniqueMember approach");

        // Extract username from user_dn (assuming format like "uid=username,ou=...")
        std::string extracted_username = user_dn;
        size_t uid_start = user_dn.find("uid=");
        if (uid_start != std::string::npos) {
            uid_start += 4; // Skip "uid="
            size_t uid_end = user_dn.find(",", uid_start);
            if (uid_end != std::string::npos) {
                extracted_username = user_dn.substr(uid_start, uid_end - uid_start);
            } else {
                extracted_username = user_dn.substr(uid_start);
            }
        }

        // Try searching for groups using member/uniqueMember attribute instead of member
        std::string alt_search_filter2 = "(|(member=" + user_dn + ")(uniqueMember=" + user_dn + ")(memberUid=" + extracted_username + "))";
        std::string search_base2 = "ou=default,ou=tenants," + ldap_domain_;

        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Trying alternative filter: " + alt_search_filter2 + " in base: " + search_base2);

        ldap_result = ldap_search_s(
            ld,
            search_base2.c_str(),
            LDAP_SCOPE_SUBTREE,
            alt_search_filter2.c_str(),
            nullptr,
            false,
            &result
        );

        if (ldap_result == LDAP_SUCCESS) {
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Alternative search 2 successful");

            int total_entries = ldap_count_entries(ld, result);
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Total entries found in alternative search 2: " + std::to_string(total_entries));

            int group_count = 0;
            LDAPMessage* entry = ldap_first_entry(ld, result);
            while (entry != nullptr) {
                group_count++;

                // Get the group DN to extract potential role name
                char* group_dn = ldap_get_dn(ld, entry);
                if (group_dn) {
                    std::string group_dn_str(group_dn);
                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Processing group DN (alt2): " + group_dn_str);

                    // Try to extract role name from DN
                    size_t pos = group_dn_str.find("cn=");
                    if (pos != std::string::npos) {
                        pos += 3; // Skip "cn="
                        size_t end_pos = group_dn_str.find(",", pos);
                        if (end_pos == std::string::npos) {
                            end_pos = group_dn_str.length();
                        }
                        std::string role_name = group_dn_str.substr(pos, end_pos - pos);

                        std::transform(role_name.begin(), role_name.end(), role_name.begin(), ::tolower);

                        // Only add if not already in the list
                        bool found = false;
                        for (const std::string& existing_role : roles) {
                            if (existing_role == role_name) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            roles.push_back(role_name);
                            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Assigned role from DN (alt2): " + role_name + " to user");
                        }
                    }

                    ldap_memfree(group_dn);
                }

                // Also check attributes
                BerElement* ber = nullptr;
                char* attr = ldap_first_attribute(ld, entry, &ber);
                while (attr != nullptr) {
                    if (strcmp(attr, "cn") == 0 || strcmp(attr, "ou") == 0 || strcmp(attr, "name") == 0 || strcmp(attr, "gid") == 0) {
                        berval** vals = ldap_get_values_len(ld, entry, attr);
                        if (vals != nullptr) {
                            for (int i = 0; vals[i] != nullptr; i++) {
                                std::string role_name(vals[i]->bv_val);

                                webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Found group with role name (alt2): " + role_name);

                                std::transform(role_name.begin(), role_name.end(), role_name.begin(), ::tolower);

                                bool found = false;
                                for (const std::string& existing_role : roles) {
                                    if (existing_role == role_name) {
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    roles.push_back(role_name);
                                    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Assigned role (alt2): " + role_name + " to user");
                                }
                            }
                            ldap_value_free_len(vals);
                        }
                    }

                    char* next_attr = ldap_next_attribute(ld, entry, ber);
                    ldap_memfree(attr);
                    attr = next_attr;
                }

                if (ber != nullptr) {
                    ber_free(ber, 0);
                }

                entry = ldap_next_entry(ld, entry);
            }

            ldap_msgfree(result);
        } else {
            webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Alternative search 2 also failed: " + std::string(ldap_err2string(ldap_result)));
        }
    }

    webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: Total processed groups for user " + user_dn + ", found " + std::to_string(roles.size()) + " roles");
    for (size_t i = 0; i < roles.size(); ++i) {
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups:   Role " + std::to_string(i+1) + ": " + roles[i]);
    }

    // If no specific roles found, assign default 'users' role
    if (roles.empty()) {
        roles.push_back("users");
    }

    // Map the tenant "administrators" group to the server's privileged role.
    // The FileEngine core grants admin (root-level create, ACL/role admin,
    // permission bypass) to the `system_admin` role, so a member of a tenant's
    // administrators group is given that role in the gRPC auth context.
    if (std::find(roles.begin(), roles.end(), "administrators") != roles.end() &&
        std::find(roles.begin(), roles.end(), "system_admin") == roles.end()) {
        roles.push_back("system_admin");
        webdav::debugLog("LDAPAuthenticator::extractRolesFromGroups: mapped 'administrators' group -> 'system_admin' role");
    }

    return roles;
}

} // namespace webdav