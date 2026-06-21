#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <Poco/DigestStream.h>
#include <Poco/MD5Engine.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Environment.h>
#include <Poco/Util/Application.h>
#include <Poco/NumberFormatter.h>

namespace webdav {

// Utility functions for string manipulation
std::vector<std::string> splitString(const std::string& str, char delimiter);
std::string trim(const std::string& str);
std::string urlDecode(const std::string& encoded);
std::string urlEncode(const std::string& decoded);

// Utility functions for authentication
std::string generateDigestHash(const std::string& username, const std::string& realm, const std::string& password);
std::string calculateHA1(const std::string& username, const std::string& realm, const std::string& password);
std::string calculateHA2(const std::string& method, const std::string& uri);
std::string calculateDigestResponse(const std::string& ha1, const std::string& nonce, 
                                  const std::string& nc, const std::string& cnonce, 
                                  const std::string& qop, const std::string& ha2);

// Utility functions for tenant extraction
std::string extractTenantFromHostname(const std::string& hostname);

// Utility functions for environment/config handling
std::string getEnvOrDefault(const std::string& env_var, const std::string& default_val);

// Utility functions for error handling
std::string getErrorMessage(int error_code);

// Logging utilities
void logMessage(const std::string& level, const std::string& message);
bool shouldLogToConsole();
bool isLogLevelAtLeast(const std::string& level);
void debugLog(const std::string& message);
void infoLog(const std::string& message);
void warnLog(const std::string& message);
void errorLog(const std::string& message);

} // namespace webdav

#endif // UTILS_H