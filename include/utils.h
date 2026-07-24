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

// Resolve the tenant for a request: an explicit X-Tenant header wins; otherwise
// the host's leading subdomain label; otherwise "default". Pure form of the
// bridge's per-request tenant precedence (no Poco request needed).
std::string resolveTenant(const std::string& x_tenant_header, const std::string& host);

// True if `url` matches any non-empty, comma-separated prefix in `allowlist`
// (each prefix whitespace-trimmed), where the match must end at an origin/path
// boundary: an exact match, a prefix ending in '/', or a following '/' '?' '#'.
// This prevents "https://app.example.com" from matching a confusable host such
// as "https://app.example.com.evil.com". Used to gate OAuth return URLs.
bool returnUrlAllowed(const std::string& allowlist, const std::string& url);

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