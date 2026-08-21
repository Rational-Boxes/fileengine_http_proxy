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

#include "utils.h"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timestamp.h>
#include <Poco/MD5Engine.h>
#include <Poco/DigestEngine.h>

namespace webdav {

namespace {
// MD5 of the input rendered as LOWERCASE hex. RFC 2617 requires the HA1/HA2 and
// the response digest to be lowercase hex — uppercase (Poco NumberFormatter's
// default) would never match a standard client's computation, so Digest auth
// would always fail.
std::string md5HexLower(const std::string& input) {
    Poco::MD5Engine md5;
    md5.update(input);
    std::string hex = Poco::DigestEngine::digestToHex(md5.digest());
    std::transform(hex.begin(), hex.end(), hex.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return hex;
}
}  // namespace

std::vector<std::string> splitString(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(str);
    std::string token;
    
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    
    return tokens;
}

std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        return "";
    }
    
    size_t end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}

std::string urlDecode(const std::string& encoded) {
    std::string decoded;
    for (size_t i = 0; i < encoded.length(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.length()) {
            std::string hex = encoded.substr(i + 1, 2);
            char ch = static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
            decoded += ch;
            i += 2; // Skip the next two characters
        } else if (encoded[i] == '+') {
            decoded += ' ';
        } else {
            decoded += encoded[i];
        }
    }
    return decoded;
}

std::string urlEncode(const std::string& decoded) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (char c : decoded) {
        // Keep alphanumeric and other accepted characters intact
        if (std::isalnum(static_cast<unsigned char>(c)) ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << std::uppercase;
            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
            escaped << std::nouppercase;
        }
    }

    return escaped.str();
}

std::string generateDigestHash(const std::string& username, const std::string& realm, const std::string& password) {
    return md5HexLower(username + ":" + realm + ":" + password);
}

std::string calculateHA1(const std::string& username, const std::string& realm, const std::string& password) {
    return generateDigestHash(username, realm, password);
}

std::string calculateHA2(const std::string& method, const std::string& uri) {
    return md5HexLower(method + ":" + uri);
}

std::string calculateDigestResponse(const std::string& ha1, const std::string& nonce,
                                  const std::string& nc, const std::string& cnonce,
                                  const std::string& qop, const std::string& ha2) {
    return md5HexLower(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2);
}

namespace {
// The sign-in label, configurable because a deployment may not be able to
// reserve "login" on its domain — on a shared host like ngrok.io it is very
// likely already taken. Set once at startup; read on every host resolution.
std::string g_login_label = "login";

std::string lowered(const std::string& in) {
    std::string out = in;
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}
}  // namespace

bool setLoginLabel(const std::string& label, std::string* error) {
    // Empty restores the default rather than disabling the reservation: an
    // empty label would make every hostname's leading label compare equal to
    // it and reserve the entire namespace.
    if (label.empty()) {
        g_login_label = "login";
        return true;
    }

    // Validated rather than trusted, because the failure is SILENT and it fails
    // OPEN. isReservedTenantLabel compares a host's leading label against this
    // string; a label that no hostname can ever equal reserves nothing, so the
    // sign-in origin quietly becomes an ordinary tenant and signed-out users
    // are bounced to a host that does not resolve. Neither symptom names the
    // cause. A trailing inline comment in a .env file is enough to cause it —
    // values there run to end of line — which is how this was found.
    const std::string l = lowered(label);

    if (l.size() > 63) {
        if (error) *error = "longer than the 63-character DNS label limit";
        return false;
    }
    // No hyphen, and this is stricter than DNS on purpose. extractTenantFromHostname
    // splits the leading label on '-' and keeps the first segment — the
    // "<tenant>-<interface>" convention that makes "acme-drive" resolve to tenant
    // "acme". So a hyphenated sign-in label such as "acme-login" would resolve to
    // the TENANT "acme" and double as a tenant host. It is reservable as a whole
    // label only when hyphen-free.
    if (l.find('-') != std::string::npos) {
        if (error) {
            *error = "contains '-', which is parsed as the <tenant>-<interface> "
                     "separator and would resolve to a tenant instead of being reserved";
        }
        return false;
    }
    if (l.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789") != std::string::npos) {
        if (error) {
            *error = "is not a bare DNS label (letters and digits only) — note that a "
                     ".env value runs to end of line, so an inline '# comment' "
                     "becomes part of it";
        }
        return false;
    }
    // An all-numeric leading label is how extractTenantFromHostname recognises an
    // IPv4 literal. Reserving one would overload that heuristic.
    if (l.find_first_not_of("0123456789") == std::string::npos) {
        if (error) *error = "is all digits, which collides with the IPv4-literal check";
        return false;
    }

    g_login_label = l;
    return true;
}

std::string loginLabel() { return g_login_label; }

bool isReservedTenantLabel(const std::string& label) {
    // Lower-cased compare: DNS labels are case-insensitive, and an X-Tenant
    // header is attacker-controlled — "Login" must not slip past a check that
    // only knows "login".
    const std::string l = lowered(label);
    return l == "www" || l == g_login_label;
}

std::string extractTenantFromHostname(const std::string& hostname) {
    // The tenant is the first '-'-delimited segment of the leading DNS label.
    // Any remainder is an interface suffix (e.g. "<tenant>-drive" for the
    // WebDAV host), so the SPA and WebDAV hosts resolve to the same tenant:
    //   acme.example.com          -> "acme"
    //   acme-drive.example.com    -> "acme"
    //   acme-staging.example.com  -> "acme"
    //   www.example.com           -> ""  (reserved; default tenant)
    //   example.com / localhost   -> ""  (no subdomain; default tenant)
    //   127.0.0.1                 -> ""  (IP literal; default tenant)

    // Drop any ":port" suffix so the port can't be mistaken for part of a label.
    std::string host = hostname.substr(0, hostname.find(':'));

    size_t first_dot = host.find('.');
    if (first_dot == std::string::npos) {
        return "";  // bare host (e.g. "localhost") -> default tenant
    }

    std::string subdomain = host.substr(0, first_dot);

    // Always split the leading label on '-' and keep the first segment: the
    // label follows the "<tenant>-<interface>" convention (e.g. "acme-drive"),
    // so the tenant is everything before the first hyphen.
    size_t dash = subdomain.find('-');
    if (dash != std::string::npos) {
        subdomain = subdomain.substr(0, dash);
    }

    // Reserved / non-tenant first labels.
    //
    // "login" is the shared sign-in origin. Reserving it is what makes the whole
    // arrangement work: every OAuth flow returns to that ONE host, so
    // OAUTH_RETURN_ALLOWLIST holds a single entry no matter how many tenants
    // exist. It must therefore never resolve to a tenant of its own — a tenant
    // literally named "login" would shadow the sign-in page for everybody.
    if (subdomain.empty() || isReservedTenantLabel(subdomain)) {
        return "";
    }

    // An all-numeric first label means the host is an IPv4 literal, not a
    // tenant subdomain.
    if (subdomain.find_first_not_of("0123456789") == std::string::npos) {
        return "";
    }

    return subdomain;  // tenant = first hyphen-delimited segment of the label
}

std::string resolveTenant(const std::string& x_tenant_header, const std::string& host) {
    // A reserved name is refused here too, not only in the hostname path:
    // X-Tenant is client-supplied, so guarding only the host would leave the
    // reservation bypassable by sending the header directly. A reserved header
    // is IGNORED rather than honoured, falling through to normal host
    // resolution — the same as if it had not been sent.
    if (!x_tenant_header.empty() && !isReservedTenantLabel(x_tenant_header))
        return x_tenant_header;
    std::string t = extractTenantFromHostname(host);
    return t.empty() ? "default" : t;
}

bool returnUrlAllowed(const std::string& allowlist, const std::string& url) {
    for (const auto& p : splitString(allowlist, ',')) {
        std::string pre = trim(p);
        if (pre.empty()) continue;
        if (url.rfind(pre, 0) != 0) continue;     // url must start with the prefix
        // Require the match to end at an origin/path boundary so a prefix like
        // "https://app.example.com" cannot match "https://app.example.com.evil.com"
        // or a different port. An exact match, a prefix that already ends in '/',
        // or a following '/'?'#' are all boundaries.
        if (url.size() == pre.size()) return true;       // exact
        if (pre.back() == '/') return true;              // prefix ends at a boundary
        const char next = url[pre.size()];
        if (next == '/' || next == '?' || next == '#') return true;
    }
    return false;
}

std::string getEnvOrDefault(const std::string& env_var, const std::string& default_val) {
    std::string val = Poco::Environment::get(env_var, "");
    if (val.empty()) {
        return default_val;
    }
    return val;
}

std::string getErrorMessage(int error_code) {
    // This is a simplified implementation
    // In a real implementation, you would map error codes to meaningful messages
    switch (error_code) {
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 412: return "Precondition Failed";
        case 500: return "Internal Server Error";
        default: return "Unknown Error";
    }
}

void logMessage(const std::string& level, const std::string& message) {
    std::string timestamp = Poco::DateTimeFormatter::format(
        Poco::Timestamp(),
        "%Y-%m-%d %H:%M:%S.%i"
    );

    std::string log_line = "[" + timestamp + "] [" + level + "] " + message;

    // Always write to standard streams for now
    if (level == "ERROR" || level == "FATAL") {
        std::cerr << log_line << std::endl;
    } else {
        std::cout << log_line << std::endl;
    }

    // In a real implementation, you might also write to a file based on configuration
}

bool shouldLogToConsole() {
    std::string log_to_console = getEnvOrDefault("LOG_WRITE_TO_CONSOLE", "true");
    // Convert to lowercase for comparison
    std::transform(log_to_console.begin(), log_to_console.end(), log_to_console.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return log_to_console == "true" || log_to_console == "1" || log_to_console == "yes";
}

bool isLogLevelAtLeast(const std::string& level) {
    std::string current_level = getEnvOrDefault("LOG_LEVEL", "info");
    std::transform(current_level.begin(), current_level.end(), current_level.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    // Define log level priorities
    if (current_level == "debug") {
        return true; // Debug level logs everything
    } else if (current_level == "info") {
        return level != "debug";
    } else if (current_level == "warn") {
        return level != "debug" && level != "info";
    } else if (current_level == "error") {
        return level == "error" || level == "fatal";
    } else if (current_level == "fatal") {
        return level == "fatal";
    }

    // Default to info level if unrecognized
    return level != "debug";
}

void debugLog(const std::string& message) {
    if (isLogLevelAtLeast("debug")) {
        logMessage("DEBUG", message);
    }
}

void infoLog(const std::string& message) {
    if (isLogLevelAtLeast("info")) {
        logMessage("INFO", message);
    }
}

void warnLog(const std::string& message) {
    if (isLogLevelAtLeast("warn")) {
        logMessage("WARN", message);
    }
}

void errorLog(const std::string& message) {
    if (isLogLevelAtLeast("error")) {
        logMessage("ERROR", message);
    }
}

} // namespace webdav