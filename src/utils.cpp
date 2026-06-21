#include "utils.h"
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <Poco/DateTimeFormatter.h>
#include <Poco/Timestamp.h>

namespace webdav {

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
    std::string a1 = username + ":" + realm + ":" + password;
    
    Poco::MD5Engine md5;
    md5.update(a1);
    Poco::DigestEngine::Digest digest = md5.digest();
    
    std::string result;
    for (auto byte : digest) {
        result += Poco::NumberFormatter::formatHex(byte, 2);
    }
    
    return result;
}

std::string calculateHA1(const std::string& username, const std::string& realm, const std::string& password) {
    return generateDigestHash(username, realm, password);
}

std::string calculateHA2(const std::string& method, const std::string& uri) {
    std::string a2 = method + ":" + uri;
    
    Poco::MD5Engine md5;
    md5.update(a2);
    Poco::DigestEngine::Digest digest = md5.digest();
    
    std::string result;
    for (auto byte : digest) {
        result += Poco::NumberFormatter::formatHex(byte, 2);
    }
    
    return result;
}

std::string calculateDigestResponse(const std::string& ha1, const std::string& nonce, 
                                  const std::string& nc, const std::string& cnonce, 
                                  const std::string& qop, const std::string& ha2) {
    std::string a3 = ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2;
    
    Poco::MD5Engine md5;
    md5.update(a3);
    Poco::DigestEngine::Digest digest = md5.digest();
    
    std::string result;
    for (auto byte : digest) {
        result += Poco::NumberFormatter::formatHex(byte, 2);
    }
    
    return result;
}

std::string extractTenantFromHostname(const std::string& hostname) {
    // The first DNS label of the host is the tenant name. Hyphens are valid in
    // labels and tenant names, so the WHOLE label is used (no truncation):
    //   acme.example.com          -> "acme"
    //   acme-staging.example.com  -> "acme-staging"
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

    // Reserved / non-tenant first labels.
    if (subdomain.empty() || subdomain == "www") {
        return "";
    }

    // An all-numeric first label means the host is an IPv4 literal, not a
    // tenant subdomain.
    if (subdomain.find_first_not_of("0123456789") == std::string::npos) {
        return "";
    }

    return subdomain;  // full label; hyphens preserved
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