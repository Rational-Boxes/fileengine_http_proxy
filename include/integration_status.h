#pragma once
// Non-secret status document for the configured commercial integration (§14.2), for a
// read-only admin panel (GET /v1/integrations). Header-only + dependency-light so it is
// unit-testable. NEVER emits key material — only whether a key is present. The issuer,
// audience, and IP allow-list are deployment config (not secrets) and are echoed so an
// admin can confirm what is wired without shell access.
#include <string>
#include <vector>

namespace httpbridge {

// Minimal JSON string escape (quote, backslash, control chars) — defensive; these
// values are deployment-config-controlled, not arbitrary user input.
inline std::string jsonEscapeStatus(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) { static const char* hex = "0123456789abcdef";
                    o += "\\u00"; o += hex[(c >> 4) & 0xF]; o += hex[c & 0xF]; }
                else o += static_cast<char>(c);
        }
    }
    return o;
}

// One integration's non-secret status object. `enabled` is true only when both an
// issuer and a public key are configured (the exchange route is live).
inline std::string integrationStatusJson(const std::string& issuer,
                                         const std::string& audience,
                                         bool key_present,
                                         const std::vector<std::string>& allowed_ips) {
    const bool enabled = !issuer.empty() && key_present;
    std::string ips;
    for (std::size_t i = 0; i < allowed_ips.size(); ++i) {
        if (i) ips += ",";
        ips += "\"" + jsonEscapeStatus(allowed_ips[i]) + "\"";
    }
    std::string out = "{";
    out += "\"enabled\":"; out += enabled ? "true" : "false";
    out += ",\"issuer\":\"" + jsonEscapeStatus(issuer) + "\"";
    out += ",\"audience\":\"" + jsonEscapeStatus(audience) + "\"";
    out += ",\"key_present\":"; out += key_present ? "true" : "false";
    out += ",\"allowed_ips\":[" + ips + "]";
    out += ",\"ip_allowlist_enforced\":"; out += allowed_ips.empty() ? "false" : "true";
    out += "}";
    return out;
}

}  // namespace httpbridge
