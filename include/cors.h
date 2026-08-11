#pragma once
// Multi-origin CORS allow-list matching. Header-only and dependency-free so it can
// be unit-tested in isolation. The bridge NEVER reflects an arbitrary Origin and
// NEVER emits "*": a request's Origin is echoed back only when it exactly matches a
// deployment-configured entry (HTTP_CORS_ORIGINS, plus the legacy HTTP_CORS_ORIGIN).
#include <string>
#include <vector>

namespace webdav {

// Returns the origin to place in Access-Control-Allow-Origin when `origin` exactly
// matches one of the allow-listed origins; otherwise returns "" (no CORS header).
// Matching is exact (scheme + host + port) — no wildcards, no prefix matching — so a
// look-alike origin (e.g. "https://host.example.com.evil.test") can never match.
inline std::string matchCorsOrigin(const std::vector<std::string>& allowed,
                                   const std::string& origin) {
    if (origin.empty()) return "";
    for (const auto& a : allowed) {
        if (!a.empty() && a == origin) return origin;
    }
    return "";
}

}  // namespace webdav
