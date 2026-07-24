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

#ifndef HTTP_BRIDGE_CLIENT_IP_H
#define HTTP_BRIDGE_CLIENT_IP_H

// Real-client-IP resolution behind a reverse proxy (security hardening).
//
// The naive "trust the first X-Forwarded-For hop" is spoofable: any client can
// send `X-Forwarded-For: 1.2.3.4` and be believed. Since the client IP gates
// security-relevant behavior (the MFA challenge-token IP binding, audit
// source_addr, and the future WebDAV IP binding), production deployments MUST
// resolve it against a set of trusted proxies.
//
// Configure FILEENGINE_TRUSTED_PROXIES (comma-separated IPs / CIDRs of the
// reverse proxy/load-balancer, e.g. `127.0.0.1,10.0.0.0/8`). When set, XFF is
// honored ONLY if the immediate peer is a trusted proxy, and the resolved client
// is the right-most XFF hop that is NOT itself a trusted proxy — so injected
// (spoofed) left-most entries are ignored. When UNSET (development), the first
// XFF hop is trusted for convenience — do not run that way in production.

#include <sstream>
#include <string>
#include <vector>

#include <Poco/Net/IPAddress.h>

namespace httpbridge {

// True if `ip` is within the CIDR (`a.b.c.d/n`) or equals the plain IP `cidr`.
// Malformed inputs are treated as no-match (fail-closed).
inline bool ipInCidr(const std::string& ip, const std::string& cidr) {
    try {
        Poco::Net::IPAddress addr(ip);
        const auto slash = cidr.find('/');
        if (slash == std::string::npos) {
            return addr == Poco::Net::IPAddress(cidr);
        }
        Poco::Net::IPAddress net(cidr.substr(0, slash));
        const unsigned prefix = static_cast<unsigned>(std::stoul(cidr.substr(slash + 1)));
        if (addr.family() != net.family()) return false;
        Poco::Net::IPAddress mask(prefix, net.family());
        return (addr & mask) == (net & mask);
    } catch (...) {
        return false;
    }
}

inline bool isTrustedProxy(const std::string& ip, const std::vector<std::string>& trusted) {
    for (const auto& c : trusted) {
        if (ipInCidr(ip, c)) return true;
    }
    return false;
}

// Resolve the real client IP.
//   peer    = the immediate socket peer (getpeername).
//   xff     = the raw X-Forwarded-For header value ("client, proxy1, proxy2").
//   trusted = configured trusted-proxy CIDRs (empty => development mode).
inline std::string resolveClientIp(const std::string& peer, const std::string& xff,
                                   const std::vector<std::string>& trusted) {
    auto trim = [](const std::string& s) -> std::string {
        const size_t a = s.find_first_not_of(" \t");
        if (a == std::string::npos) return std::string();
        const size_t b = s.find_last_not_of(" \t");
        return s.substr(a, b - a + 1);
    };

    // Development / no trusted proxies configured: trust the first XFF hop.
    if (trusted.empty()) {
        if (!xff.empty()) {
            const auto c = xff.find(',');
            return trim(c == std::string::npos ? xff : xff.substr(0, c));
        }
        return peer;
    }

    // Hardened: XFF is only credible when the request actually arrived via a
    // trusted proxy. A direct (non-proxy) peer cannot spoof via XFF.
    if (!isTrustedProxy(peer, trusted)) return peer;
    if (xff.empty()) return peer;

    // Walk right-to-left; the first hop that is NOT a trusted proxy is the real
    // client (everything to its left is attacker-controllable and ignored).
    std::vector<std::string> hops;
    std::stringstream ss(xff);
    std::string h;
    while (std::getline(ss, h, ',')) hops.push_back(trim(h));
    for (auto it = hops.rbegin(); it != hops.rend(); ++it) {
        if (it->empty()) continue;
        if (!isTrustedProxy(*it, trusted)) return *it;
    }
    return peer;  // every hop was a trusted proxy (unusual) — fall back to the peer
}

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_CLIENT_IP_H
