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

#ifndef HTTP_BRIDGE_OAUTH_STATE_STORE_H
#define HTTP_BRIDGE_OAUTH_STATE_STORE_H

#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <string>

namespace httpbridge {

// In-flight OAuth2 authorization request, created at /authorize and consumed at
// /callback. Carries everything the callback must NOT re-derive from the
// (attacker-influenced) callback request: the PKCE verifier, the host-resolved
// tenant, and the validated SPA return URL.
struct OAuthState {
    std::string provider;       // which provider this state was minted for
    std::string code_verifier;  // PKCE verifier (never leaves the server)
    std::string nonce;          // OIDC nonce, verified against the id_token
    std::string tenant;         // resolved at authorize-time from the host
    std::string return_to;      // validated SPA callback URL
    std::chrono::steady_clock::time_point expiry;
};

// Short-lived, one-shot store for OAuth `state` values. Distinct from TokenStore
// on purpose: `consume()` deletes on first use (CSRF/replay defense), the payload
// is the pending request rather than a resolved identity, and the TTL is minutes
// not hours. Thread-safe; single-instance (state must be consumed by the same
// process that created it — see TokenStore's note on horizontal scaling).
class OAuthStateStore {
public:
    explicit OAuthStateStore(int ttl_seconds = 300) : ttl_(ttl_seconds) {}

    // Stores `st` (expiry filled in here) and returns a fresh random state key.
    std::string create(OAuthState st) {
        std::string state = randomToken();
        st.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(ttl_);
        std::lock_guard<std::mutex> lock(mutex_);
        sweepLocked();
        states_[state] = std::move(st);
        return state;
    }

    // Returns true and fills `out` iff the state exists and is unexpired; in all
    // cases the entry is removed, so a replayed state fails the second time.
    bool consume(const std::string& state, OAuthState& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = states_.find(state);
        if (it == states_.end()) return false;
        bool fresh = std::chrono::steady_clock::now() < it->second.expiry;
        if (fresh) out = it->second;
        states_.erase(it);
        return fresh;
    }

    int ttl() const { return ttl_; }

private:
    // Drop expired entries so abandoned flows don't accumulate.
    void sweepLocked() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = states_.begin(); it != states_.end();) {
            if (now >= it->second.expiry) it = states_.erase(it);
            else ++it;
        }
    }

    static std::string randomToken() {
        unsigned char buf[32] = {0};
        std::ifstream f("/dev/urandom", std::ios::binary);
        f.read(reinterpret_cast<char*>(buf), sizeof(buf));
        static const char* hex = "0123456789abcdef";
        std::string s;
        s.reserve(sizeof(buf) * 2);
        for (unsigned char b : buf) {
            s += hex[b >> 4];
            s += hex[b & 0x0f];
        }
        return s;
    }

    int ttl_;
    std::map<std::string, OAuthState> states_;
    std::mutex mutex_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_OAUTH_STATE_STORE_H
