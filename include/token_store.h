#ifndef HTTP_BRIDGE_TOKEN_STORE_H
#define HTTP_BRIDGE_TOKEN_STORE_H

#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace httpbridge {

// A resolved, cached identity bound to a bearer token.
struct Session {
    std::string user;
    std::string tenant;
    std::vector<std::string> roles;
    std::chrono::steady_clock::time_point expiry;
};

// In-process bearer-token store with a fixed TTL. Lets chatty clients
// authenticate once (one LDAP bind) and reuse a token, skipping the directory
// round-trip on every request. Thread-safe.
//
// Single-instance only; for horizontal scaling this would move to a shared
// store (e.g. Redis) — see DEVELOPMENT_PLAN.md.
class TokenStore {
public:
    explicit TokenStore(int ttl_seconds) : ttl_(ttl_seconds) {}

    std::string issue(const std::string& user, const std::string& tenant,
                      const std::vector<std::string>& roles) {
        Session s{user, tenant, roles,
                  std::chrono::steady_clock::now() + std::chrono::seconds(ttl_)};
        std::string token = randomToken();
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_[token] = std::move(s);
        return token;
    }

    // Returns true and fills `out` if the token exists and is unexpired.
    bool lookup(const std::string& token, Session& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(token);
        if (it == sessions_.end()) return false;
        if (std::chrono::steady_clock::now() >= it->second.expiry) {
            sessions_.erase(it);
            return false;
        }
        out = it->second;
        return true;
    }

    void revoke(const std::string& token) {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.erase(token);
    }

    int ttl() const { return ttl_; }

private:
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
    std::map<std::string, Session> sessions_;
    std::mutex mutex_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_TOKEN_STORE_H
