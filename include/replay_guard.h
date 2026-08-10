#pragma once
// Small in-memory single-use guard for assertion `jti` values (replay rejection for
// the token-exchange endpoint). An assertion is accepted at most once until its own
// expiry; a replayed jti within its lifetime is refused. Header-only + dependency-free
// so it is unit-testable; thread-safe for the multi-threaded HTTP server.
//
// This is per-process (a bespoke single-bridge deployment). A multi-bridge deployment
// would back this with a shared store (e.g. Redis) behind the same seen()/interface.
#include <mutex>
#include <string>
#include <unordered_map>

namespace httpbridge {

class ReplayGuard {
public:
    // Record `jti` as used until `expires_at` (unix epoch). Returns true if this jti
    // was NOT seen before (i.e. the caller may proceed); false if it is a replay.
    // `now` is unix epoch seconds; an already-expired record is treated as free.
    // Empty jti is always accepted and never stored (nothing to replay-key on).
    bool accept(const std::string& jti, long expires_at, long now) {
        if (jti.empty()) return true;
        std::lock_guard<std::mutex> g(mu_);
        purgeLocked(now);
        auto it = seen_.find(jti);
        if (it != seen_.end() && it->second > now) return false;  // live record => replay
        seen_[jti] = expires_at;
        return true;
    }

    std::size_t size() const {
        std::lock_guard<std::mutex> g(mu_);
        return seen_.size();
    }

private:
    // Drop expired records so the map cannot grow without bound. O(n) but only over
    // entries whose assertions have already expired; the live set stays small.
    void purgeLocked(long now) {
        for (auto it = seen_.begin(); it != seen_.end();) {
            if (it->second <= now) it = seen_.erase(it);
            else ++it;
        }
    }

    mutable std::mutex mu_;
    std::unordered_map<std::string, long> seen_;  // jti -> expiry epoch
};

}  // namespace httpbridge
