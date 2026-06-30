#ifndef CIRCUIT_BREAKER_H
#define CIRCUIT_BREAKER_H

#include <chrono>
#include <functional>

namespace webdav {

// Lazy circuit-breaker for primary/replica failover (REPLICATION_FAILOVER.md).
// A failed primary connection trips it for a cooldown, during which requests use
// the replica; after the cooldown the next request re-probes the primary and
// resumes on success. The clock is injectable for deterministic tests.
//
// Not internally synchronized — callers serialize access (the LDAP authenticator
// touches it only under its existing mutex).
class CircuitBreaker {
public:
    explicit CircuitBreaker(double cooldown_s = 30.0) : cooldown_s_(cooldown_s) {}

    // True when the primary should be attempted (never tripped, or the cooldown
    // has elapsed so it is time to re-probe).
    bool shouldTryPrimary() const { return now() >= down_until_; }

    // True while inside the cooldown window (primary considered down).
    bool isDegraded() const { return now() < down_until_; }

    // Mark the primary down for cooldown_s from now.
    void trip() { down_until_ = now() + cooldown_s_; }

    // Mark the primary healthy again (a probe/op succeeded).
    void reset() { down_until_ = 0.0; }

    // Inject a clock (seconds, monotonic) for tests.
    void setClock(std::function<double()> clock) { clock_ = std::move(clock); }

private:
    double now() const {
        if (clock_) return clock_();
        return std::chrono::duration<double>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    double cooldown_s_;
    double down_until_ = 0.0;
    std::function<double()> clock_;
};

}  // namespace webdav

#endif  // CIRCUIT_BREAKER_H
