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

#ifndef HTTP_BRIDGE_TOKEN_DENYLIST_H
#define HTTP_BRIDGE_TOKEN_DENYLIST_H

#include <ctime>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

struct redisContext;  // forward-declared; hiredis is pulled in only by the .cpp

namespace httpbridge {

// Verdict for one `jti`.
enum class Revocation {
    Allowed,  // definitely not revoked
    Revoked,  // definitely revoked
    Unknown,  // could not be established — the store could not be reached
};

/**
 * Revoked-token denylist, keyed by `jti`, shared through Redis.
 *
 * WHY IT HAS TO EXIST. Session tokens are stateless HS256 JWTs: the bridge
 * verifies a signature and an `exp` and asks nothing else, so a token stays
 * good for its whole TTL no matter what happens in between. `DELETE
 * /v1/auth/token` therefore did not end a session. It dropped the WebDAV
 * session-presence entry and wrote an audit record, and the token itself went
 * on working — in another tab, in a script, in anything holding a copy —
 * until it expired on its own. Signing out looked like it worked and did not.
 *
 * WHY REDIS. The denylist is only worth having if EVERY door consults the same
 * one. Bridge instances are horizontally scalable and the deployment already
 * runs Redis for the audit stream and the §14 session registry, so it is the
 * store that is genuinely shared rather than per-process — an in-memory set
 * would revoke the token on the one instance that happened to serve the logout
 * and nowhere else, which is worse than not revoking at all because it looks
 * like it worked.
 *
 * SELF-EXPIRING. Each entry is written with `EX` set to the token's own
 * remaining lifetime, so the denylist holds only tokens that would otherwise
 * still be honoured, and never needs sweeping. Its steady-state size is
 * "sign-outs in the last TOKEN_TTL_SECONDS", which is small.
 *
 * FAIL-CLOSED BY DEFAULT, and this is the whole point. A lookup that cannot
 * reach Redis yields `Unknown`, and an `Unknown` is refused. Honouring a token
 * we cannot vouch for would restore precisely the behaviour this class exists
 * to remove, and it would do it silently — the same shape as the audit sink
 * that failed open and quietly turned every write-ahead into a no-op.
 * `AUTH_REVOCATION_FAIL_OPEN=true` inverts it for a deployment that would
 * rather serve requests than enforce sign-out, but nothing chooses that on a
 * deployment's behalf.
 *
 * THE CACHE IS WHAT MAKES FAIL-CLOSED AFFORDABLE. Consulting Redis on every
 * authenticated request would put the whole request load through one
 * mutex-guarded connection — today only login and logout go that way — and
 * would make a momentary Redis stall a total outage. So a verdict is trusted
 * for `cache_ttl` seconds. That is the revocation LATENCY: a signed-out token
 * keeps working for at most that long, against the 900-3600s it used to get.
 * Set it to 0 to check every time.
 */
class TokenDenylist {
public:
    struct Options {
        bool enabled = true;
        std::string host = "localhost";
        int port = 6379;
        std::string password;
        int db = 0;
        std::string key_prefix = "auth:revoked:";
        // Seconds a verdict is trusted before Redis is asked again. This is the
        // worst-case delay between signing out and the token stopping.
        int cache_ttl = 5;
        // Honour a token whose status cannot be established. Off, deliberately.
        bool fail_open = false;
        // Bound on the verdict cache, so a flood of distinct jtis cannot grow it
        // without limit. Entries are short-lived; this is a backstop, not a policy.
        std::size_t max_cache_entries = 100000;
    };

    // Backend seams. Injected so the caching and fail-closed policy — the parts
    // that decide whether someone stays signed in — are testable without a Redis.
    using Lookup = std::function<Revocation(const std::string& jti)>;
    using Store = std::function<bool(const std::string& jti, int ttl_seconds)>;
    using Ping = std::function<bool()>;

    // Redis-backed.
    explicit TokenDenylist(Options options);
    // Test-injected backend.
    TokenDenylist(Options options, Lookup lookup, Store store, Ping ping);
    ~TokenDenylist();

    /**
     * Put `jti` beyond use for `ttl_seconds` — its own remaining lifetime.
     *
     * A non-positive ttl is a token that has already expired, which needs no
     * denying. Returns false if the write did not land, which the caller should
     * treat as "the session was NOT revoked" and say so, rather than reporting a
     * successful sign-out that did nothing.
     */
    bool revoke(const std::string& jti, int ttl_seconds);

    /** The raw verdict, cache included. */
    Revocation check(const std::string& jti);

    /**
     * May a token bearing this `jti` be honoured?
     *
     * The policy call: `Revoked` is always refused, and `Unknown` is refused
     * unless the deployment has explicitly asked to fail open. A token with no
     * `jti` at all cannot be revoked and is permitted — that is the download
     * ticket, which carries no jti, lives for seconds and is scoped to one file.
     */
    bool permits(const std::string& jti);

    /** True if the store answers. Used by the startup gate, as auditing does. */
    bool healthy();

    bool enabled() const { return opts_.enabled; }
    bool failOpen() const { return opts_.fail_open; }

    /** Test seam — drop cached verdicts. */
    void clearCache();

private:
    struct Entry {
        Revocation verdict;
        std::time_t until;
    };

    std::string key(const std::string& jti) const { return opts_.key_prefix + jti; }
    // mutex_ held.
    void cachePutLocked(const std::string& jti, Revocation v, std::time_t now);
    void pruneLocked(std::time_t now);

    // Redis implementations behind the seams above (no-ops without hiredis).
    bool ensureConnectedLocked();
    Revocation redisLookup(const std::string& jti);
    bool redisStore(const std::string& jti, int ttl_seconds);
    bool redisPing();

    Options opts_;
    Lookup lookup_;
    Store store_;
    Ping ping_;

    std::mutex mutex_;
    std::unordered_map<std::string, Entry> cache_;  // guarded by mutex_
    // Guards the Redis connection specifically, so a slow socket does not also
    // block readers that only need the cache.
    std::mutex conn_mutex_;
    redisContext* ctx_ = nullptr;  // guarded by conn_mutex_
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_TOKEN_DENYLIST_H
