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

#include "token_denylist.h"

#ifdef HTTPBRIDGE_HAS_HIREDIS
#include <hiredis/hiredis.h>
#endif

namespace httpbridge {

TokenDenylist::TokenDenylist(Options options) : opts_(std::move(options)) {
    lookup_ = [this](const std::string& jti) { return redisLookup(jti); };
    store_ = [this](const std::string& jti, int ttl) { return redisStore(jti, ttl); };
    ping_ = [this]() { return redisPing(); };
}

TokenDenylist::TokenDenylist(Options options, Lookup lookup, Store store, Ping ping)
    : opts_(std::move(options)),
      lookup_(std::move(lookup)),
      store_(std::move(store)),
      ping_(std::move(ping)) {}

TokenDenylist::~TokenDenylist() {
#ifdef HTTPBRIDGE_HAS_HIREDIS
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
#endif
}

// ---- policy ---------------------------------------------------------------

void TokenDenylist::pruneLocked(std::time_t now) {
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (it->second.until <= now) it = cache_.erase(it);
        else ++it;
    }
    // Still over the bound after dropping what expired: the entries left are all
    // live, so there is no principled one to evict. Drop the lot — correctness is
    // unaffected (every verdict is re-fetched) and the alternative is unbounded
    // growth under a flood of distinct jtis.
    if (cache_.size() > opts_.max_cache_entries) cache_.clear();
}

void TokenDenylist::cachePutLocked(const std::string& jti, Revocation v, std::time_t now) {
    // Never cache Unknown: it is the absence of an answer, not an answer, and
    // remembering it would extend one unreachable moment across the whole window.
    if (v == Revocation::Unknown || opts_.cache_ttl <= 0) return;
    if (cache_.size() >= opts_.max_cache_entries) pruneLocked(now);
    cache_[jti] = Entry{v, now + opts_.cache_ttl};
}

Revocation TokenDenylist::check(const std::string& jti) {
    if (!opts_.enabled || jti.empty()) return Revocation::Allowed;
    const std::time_t now = std::time(nullptr);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(jti);
        if (it != cache_.end() && it->second.until > now) return it->second.verdict;
    }
    const Revocation v = lookup_ ? lookup_(jti) : Revocation::Unknown;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cachePutLocked(jti, v, now);
    }
    return v;
}

bool TokenDenylist::permits(const std::string& jti) {
    switch (check(jti)) {
        case Revocation::Allowed: return true;
        case Revocation::Revoked: return false;
        case Revocation::Unknown: return opts_.fail_open;
    }
    return opts_.fail_open;  // unreachable; refuse by default
}

bool TokenDenylist::revoke(const std::string& jti, int ttl_seconds) {
    if (!opts_.enabled) return true;   // nothing claims to be revoking
    if (jti.empty()) return false;     // cannot deny what cannot be named
    if (ttl_seconds <= 0) return true; // already expired; the denylist adds nothing
    const bool ok = store_ ? store_(jti, ttl_seconds) : false;
    if (ok) {
        // Seed the cache so this instance stops honouring the token immediately
        // rather than after cache_ttl. Other instances see it on their next miss.
        std::lock_guard<std::mutex> lock(mutex_);
        const std::time_t now = std::time(nullptr);
        if (opts_.cache_ttl > 0) cache_[jti] = Entry{Revocation::Revoked, now + opts_.cache_ttl};
    }
    return ok;
}

bool TokenDenylist::healthy() {
    if (!opts_.enabled) return true;
    return ping_ ? ping_() : false;
}

void TokenDenylist::clearCache() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

// ---- Redis backend --------------------------------------------------------
//
// Mirrors SessionStore: one lazily-established, mutex-guarded connection, freed
// and rebuilt on any error so a dropped socket heals on the next call.

#ifdef HTTPBRIDGE_HAS_HIREDIS

bool TokenDenylist::ensureConnectedLocked() {
    if (ctx_ && !ctx_->err) return true;
    if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
    ctx_ = redisConnect(opts_.host.c_str(), opts_.port);
    if (!ctx_ || ctx_->err) {
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    if (!opts_.password.empty()) {
        auto* r = static_cast<redisReply*>(redisCommand(ctx_, "AUTH %s", opts_.password.c_str()));
        bool ok = r && r->type != REDIS_REPLY_ERROR;
        if (r) freeReplyObject(r);
        if (!ok) { redisFree(ctx_); ctx_ = nullptr; return false; }
    }
    if (opts_.db != 0) {
        auto* r = static_cast<redisReply*>(redisCommand(ctx_, "SELECT %d", opts_.db));
        bool ok = r && r->type != REDIS_REPLY_ERROR;
        if (r) freeReplyObject(r);
        if (!ok) { redisFree(ctx_); ctx_ = nullptr; return false; }
    }
    return true;
}

Revocation TokenDenylist::redisLookup(const std::string& jti) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!ensureConnectedLocked()) return Revocation::Unknown;
    const std::string k = key(jti);
    auto* reply = static_cast<redisReply*>(redisCommand(ctx_, "EXISTS %s", k.c_str()));
    if (!reply || ctx_->err || reply->type == REDIS_REPLY_ERROR) {
        if (reply) freeReplyObject(reply);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return Revocation::Unknown;   // NOT "allowed" — we simply do not know
    }
    const bool present = reply->type == REDIS_REPLY_INTEGER && reply->integer > 0;
    freeReplyObject(reply);
    return present ? Revocation::Revoked : Revocation::Allowed;
}

bool TokenDenylist::redisStore(const std::string& jti, int ttl_seconds) {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!ensureConnectedLocked()) return false;
    const std::string k = key(jti);
    // The value is immaterial — presence is the whole signal. EX makes the entry
    // expire exactly when the token would have anyway.
    auto* reply = static_cast<redisReply*>(
        redisCommand(ctx_, "SET %s 1 EX %d", k.c_str(), ttl_seconds));
    if (!reply || ctx_->err || reply->type == REDIS_REPLY_ERROR) {
        if (reply) freeReplyObject(reply);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    freeReplyObject(reply);
    return true;
}

bool TokenDenylist::redisPing() {
    std::lock_guard<std::mutex> lock(conn_mutex_);
    if (!ensureConnectedLocked()) return false;
    auto* reply = static_cast<redisReply*>(redisCommand(ctx_, "PING"));
    const bool ok = reply && reply->type != REDIS_REPLY_ERROR;
    if (reply) freeReplyObject(reply);
    if (!ok && ctx_) { redisFree(ctx_); ctx_ = nullptr; }
    return ok;
}

#else  // built without hiredis

// No store, so nothing can be established. Every lookup is Unknown, which
// fail-closed turns into a refusal — and the startup gate refuses to run at all
// with revocation enabled, so this is reached only if that gate is bypassed.
bool TokenDenylist::ensureConnectedLocked() { return false; }
Revocation TokenDenylist::redisLookup(const std::string&) { return Revocation::Unknown; }
bool TokenDenylist::redisStore(const std::string&, int) { return false; }
bool TokenDenylist::redisPing() { return false; }

#endif  // HTTPBRIDGE_HAS_HIREDIS

}  // namespace httpbridge
