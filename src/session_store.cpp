#include "session_store.h"

#ifdef HTTPBRIDGE_HAS_HIREDIS
#include <hiredis/hiredis.h>
#endif

namespace httpbridge {

SessionStore::SessionStore(Options options) : opts_(std::move(options)) {}

SessionStore::~SessionStore() {
#ifdef HTTPBRIDGE_HAS_HIREDIS
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
#endif
}

#ifdef HTTPBRIDGE_HAS_HIREDIS
// mutex_ must be held. Ensures ctx_ is a live, authenticated connection.
bool SessionStore::ensureConnectedLocked() {
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

bool SessionStore::add(const std::string& tenant, const std::string& uid,
                       const std::string& member, long long score_epoch) {
    if (!opts_.enabled) return true;
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureConnectedLocked()) return false;
    const std::string k = key(tenant, uid);
    auto* reply = static_cast<redisReply*>(redisCommand(
        ctx_, "ZADD %s %lld %b", k.c_str(), score_epoch, member.data(), member.size()));
    if (!reply || ctx_->err) {
        if (reply) freeReplyObject(reply);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    bool ok = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return ok;
}

bool SessionStore::remove(const std::string& tenant, const std::string& uid,
                          const std::string& member) {
    if (!opts_.enabled) return true;
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureConnectedLocked()) return false;
    const std::string k = key(tenant, uid);
    auto* reply = static_cast<redisReply*>(redisCommand(
        ctx_, "ZREM %s %b", k.c_str(), member.data(), member.size()));
    if (!reply || ctx_->err) {
        if (reply) freeReplyObject(reply);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    bool ok = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return ok;
}
#else
bool SessionStore::ensureConnectedLocked() { return false; }
bool SessionStore::add(const std::string&, const std::string&, const std::string&, long long) {
    return true;  // built without hiredis: the gate is inert, never blocks login
}
bool SessionStore::remove(const std::string&, const std::string&, const std::string&) {
    return true;
}
#endif

}  // namespace httpbridge
