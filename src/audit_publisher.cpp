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

#include "audit_publisher.h"

#include <ctime>
#include <sstream>

#include <Poco/JSON/Object.h>
#include <Poco/Types.h>
#include <Poco/UUIDGenerator.h>

#ifdef HTTPBRIDGE_HAS_HIREDIS
#include <hiredis/hiredis.h>
#endif

namespace httpbridge {

AuditPublisher::AuditPublisher(Options options) : opts_(std::move(options)) {}

AuditPublisher::~AuditPublisher() {
#ifdef HTTPBRIDGE_HAS_HIREDIS
    if (ctx_) {
        redisFree(ctx_);
        ctx_ = nullptr;
    }
#endif
}

std::string AuditPublisher::buildAuthEnvelope(const std::string& action, const std::string& outcome,
                                              const std::string& actor, const std::string& tenant,
                                              const std::string& source_addr, const std::string& scope) {
    Poco::JSON::Object obj;
    // event_id MUST be a UUID — the consumer validates it (a non-UUID is dropped
    // as poison). ts is emit-time epoch seconds (the contract accepts epoch).
    obj.set("event_id", Poco::UUIDGenerator::defaultGenerator().createRandom().toString());
    obj.set("ts", static_cast<Poco::Int64>(std::time(nullptr)));
    obj.set("scope", scope);
    if (!tenant.empty()) obj.set("tenant", tenant);
    obj.set("category", "auth");
    obj.set("action", action);
    obj.set("outcome", outcome);
    obj.set("actor", actor);
    obj.set("source_iface", "rest");
    if (!source_addr.empty()) obj.set("source_addr", source_addr);

    std::ostringstream ss;
    obj.stringify(ss);
    return ss.str();
}

bool AuditPublisher::emitAuth(const std::string& action, const std::string& outcome,
                              const std::string& actor, const std::string& tenant,
                              const std::string& source_addr, const std::string& scope) {
    if (!opts_.enabled) return true;  // auditing off -> never blocks the operation
    return publish(buildAuthEnvelope(action, outcome, actor, tenant, source_addr, scope));
}

#ifdef HTTPBRIDGE_HAS_HIREDIS
// mutex_ must be held. Ensures ctx_ is a live, authenticated connection.
bool AuditPublisher::ensureConnectedLocked() {
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
#else
bool AuditPublisher::ensureConnectedLocked() { return false; }
#endif

bool AuditPublisher::healthy() {
#ifdef HTTPBRIDGE_HAS_HIREDIS
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureConnectedLocked()) return false;
    auto* reply = static_cast<redisReply*>(redisCommand(ctx_, "PING"));
    bool ok = reply && ctx_ && !ctx_->err && reply->type != REDIS_REPLY_ERROR;
    if (reply) freeReplyObject(reply);
    if (!ok && ctx_) { redisFree(ctx_); ctx_ = nullptr; }
    return ok;
#else
    return false;  // built without hiredis: cannot publish
#endif
}

bool AuditPublisher::publish(const std::string& payload) {
#ifdef HTTPBRIDGE_HAS_HIREDIS
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ensureConnectedLocked()) return false;

    auto* reply = static_cast<redisReply*>(redisCommand(
        ctx_, "XADD %s MAXLEN ~ %lld * payload %b",
        opts_.stream.c_str(), opts_.stream_maxlen, payload.data(), payload.size()));
    if (!reply || ctx_->err) {
        if (reply) freeReplyObject(reply);
        if (ctx_) { redisFree(ctx_); ctx_ = nullptr; }
        return false;
    }
    bool ok = reply->type != REDIS_REPLY_ERROR;
    freeReplyObject(reply);
    return ok;
#else
    (void)payload;
    return true;  // built without hiredis: auditing unavailable, never blocks
#endif
}

}  // namespace httpbridge
