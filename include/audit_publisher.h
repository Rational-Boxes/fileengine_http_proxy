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

#ifndef HTTP_BRIDGE_AUDIT_PUBLISHER_H
#define HTTP_BRIDGE_AUDIT_PUBLISHER_H

#include <mutex>
#include <string>

struct redisContext;  // forward-declared; hiredis is pulled in only by the .cpp

namespace httpbridge {

// Emits auth-category audit events (login_success / login_failure) to the shared
// aggregating Redis stream (fileengine:audit), matching
// audit_service/AUDIT_CONTRACT.md. This is the http_bridge door's counterpart of
// the core's RedisAuditSink and the Python AuditPublisher.
//
// XADD-success is the durability point (§6 "queue-accepted"), so emitAuth()
// returns whether the entry was durably accepted (or auditing is disabled), and a
// fail-closed caller (login_success) gates token issuance on it. Poco dispatches
// requests across worker threads, so the single Redis connection is guarded by a
// mutex; login volume is low, so serializing is fine. When the build has no
// hiredis, emit is a no-op that returns true (auditing unavailable never blocks).
class AuditPublisher {
public:
    struct Options {
        bool        enabled = false;
        std::string host = "localhost";
        int         port = 6379;
        std::string password;
        int         db = 0;
        std::string stream = "fileengine:audit";
        long long   stream_maxlen = 1000000;
    };

    explicit AuditPublisher(Options options);
    ~AuditPublisher();

    // Build + publish an auth envelope. `tenant` may be empty (then pass
    // scope="global"). Returns true iff durably accepted, or auditing is off.
    bool emitAuth(const std::string& action, const std::string& outcome,
                  const std::string& actor, const std::string& tenant,
                  const std::string& source_addr, const std::string& scope = "tenant");

    // Serialize an auth envelope (event_id/ts filled). Exposed for testing.
    static std::string buildAuthEnvelope(const std::string& action, const std::string& outcome,
                                         const std::string& actor, const std::string& tenant,
                                         const std::string& source_addr, const std::string& scope);

    // True iff auditing is turned on (FILEENGINE_AUDIT_ENABLED).
    bool enabled() const { return opts_.enabled; }

    // True iff the audit log is currently publishable: built WITH hiredis AND a
    // Redis connection (auth/db + PING) succeeds. Returns false when built
    // without hiredis. Used by the startup gate (A-i) and /readyz (A-ii) so that
    // "enabled but unable to record" is loud rather than a silent fail-open.
    bool healthy();

private:
    bool publish(const std::string& payload);  // XADD; mutex-guarded
    bool ensureConnectedLocked();              // mutex_ held; hiredis-only

    Options opts_;
    std::mutex mutex_;
    redisContext* ctx_ = nullptr;  // guarded by mutex_
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_AUDIT_PUBLISHER_H
