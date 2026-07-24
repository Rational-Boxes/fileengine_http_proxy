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

#ifndef HTTP_BRIDGE_SESSION_STORE_H
#define HTTP_BRIDGE_SESSION_STORE_H

#include <mutex>
#include <string>

struct redisContext;  // forward-declared; hiredis is pulled in only by the .cpp

namespace httpbridge {

// WebDAV session-presence registry (PROPOSAL §14). A live Web-UI session for a
// user is a member of the sorted set  webdav:session:{tenant}:{uid}  with member
// "{jti}|{ip}" and score = the session's expiry epoch. http_bridge writes on
// login/refresh (ZADD) and removes on logout (ZREM); webdav_bridge reads the set
// to gate external WebDAV requests.
//
// All operations are best-effort: they never block login/logout, and are a no-op
// when the feature is disabled or the build has no hiredis. Mirrors
// AuditPublisher's single mutex-guarded connection (login volume is low).
class SessionStore {
public:
    struct Options {
        bool        enabled = false;              // WEBDAV_IP_BINDING_ENABLED
        std::string host = "localhost";
        int         port = 6379;
        std::string password;
        int         db = 0;
        std::string key_prefix = "webdav:session:";
    };

    explicit SessionStore(Options options);
    ~SessionStore();

    // ZADD prefix{tenant}:{uid} <score_epoch> "{member}". True on success (or when
    // disabled/no-hiredis — never a hard failure).
    bool add(const std::string& tenant, const std::string& uid,
             const std::string& member, long long score_epoch);

    // ZREM prefix{tenant}:{uid} "{member}".
    bool remove(const std::string& tenant, const std::string& uid,
                const std::string& member);

    bool enabled() const { return opts_.enabled; }

private:
    std::string key(const std::string& tenant, const std::string& uid) const {
        return opts_.key_prefix + tenant + ":" + uid;
    }
    bool ensureConnectedLocked();  // mutex_ held; hiredis-only

    Options opts_;
    std::mutex mutex_;
    redisContext* ctx_ = nullptr;  // guarded by mutex_
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_SESSION_STORE_H
