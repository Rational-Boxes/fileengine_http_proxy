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

#ifndef HTTP_BRIDGE_UPLOAD_SESSION_H
#define HTTP_BRIDGE_UPLOAD_SESSION_H

#include <cstdint>
#include <ctime>
#include <mutex>
#include <set>
#include <string>
#include <functional>
#include <istream>
#include <vector>

namespace httpbridge {

/**
 * Resumable, chunked upload sessions.
 *
 * WHY THIS EXISTS. A single streamed PUT works and is cheap, but it is one
 * request: a connection lost at 900 MB of a 1 GB file starts again at zero, and
 * on a phone or a hotel network that is the normal case rather than the
 * unlucky one. So a large upload arrives as independent parts that can be
 * retried individually, and the client can ask what already landed and send
 * only the rest.
 *
 * PARTS LIVE ON LOCAL DISK, not in Redis and not in memory. They are the file —
 * gigabytes of it — and the two stores this deployment already runs are the
 * wrong shape for that. A manifest sits beside them, so a session survives a
 * bridge restart and `status` can answer from one place.
 *
 * THAT MAKES A SESSION LOCAL TO THE INSTANCE THAT HOLDS ITS PARTS. This
 * deployment runs one bridge, so it does not bite today; behind more than one,
 * a session must stick to its instance (or the part directory must be shared
 * storage), and resuming against the wrong instance would look like the parts
 * had vanished. Recorded here because it is the kind of constraint that is
 * invisible until the day someone scales out.
 *
 * THE CORE HAS NO APPEND. `StreamFileUpload` is one continuous stream that
 * produces one version, so commit is where the parts become a file: they are
 * read back in order and streamed through as if they had arrived that way. The
 * core still never holds the whole file, and neither does this — commit copies
 * a chunk at a time.
 *
 * OWNERSHIP IS PART OF THE SESSION. Every operation is checked against the
 * user, tenant and target uid the session was opened for. A resumable upload is
 * a handle that lives across requests, and a handle nobody owns is a handle
 * anybody can finish.
 */
class UploadSession {
public:
    struct Options {
        std::string root = "/var/tmp/fileengine-uploads";
        long long max_total_bytes = 5368709120LL;   // 5 GiB, matches the streamed PUT
        long max_part_bytes = 134217728L;           // 128 MiB — a part is a retry unit
        int ttl_seconds = 86400;                    // abandoned sessions are swept after a day
        int max_sessions_per_user = 8;              // bounds disk against a client that only opens
    };

    // What a session knows about itself. Persisted as the manifest.
    struct Meta {
        std::string id;
        std::string uid;      // the file being written
        std::string user;
        std::string tenant;
        long long size = 0;         // total bytes the client promised
        long chunk_size = 0;        // bytes per part, except the last
        std::time_t created = 0;
        std::time_t expires = 0;
    };

    explicit UploadSession(Options opts);

    // Open a session for (uid, user, tenant). Empty id on failure, with `err` set.
    std::string create(const std::string& uid, const std::string& user,
                       const std::string& tenant, long long size, long chunk_size,
                       std::string& err);

    // Read a manifest. False when the id is unknown, malformed or expired.
    bool load(const std::string& id, Meta& out) const;

    // Is this caller the one that opened it, for this file?
    static bool owns(const Meta& m, const std::string& uid,
                     const std::string& user, const std::string& tenant) {
        return m.uid == uid && m.user == user && m.tenant == tenant;
    }

    // Store one part. Idempotent: re-sending a part overwrites it, so a client
    // that retries after an ambiguous failure does not corrupt the result.
    bool putPart(const Meta& m, int index, const char* data, std::size_t len,
                 std::string& err);

    // Same, but read from a stream. The part is written to disk as it arrives —
    // a part can be 128 MiB and holding it whole would reintroduce, one route
    // along, exactly the buffering the streamed PUT avoids.
    bool putPartStream(const Meta& m, int index, std::istream& in, std::string& err);

    // Which parts have landed — the answer that makes resuming possible.
    std::set<int> received(const Meta& m) const;

    // How many parts the declared size implies.
    static int partCount(long long size, long chunk_size) {
        if (size <= 0 || chunk_size <= 0) return 0;
        return static_cast<int>((size + chunk_size - 1) / chunk_size);
    }

    bool complete(const Meta& m) const {
        return static_cast<int>(received(m).size()) == partCount(m.size, m.chunk_size);
    }

    // Feed the assembled bytes to `sink` in order, a chunk at a time. Returns
    // false (with `err`) if a part is missing or unreadable — commit must not
    // hand the core a file with a hole in it.
    bool readAssembled(const Meta& m,
                       const std::function<bool(const char*, std::size_t)>& sink,
                       std::string& err) const;

    // Remove a session and its parts. Called on commit, on abort, and by the
    // sweep; safe to call on a session that is already gone.
    void discard(const std::string& id) const;

    // Delete expired sessions. Cheap, and the only thing standing between an
    // abandoned upload and a full disk.
    int sweepExpired() const;

    const Options& options() const { return opts_; }

    // Where part `index` lives. Public because commit streams the parts back
    // itself, with a cursor across them, rather than through readAssembled —
    // the gRPC writer asks for "the next chunk" and cannot be driven by a loop
    // that owns the iteration.
    std::string partPath(const Meta& m, int index) const { return partFor(m, index); }

    // ---- pure helpers, tested directly ----------------------------------

    // A session id is ours: 32 lowercase hex characters. Everything downstream
    // builds a filesystem path from it, so this is the boundary that keeps
    // "../" and absolute paths out — validate, never sanitise.
    static bool validId(const std::string& id);

    // Is the part index within what the declared size allows?
    static bool validIndex(const Meta& m, int index) {
        return index >= 0 && index < partCount(m.size, m.chunk_size);
    }

    // The size this part must be: chunk_size, except the last, which is the
    // remainder. Checked on arrival so a wrong-sized part is refused where it
    // can still be explained, not discovered as a corrupt file after commit.
    static long long expectedPartSize(const Meta& m, int index);

private:
    std::string dirFor(const std::string& id) const;
    std::string manifestFor(const std::string& id) const;
    std::string partFor(const Meta& m, int index) const;

    Options opts_;
    mutable std::mutex mutex_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_UPLOAD_SESSION_H
