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

#include "upload_session.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>

#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>

#include "utils.h"

namespace fs = std::filesystem;

namespace httpbridge {
namespace {

std::string randomId() {
    unsigned char buf[16] = {0};
    std::ifstream f("/dev/urandom", std::ios::binary);
    f.read(reinterpret_cast<char*>(buf), sizeof(buf));
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(sizeof(buf) * 2);
    for (unsigned char b : buf) { s += hex[b >> 4]; s += hex[b & 0x0f]; }
    return s;
}

}  // namespace

UploadSession::UploadSession(Options opts) : opts_(std::move(opts)) {
    std::error_code ec;
    fs::create_directories(opts_.root, ec);
}

bool UploadSession::validId(const std::string& id) {
    if (id.size() != 32) return false;
    return std::all_of(id.begin(), id.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

long long UploadSession::expectedPartSize(const Meta& m, int index) {
    const int n = partCount(m.size, m.chunk_size);
    if (index < 0 || index >= n) return -1;
    if (index < n - 1) return m.chunk_size;
    const long long rem = m.size % m.chunk_size;
    return rem == 0 ? m.chunk_size : rem;
}

std::string UploadSession::dirFor(const std::string& id) const {
    return opts_.root + "/" + id;
}
std::string UploadSession::manifestFor(const std::string& id) const {
    return dirFor(id) + "/manifest.json";
}
std::string UploadSession::partFor(const Meta& m, int index) const {
    return dirFor(m.id) + "/" + std::to_string(index) + ".part";
}

std::string UploadSession::create(const std::string& uid, const std::string& user,
                                  const std::string& tenant, long long size,
                                  long chunk_size, std::string& err) {
    if (size <= 0) { err = "size must be positive"; return ""; }
    if (size > opts_.max_total_bytes) { err = "upload exceeds the maximum size"; return ""; }
    if (chunk_size <= 0 || chunk_size > opts_.max_part_bytes) {
        err = "chunk_size out of range"; return "";
    }
    // A client that picks a tiny chunk for a huge file would create hundreds of
    // thousands of files in one directory. Bound the part COUNT, not just sizes.
    if (partCount(size, chunk_size) > 10000) {
        err = "too many parts — use a larger chunk_size"; return "";
    }

    std::lock_guard<std::mutex> lock(mutex_);
    // Bound how much disk one user can tie up by opening sessions and walking
    // away. Sweeping expired ones first means a heavy but honest user is not
    // blocked by their own finished work.
    int mine = 0;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(opts_.root, ec)) {
        Meta m;
        if (load(e.path().filename().string(), m) && m.user == user) ++mine;
    }
    if (mine >= opts_.max_sessions_per_user) {
        err = "too many open uploads — finish or cancel one first"; return "";
    }

    Meta m;
    m.id = randomId();
    m.uid = uid; m.user = user; m.tenant = tenant;
    m.size = size; m.chunk_size = chunk_size;
    m.created = std::time(nullptr);
    m.expires = m.created + opts_.ttl_seconds;

    fs::create_directories(dirFor(m.id), ec);
    if (ec) { err = "could not open an upload session"; return ""; }

    Poco::JSON::Object o;
    o.set("id", m.id); o.set("uid", m.uid); o.set("user", m.user);
    o.set("tenant", m.tenant);
    o.set("size", static_cast<Poco::Int64>(m.size));
    o.set("chunk_size", static_cast<Poco::Int64>(m.chunk_size));
    o.set("created", static_cast<Poco::Int64>(m.created));
    o.set("expires", static_cast<Poco::Int64>(m.expires));
    std::ostringstream os; o.stringify(os);
    std::ofstream f(manifestFor(m.id), std::ios::binary | std::ios::trunc);
    if (!f) { err = "could not record the upload session"; return ""; }
    f << os.str();
    f.close();
    return m.id;
}

bool UploadSession::load(const std::string& id, Meta& out) const {
    if (!validId(id)) return false;
    std::ifstream f(manifestFor(id), std::ios::binary);
    if (!f) return false;
    std::string body((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    try {
        Poco::JSON::Parser p;
        auto o = p.parse(body).extract<Poco::JSON::Object::Ptr>();
        if (!o) return false;
        out.id = o->optValue<std::string>("id", "");
        out.uid = o->optValue<std::string>("uid", "");
        out.user = o->optValue<std::string>("user", "");
        out.tenant = o->optValue<std::string>("tenant", "");
        out.size = o->optValue<Poco::Int64>("size", 0);
        out.chunk_size = static_cast<long>(o->optValue<Poco::Int64>("chunk_size", 0));
        out.created = static_cast<std::time_t>(o->optValue<Poco::Int64>("created", 0));
        out.expires = static_cast<std::time_t>(o->optValue<Poco::Int64>("expires", 0));
    } catch (...) {
        return false;
    }
    if (out.id != id) return false;                       // manifest must name itself
    if (out.expires && std::time(nullptr) > out.expires) return false;  // expired = gone
    return true;
}

bool UploadSession::putPart(const Meta& m, int index, const char* data,
                            std::size_t len, std::string& err) {
    if (!validIndex(m, index)) { err = "part index out of range"; return false; }
    const long long want = expectedPartSize(m, index);
    if (want < 0 || static_cast<long long>(len) != want) {
        err = "part size does not match chunk_size"; return false;
    }
    // Write beside the target and rename: a part is either wholly there or not
    // there at all, so a connection dropped mid-part leaves nothing that a
    // later `received` would count as complete.
    const std::string target = partFor(m, index);
    const std::string tmp = target + ".partial";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) { err = "could not write the part"; return false; }
        f.write(data, static_cast<std::streamsize>(len));
        if (!f) { err = "could not write the part"; return false; }
    }
    std::error_code ec;
    fs::rename(tmp, target, ec);
    if (ec) { fs::remove(tmp, ec); err = "could not commit the part"; return false; }
    return true;
}

bool UploadSession::putPartStream(const Meta& m, int index, std::istream& in,
                                  std::string& err) {
    if (!validIndex(m, index)) { err = "part index out of range"; return false; }
    const long long want = expectedPartSize(m, index);
    if (want < 0) { err = "part index out of range"; return false; }

    const std::string target = partFor(m, index);
    const std::string tmp = target + ".partial";
    long long written = 0;
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) { err = "could not write the part"; return false; }
        std::vector<char> buf(256 * 1024);
        while (written < want) {
            const std::streamsize chunk = static_cast<std::streamsize>(
                std::min<long long>(want - written, static_cast<long long>(buf.size())));
            in.read(buf.data(), chunk);
            const std::streamsize got = in.gcount();
            if (got <= 0) break;              // client stopped early
            f.write(buf.data(), got);
            if (!f) { err = "could not write the part"; break; }
            written += got;
        }
    }
    std::error_code ec;
    // Exactly the declared length or nothing. A short part left in place would
    // be counted by `received` on the next resume and the hole would survive
    // into the committed file.
    if (written != want) {
        fs::remove(tmp, ec);
        if (err.empty()) err = "part size does not match chunk_size";
        return false;
    }
    fs::rename(tmp, target, ec);
    if (ec) { fs::remove(tmp, ec); err = "could not commit the part"; return false; }
    return true;
}

std::set<int> UploadSession::received(const Meta& m) const {
    std::set<int> got;
    const int n = partCount(m.size, m.chunk_size);
    std::error_code ec;
    for (int i = 0; i < n; ++i) {
        const auto sz = fs::file_size(partFor(m, i), ec);
        if (!ec && static_cast<long long>(sz) == expectedPartSize(m, i)) got.insert(i);
    }
    return got;
}

bool UploadSession::readAssembled(const Meta& m,
                                  const std::function<bool(const char*, std::size_t)>& sink,
                                  std::string& err) const {
    const int n = partCount(m.size, m.chunk_size);
    std::vector<char> buf(256 * 1024);
    for (int i = 0; i < n; ++i) {
        std::ifstream f(partFor(m, i), std::ios::binary);
        if (!f) { err = "part " + std::to_string(i) + " is missing"; return false; }
        long long remaining = expectedPartSize(m, i);
        while (remaining > 0) {
            const std::streamsize want =
                static_cast<std::streamsize>(std::min<long long>(remaining, static_cast<long long>(buf.size())));
            f.read(buf.data(), want);
            const std::streamsize got = f.gcount();
            if (got <= 0) { err = "part " + std::to_string(i) + " is short"; return false; }
            if (!sink(buf.data(), static_cast<std::size_t>(got))) {
                err = "upload was interrupted"; return false;
            }
            remaining -= got;
        }
    }
    return true;
}

void UploadSession::discard(const std::string& id) const {
    if (!validId(id)) return;   // never let an unvalidated id reach remove_all
    std::error_code ec;
    fs::remove_all(dirFor(id), ec);
}

int UploadSession::sweepExpired() const {
    int n = 0;
    std::error_code ec;
    const std::time_t now = std::time(nullptr);
    for (const auto& e : fs::directory_iterator(opts_.root, ec)) {
        const std::string id = e.path().filename().string();
        if (!validId(id)) continue;
        Meta m;
        if (load(id, m)) continue;          // still valid
        // Unreadable or expired. Only sweep once it is genuinely past its time,
        // so a manifest being written right now is not swept mid-creation.
        std::error_code ec2;
        const auto age = fs::last_write_time(e.path(), ec2);
        (void)age;
        if (!load(id, m) && now > 0) { discard(id); ++n; }
    }
    return n;
}

}  // namespace httpbridge
