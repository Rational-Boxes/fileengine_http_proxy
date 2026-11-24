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

// A forward-only ZIP writer, for streaming a folder tree to a client without
// assembling the archive anywhere — not on disk, not in memory.
//
// Why it can be forward-only: every entry sets general-purpose bit 3, which
// moves its CRC-32 and sizes from the local header (written BEFORE the data) to
// a data descriptor written AFTER it. The CRC is accumulated as the bytes pass
// through, so nothing is read twice and nothing is held beyond the chunk in
// hand. The central directory at the end is built from what was remembered on
// the way (a name, a CRC, two sizes and an offset per entry) — a few dozen
// bytes per member, never the members themselves.
//
// Why the sizes are NOT taken up front: the size a listing reports comes from
// the version row, and that column is known to be wrong for some production
// rows (copies made before core 1.9.67 recorded the stored blob length; seed-era
// rows are stale). An archive whose length was declared from those numbers
// would abort on exactly those files. This writer counts the bytes that really
// went out, so the archive is correct whatever the bookkeeping says, at the cost
// of a Content-Length (the response is chunked). share_service's archive.py
// makes the opposite trade, deliberately — a share recipient gets a progress bar
// — and is the reference this one was checked against.
//
// zip64 only where it is needed (Go's archive/zip makes the same choice): an
// entry gets a 64-bit descriptor and a zip64 central extra only when its size or
// offset does not fit 32 bits, and the archive gets the zip64 end records only
// when its entry count or directory position does. A small folder is therefore a
// plain ZIP that every extractor, including old ones, opens.
//
// Store-only (method 0). Most of what this system holds — PDF, Office, images,
// video — is already compressed, and storing keeps the bridge thread's cost at
// one memcpy and one CRC per byte.
//
// Pure: no Poco, no gRPC. Output goes to a Sink, so tests can capture it and the
// bridge can hand it to the socket.
#pragma once
#include <array>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace httpbridge {
namespace zip {

// ---- CRC-32 (ISO-HDLC, the one ZIP uses; reflected poly 0xEDB88320) -------
inline const std::array<uint32_t, 256>& crcTable() {
    static const std::array<uint32_t, 256> t = [] {
        std::array<uint32_t, 256> a{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            a[i] = c;
        }
        return a;
    }();
    return t;
}

// Running CRC: crc32Update(0, ...) starts one; feed the result back in.
inline uint32_t crc32Update(uint32_t crc, const char* p, size_t n) {
    const auto& t = crcTable();
    crc = ~crc;
    for (size_t i = 0; i < n; ++i)
        crc = t[(crc ^ static_cast<uint8_t>(p[i])) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

// ---- DOS date/time ---------------------------------------------------------
// ZIP's native timestamp: local time with 2-second resolution and a 1980 epoch.
// We write UTC (there is no "local" for a server streaming to a stranger);
// anything before 1980, or unknown (<= 0), becomes the DOS epoch.
struct DosTime { uint16_t time = 0; uint16_t date = (1 << 5) | 1; };  // 1980-01-01

inline DosTime dosTimeFromUnix(int64_t epoch) {
    DosTime d;
    if (epoch <= 0) return d;
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
    if (!gmtime_r(&t, &tm)) return d;
    const int year = tm.tm_year + 1900;
    if (year < 1980) return d;
    if (year > 2107) {  // the 7-bit year field's ceiling
        d.date = static_cast<uint16_t>((127 << 9) | (12 << 5) | 31);
        d.time = static_cast<uint16_t>((23 << 11) | (59 << 5) | 29);
        return d;
    }
    d.date = static_cast<uint16_t>(((year - 1980) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday);
    d.time = static_cast<uint16_t>((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2));
    return d;
}

// ---- names -----------------------------------------------------------------
// A node name becomes ONE path segment. The core does not forbid '/' or '\' in a
// name, and an extractor would treat either as a directory separator — so a
// file called "a/../../x" would otherwise climb out of the extraction directory
// (zip-slip). Separators and control characters become '_', and the two names
// that mean something to a filesystem ("." and "..") are renamed outright.
inline std::string sanitizeSegment(const std::string& raw) {
    std::string s;
    s.reserve(raw.size());
    for (unsigned char c : raw) {
        if (c == '/' || c == '\\' || c < 0x20 || c == 0x7F) s.push_back('_');
        else s.push_back(static_cast<char>(c));
    }
    // Trailing dots and spaces are silently stripped by Windows, which would
    // merge "a." into "a"; and an all-dots name is a traversal on some tools.
    while (!s.empty() && (s.back() == ' ' || s.back() == '.')) s.pop_back();
    if (s.empty()) s = "_";
    return s;
}

// Two siblings can share a name (case variants, or a name that sanitising made
// equal). An archive with duplicate paths extracts as one file silently
// overwriting the other, so the second becomes "name (2).ext", and so on.
// Comparison is case-insensitive because the most common extractors are.
class SiblingNames {
public:
    std::string claim(const std::string& name) {
        if (taken_.insert(fold(name)).second) return name;
        const auto dot = name.find_last_of('.');
        const bool hasExt = dot != std::string::npos && dot > 0;
        const std::string stem = hasExt ? name.substr(0, dot) : name;
        const std::string ext = hasExt ? name.substr(dot) : std::string();
        for (int n = 2;; ++n) {
            std::string cand = stem + " (" + std::to_string(n) + ")" + ext;
            if (taken_.insert(fold(cand)).second) return cand;
        }
    }
private:
    static std::string fold(const std::string& s) {
        std::string o(s);
        for (auto& c : o) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        return o;
    }
    std::set<std::string> taken_;
};

// ---- the writer ------------------------------------------------------------
// Returns false when the receiver is gone; every method then refuses further
// work, and the caller must ABORT the transfer rather than finish it — a ZIP
// that ends without its central directory is not an archive.
using Sink = std::function<bool(const char*, size_t)>;

class Writer {
public:
    explicit Writer(Sink sink) : sink_(std::move(sink)) {}

    // Directory entry. `path` is relative, '/'-separated, without a trailing
    // slash (the writer adds it — that is how a ZIP marks a directory).
    bool addDirectory(const std::string& path, int64_t mtime = 0) {
        if (open_ || failed_) return false;
        Entry e;
        e.name = path + "/";
        e.dir = true;
        e.dos = dosTimeFromUnix(mtime);
        e.offset = written_;
        if (!writeLocal(e)) return false;
        entries_.push_back(std::move(e));
        return true;
    }

    // Begin a file entry; follow with data() calls and exactly one endFile().
    bool beginFile(const std::string& path, int64_t mtime = 0) {
        if (open_ || failed_) return false;
        Entry e;
        e.name = path;
        e.dos = dosTimeFromUnix(mtime);
        e.offset = written_;
        if (!writeLocal(e)) return false;
        entries_.push_back(std::move(e));
        open_ = true;
        return true;
    }

    bool data(const char* p, size_t n) {
        if (!open_ || failed_) return false;
        if (n == 0) return true;
        Entry& e = entries_.back();
        e.crc = crc32Update(e.crc, p, n);
        e.size += n;
        return emit(p, n);
    }

    bool endFile() {
        if (!open_ || failed_) return false;
        open_ = false;
        const Entry& e = entries_.back();
        std::string d;
        put32(d, kSigDescriptor);
        put32(d, e.crc);
        if (e.size >= k32Max) {  // zip64 descriptor: 64-bit sizes
            put64(d, e.size);
            put64(d, e.size);
        } else {
            put32(d, static_cast<uint32_t>(e.size));
            put32(d, static_cast<uint32_t>(e.size));
        }
        return emit(d.data(), d.size());
    }

    // Central directory + end records. After this the writer is spent.
    bool finish() {
        if (open_ || failed_ || finished_) return false;
        finished_ = true;
        const uint64_t cdOffset = written_;
        std::string cd;
        for (const auto& e : entries_) {
            const bool z64 = e.size >= k32Max || e.offset >= k32Max;
            put32(cd, kSigCentral);
            put16(cd, kMadeByUnix);
            put16(cd, z64 ? kVersionZip64 : kVersionDefault);
            put16(cd, flagsFor(e));
            put16(cd, 0);                       // method: store
            put16(cd, e.dos.time);
            put16(cd, e.dos.date);
            put32(cd, e.crc);
            put32(cd, z64 ? k32Max : static_cast<uint32_t>(e.size));  // compressed
            put32(cd, z64 ? k32Max : static_cast<uint32_t>(e.size));  // uncompressed
            put16(cd, static_cast<uint16_t>(e.name.size()));
            put16(cd, z64 ? 28 : 0);            // extra length
            put16(cd, 0);                       // comment length
            put16(cd, 0);                       // disk number start
            put16(cd, 0);                       // internal attributes
            // Unix mode in the high half, so extractors that honour it (Info-ZIP,
            // macOS) create readable files instead of mode 000; 0x10 is the DOS
            // directory bit, for the ones that read the low half.
            put32(cd, e.dir ? ((040755u << 16) | 0x10u) : (0100644u << 16));
            put32(cd, z64 ? k32Max : static_cast<uint32_t>(e.offset));
            cd += e.name;
            if (z64) {
                // All three fields, because all three headers fields say 0xFFFFFFFF.
                put16(cd, 0x0001);
                put16(cd, 24);
                put64(cd, e.size);
                put64(cd, e.size);
                put64(cd, e.offset);
            }
            // Flush in pieces: a large tree's directory should not become one
            // contiguous allocation either.
            if (cd.size() >= 64 * 1024) {
                if (!emit(cd.data(), cd.size())) return false;
                cd.clear();
            }
        }
        if (!cd.empty() && !emit(cd.data(), cd.size())) return false;
        const uint64_t cdSize = written_ - cdOffset;
        const uint64_t count = entries_.size();

        std::string end;
        const bool z64 = count >= 0xFFFF || cdSize >= k32Max || cdOffset >= k32Max;
        if (z64) {
            const uint64_t z64EocdOffset = written_;
            put32(end, kSigZip64Eocd);
            put64(end, 44);                     // size of the remaining record
            put16(end, kMadeByUnix);
            put16(end, kVersionZip64);
            put32(end, 0);                      // this disk
            put32(end, 0);                      // disk with the central directory
            put64(end, count);
            put64(end, count);
            put64(end, cdSize);
            put64(end, cdOffset);
            put32(end, kSigZip64Locator);
            put32(end, 0);
            put64(end, z64EocdOffset);
            put32(end, 1);                      // total disks
        }
        put32(end, kSigEocd);
        put16(end, 0);
        put16(end, 0);
        put16(end, z64 ? 0xFFFF : static_cast<uint16_t>(count));
        put16(end, z64 ? 0xFFFF : static_cast<uint16_t>(count));
        put32(end, z64 ? k32Max : static_cast<uint32_t>(cdSize));
        put32(end, z64 ? k32Max : static_cast<uint32_t>(cdOffset));
        put16(end, 0);                          // comment length
        return emit(end.data(), end.size());
    }

    uint64_t bytesWritten() const { return written_; }
    size_t entryCount() const { return entries_.size(); }
    bool failed() const { return failed_; }

private:
    struct Entry {
        std::string name;
        bool dir = false;
        DosTime dos;
        uint32_t crc = 0;
        uint64_t size = 0;
        uint64_t offset = 0;
    };

    static constexpr uint32_t k32Max = 0xFFFFFFFFu;
    static constexpr uint32_t kSigLocal = 0x04034B50;
    static constexpr uint32_t kSigDescriptor = 0x08074B50;
    static constexpr uint32_t kSigCentral = 0x02014B50;
    static constexpr uint32_t kSigZip64Eocd = 0x06064B50;
    static constexpr uint32_t kSigZip64Locator = 0x07064B50;
    static constexpr uint32_t kSigEocd = 0x06054B50;
    static constexpr uint16_t kFlagDescriptor = 0x0008;
    static constexpr uint16_t kFlagUtf8 = 0x0800;
    static constexpr uint16_t kVersionDefault = 20;     // 2.0: store, directories
    static constexpr uint16_t kVersionZip64 = 45;       // 4.5: zip64
    static constexpr uint16_t kMadeByUnix = (3 << 8) | 45;

    static uint16_t flagsFor(const Entry& e) {
        // A directory has no bytes to checksum, so nothing is deferred.
        return static_cast<uint16_t>(kFlagUtf8 | (e.dir ? 0 : kFlagDescriptor));
    }

    bool writeLocal(const Entry& e) {
        std::string h;
        put32(h, kSigLocal);
        put16(h, kVersionDefault);
        put16(h, flagsFor(e));
        put16(h, 0);                // method: store
        put16(h, e.dos.time);
        put16(h, e.dos.date);
        put32(h, 0);                // crc   -> data descriptor
        put32(h, 0);                // csize -> data descriptor
        put32(h, 0);                // usize -> data descriptor
        put16(h, static_cast<uint16_t>(e.name.size()));
        put16(h, 0);                // extra length
        h += e.name;
        return emit(h.data(), h.size());
    }

    bool emit(const char* p, size_t n) {
        if (failed_) return false;
        if (!sink_(p, n)) { failed_ = true; return false; }
        written_ += n;
        return true;
    }

    static void put16(std::string& s, uint16_t v) {
        s.push_back(static_cast<char>(v & 0xFF));
        s.push_back(static_cast<char>((v >> 8) & 0xFF));
    }
    static void put32(std::string& s, uint32_t v) {
        for (int i = 0; i < 4; ++i) s.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
    }
    static void put64(std::string& s, uint64_t v) {
        for (int i = 0; i < 8; ++i) s.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
    }

    Sink sink_;
    std::vector<Entry> entries_;
    uint64_t written_ = 0;
    bool open_ = false;
    bool failed_ = false;
    bool finished_ = false;
};

// ---- the download's filename ------------------------------------------------
// RFC 6266: an ASCII fallback plus the exact UTF-8 name in filename*. The
// fallback drops anything a header or a filesystem would choke on.
inline std::string attachmentDisposition(const std::string& utf8Name) {
    std::string ascii;
    for (unsigned char c : utf8Name) {
        if (c >= 0x20 && c < 0x7F && c != '"' && c != '\\' && c != '/' && c != ';' && c != '%')
            ascii.push_back(static_cast<char>(c));
        else if (c < 0x80)
            ascii.push_back('_');
        // non-ASCII bytes are omitted from the fallback; filename* carries them
    }
    if (ascii.empty() || ascii == ".zip") ascii = "download.zip";
    static const char* hex = "0123456789ABCDEF";
    std::string enc;
    for (unsigned char c : utf8Name) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~') {
            enc.push_back(static_cast<char>(c));
        } else {
            enc.push_back('%');
            enc.push_back(hex[c >> 4]);
            enc.push_back(hex[c & 0xF]);
        }
    }
    return "attachment; filename=\"" + ascii + "\"; filename*=UTF-8''" + enc;
}

}  // namespace zip
}  // namespace httpbridge
