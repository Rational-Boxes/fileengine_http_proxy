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
// zip64 only where it is needed, decided ONCE per entry, when it begins. An entry
// is zip64 when it starts beyond 4 GiB or its expected size (the caller's hint)
// is large; a zip64 entry then carries the zip64 extra in its local header, a
// 64-bit data descriptor and the zip64 extra in its central header — all three,
// always together. APPNOTE 4.3.9.2 ties the descriptor's width to the presence
// of zip64 information, and readers disagree on WHICH header they consult:
// Info-ZIP takes it from the central entry, so a small file past the 4 GiB mark
// with a 16-byte descriptor read as "overlapped components (possible zip bomb)".
// (Measured 2026-11-23 against a 4.5 GiB archive; Python, 7-Zip, Go and Java's
// ZipFile all accepted it, which is why only one reader caught it.)
//
// The hint is only a hint — sizes in the version table are known to be wrong for
// some rows — so it is used with a wide margin (kZip64HintBytes), and an entry
// that was begun as non-zip64 and then grows past 4 GiB is REFUSED rather than
// written with fields that cannot hold its size: overflowed() reports it, and
// the caller must abort the transfer. The archive gets the zip64 end records
// only when its entry count or directory position needs them, so a small folder
// is a plain ZIP that every extractor, including old ones, opens.
//
// Files are DEFLATE (method 8) at level 0: the bytes go out unchanged, framed
// in "stored" deflate blocks (RFC 1951 3.2.4 — a 5-byte header per block of at
// most 65,535 bytes, about 0.008% larger). Why not plain method 0 (store):
// Java's ZipInputStream, a STREAMING reader that tools built on it inherit,
// rejects any STORED entry with a data descriptor — "only DEFLATED entries can
// have EXT descriptor" — and a forward-only writer cannot avoid the descriptor.
// Every other reader takes either. Not compressing is deliberate: most of what
// this system holds (PDF, Office, images, video) is already compressed, and the
// bridge thread's cost stays one memcpy and one CRC per byte. The blocks are
// framed here, not by zlib's deflate(), so the output does not depend on how the
// core chunked the data — the same tree gives a byte-identical archive.
// Directories (no data, no descriptor) stay method 0.
//
// Pure: no Poco, no gRPC. Output goes to a Sink, so tests can capture it and the
// bridge can hand it to the socket.
#pragma once
#include <zlib.h>

#include <algorithm>
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

// ---- CRC-32 (ISO-HDLC, the one ZIP uses) -----------------------------------
// zlib's, not a byte-at-a-time table: measured 16 GiB/s against 458 MiB/s on the
// same machine (zlib-ng), and at the table's speed the checksum alone would have
// cost one bridge core per archive at network speed.
// Running CRC: crc32Update(0, ...) starts one; feed the result back in.
inline uint32_t crc32Update(uint32_t crc, const char* p, size_t n) {
    while (n > 0) {   // zlib takes a uInt length
        const uInt step = static_cast<uInt>(n > 0x40000000u ? 0x40000000u : n);
        crc = static_cast<uint32_t>(::crc32(crc, reinterpret_cast<const Bytef*>(p), step));
        p += step;
        n -= step;
    }
    return crc;
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
    explicit Writer(Sink sink) : sink_(std::move(sink)) { pending_.reserve(kBlockMax); }

    // Directory entry. `path` is relative, '/'-separated, without a trailing
    // slash (the writer adds it — that is how a ZIP marks a directory).
    bool addDirectory(const std::string& path, int64_t mtime = 0) {
        if (open_ || failed_) return false;
        Entry e;
        e.name = path + "/";
        e.dir = true;
        e.dos = dosTimeFromUnix(mtime);
        e.offset = written_;
        e.z64 = written_ >= k32Max;
        if (!writeLocal(e)) return false;
        entries_.push_back(std::move(e));
        return true;
    }

    // Begin a file entry; follow with data() calls and exactly one endFile().
    // `sizeHint` is the size the caller expects (0 = small/unknown); it decides
    // whether the entry is written as zip64 — see the header comment.
    bool beginFile(const std::string& path, int64_t mtime = 0, uint64_t sizeHint = 0) {
        if (open_ || failed_) return false;
        Entry e;
        e.name = path;
        e.dos = dosTimeFromUnix(mtime);
        e.offset = written_;
        e.z64 = written_ >= k32Max || sizeHint >= kZip64HintBytes;
        if (!writeLocal(e)) return false;
        entries_.push_back(std::move(e));
        open_ = true;
        return true;
    }

    bool data(const char* p, size_t n) {
        if (!open_ || failed_) return false;
        if (n == 0) return true;
        Entry& e = entries_.back();
        if (!e.z64 && deflatedBound(e.size + n) >= k32Max) {
            // Begun as a 32-bit entry (the hint said small) and now too big for
            // one. Its local header is already on the wire, so there is no
            // honest way to continue.
            overflowed_ = true;
            failed_ = true;
            return false;
        }
        e.crc = crc32Update(e.crc, p, n);
        e.size += n;
        // Fill the pending block; each full one goes out as a non-final block.
        while (n > 0) {
            const size_t take = std::min(n, kBlockMax - pending_.size());
            pending_.append(p, take);
            p += take;
            n -= take;
            if (pending_.size() == kBlockMax && !flushBlock(e, false)) return false;
        }
        return true;
    }

    bool endFile() {
        if (!open_ || failed_) return false;
        Entry& e = entries_.back();
        // The final block carries whatever is left — possibly nothing, which is
        // how an empty file is encoded (5 bytes).
        if (!flushBlock(e, true)) return false;
        open_ = false;
        std::string d;
        put32(d, kSigDescriptor);
        put32(d, e.crc);
        if (e.z64) {  // zip64 descriptor: 64-bit sizes, because the local header said so
            put64(d, e.csize);
            put64(d, e.size);
        } else {
            put32(d, static_cast<uint32_t>(e.csize));
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
            const bool z64 = e.z64;
            put32(cd, kSigCentral);
            put16(cd, kMadeByUnix);
            put16(cd, z64 ? kVersionZip64 : kVersionDefault);
            put16(cd, flagsFor(e));
            put16(cd, methodFor(e));
            put16(cd, e.dos.time);
            put16(cd, e.dos.date);
            put32(cd, e.crc);
            put32(cd, z64 ? k32Max : static_cast<uint32_t>(e.csize)); // compressed
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
                put64(cd, e.size);              // uncompressed first, per APPNOTE 4.5.3
                put64(cd, e.csize);
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
    // True when an entry outgrew the 32-bit header it was begun with (the
    // size hint was wrong by gigabytes). The transfer must be aborted.
    bool overflowed() const { return overflowed_; }

    // Entries expected to be at least this large are written as zip64. Far
    // below 4 GiB on purpose: the hint comes from the version table, which is
    // known to be wrong for some rows, and a wrong "small" costs an aborted
    // download where a wrong "large" costs nothing.
    static constexpr uint64_t kZip64HintBytes = 1ull << 30;   // 1 GiB

private:
    struct Entry {
        std::string name;
        bool dir = false;
        DosTime dos;
        uint32_t crc = 0;
        uint64_t size = 0;    // bytes of the file
        uint64_t csize = 0;   // bytes on the wire: the file plus block headers
        uint64_t offset = 0;
        bool z64 = false;   // decided at begin; local, descriptor and central agree
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
    static constexpr uint16_t kVersionDefault = 20;     // 2.0: deflate, directories
    static constexpr uint16_t kMethodStore = 0;
    static constexpr uint16_t kMethodDeflate = 8;
    static constexpr size_t kBlockMax = 0xFFFF;         // a stored block's LEN is 16 bits
    static constexpr uint64_t kBlockHeader = 5;

    static uint16_t methodFor(const Entry& e) { return e.dir ? kMethodStore : kMethodDeflate; }

    // The largest compressed size `n` file bytes can become: one header per full
    // block plus the final one.
    static uint64_t deflatedBound(uint64_t n) { return n + kBlockHeader * (n / kBlockMax + 1); }

    // A stored deflate block: BFINAL in bit 0, BTYPE 00, padding to the byte,
    // then LEN and its one's complement. The header and the payload go to the
    // sink separately, so the payload is not copied again and a sink that looks
    // at content (the sparse-file test) sees the file's bytes as they were.
    bool flushBlock(Entry& e, bool final) {
        const uint16_t len = static_cast<uint16_t>(pending_.size());
        std::string h;
        h.push_back(static_cast<char>(final ? 1 : 0));
        put16(h, len);
        put16(h, static_cast<uint16_t>(~len));
        if (!emit(h.data(), h.size())) return false;
        if (len && !emit(pending_.data(), len)) return false;
        e.csize += kBlockHeader + len;
        pending_.clear();
        return true;
    }
    static constexpr uint16_t kVersionZip64 = 45;       // 4.5: zip64
    static constexpr uint16_t kMadeByUnix = (3 << 8) | 45;

    static uint16_t flagsFor(const Entry& e) {
        // A directory has no bytes to checksum, so nothing is deferred.
        return static_cast<uint16_t>(kFlagUtf8 | (e.dir ? 0 : kFlagDescriptor));
    }

    bool writeLocal(const Entry& e) {
        std::string h;
        put32(h, kSigLocal);
        put16(h, e.z64 ? kVersionZip64 : kVersionDefault);
        put16(h, flagsFor(e));
        put16(h, methodFor(e));
        put16(h, e.dos.time);
        put16(h, e.dos.date);
        put32(h, 0);                // crc -> data descriptor
        // Sizes -> data descriptor. A zip64 entry says "see the zip64 extra"
        // (0xFFFFFFFF), as Python's streaming writer does; the extra's values
        // are zero because, under bit 3, they are not known yet.
        put32(h, e.z64 ? k32Max : 0);
        put32(h, e.z64 ? k32Max : 0);
        put16(h, static_cast<uint16_t>(e.name.size()));
        put16(h, e.z64 ? 20 : 0);   // extra length
        h += e.name;
        if (e.z64) {
            put16(h, 0x0001);
            put16(h, 16);
            put64(h, 0);
            put64(h, 0);
        }
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
    std::string pending_;           // at most one block (64 KiB) of file data
    std::vector<Entry> entries_;
    uint64_t written_ = 0;
    bool open_ = false;
    bool failed_ = false;
    bool finished_ = false;
    bool overflowed_ = false;
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
