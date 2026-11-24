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

// zip_stream.h — the forward-only ZIP writer behind GET /v1/dirs/{uid}/archive.
//
// The structural tests here parse the writer's own output by the spec. They are
// necessary but not sufficient: a writer and a parser written by the same hand
// agree on the same mistakes. ZIP_STREAM_DUMP_DIR, when set, writes the test
// archives out so an INDEPENDENT reader can check them —
// tests/check_zip_stream.sh runs Python's zipfile and Info-ZIP's `unzip -t`
// over them.
#include <gtest/gtest.h>

#include <cstdlib>
#include <fstream>
#include <string>

#include "zip_stream.h"

using namespace httpbridge::zip;

namespace {

uint32_t rd32(const std::string& s, size_t at) {
    return static_cast<uint32_t>(static_cast<uint8_t>(s[at])) |
           static_cast<uint32_t>(static_cast<uint8_t>(s[at + 1])) << 8 |
           static_cast<uint32_t>(static_cast<uint8_t>(s[at + 2])) << 16 |
           static_cast<uint32_t>(static_cast<uint8_t>(s[at + 3])) << 24;
}
uint16_t rd16(const std::string& s, size_t at) {
    return static_cast<uint16_t>(static_cast<uint8_t>(s[at]) |
                                 static_cast<uint8_t>(s[at + 1]) << 8);
}

Writer captureTo(std::string& out) {
    return Writer([&out](const char* p, size_t n) { out.append(p, n); return true; });
}

void dump(const std::string& name, const std::string& bytes) {
    const char* dir = std::getenv("ZIP_STREAM_DUMP_DIR");
    if (!dir || !*dir) return;
    std::ofstream f(std::string(dir) + "/" + name, std::ios::binary);
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

TEST(ZipCrc, MatchesTheStandardCheckValue) {
    // The CRC-32/ISO-HDLC check value, as zlib.crc32(b"123456789") reports it.
    const std::string v = "123456789";
    EXPECT_EQ(crc32Update(0, v.data(), v.size()), 0xCBF43926u);
}

TEST(ZipCrc, IsTheSameFedInChunks) {
    const std::string v = "The quick brown fox jumps over the lazy dog";
    uint32_t whole = crc32Update(0, v.data(), v.size());
    uint32_t parts = 0;
    for (size_t i = 0; i < v.size(); i += 5)
        parts = crc32Update(parts, v.data() + i, std::min<size_t>(5, v.size() - i));
    EXPECT_EQ(whole, parts);
    EXPECT_EQ(whole, 0x414FA339u);
}

TEST(ZipDosTime, ConvertsUtcAndClampsTheEpoch) {
    // 2026-11-23 14:30:58 UTC
    DosTime d = dosTimeFromUnix(1795444258);
    EXPECT_EQ(d.date, ((2026 - 1980) << 9) | (11 << 5) | 23);
    EXPECT_EQ(d.time, (14 << 11) | (30 << 5) | (58 / 2));
    DosTime z = dosTimeFromUnix(0);
    EXPECT_EQ(z.date, (1 << 5) | 1);   // 1980-01-01, not 1980-00-00
    EXPECT_EQ(z.time, 0);
    DosTime old = dosTimeFromUnix(315532799);   // 1979-12-31
    EXPECT_EQ(old.date, (1 << 5) | 1);
}

TEST(ZipNames, ASeparatorInANameCannotClimbOut) {
    EXPECT_EQ(sanitizeSegment("../../etc/passwd"), ".._.._etc_passwd");   // one segment
    EXPECT_EQ(sanitizeSegment("a\\b"), "a_b");
    EXPECT_EQ(sanitizeSegment(".."), "_");
    EXPECT_EQ(sanitizeSegment("."), "_");
    EXPECT_EQ(sanitizeSegment(""), "_");
    EXPECT_EQ(sanitizeSegment("tab\there"), "tab_here");
    EXPECT_EQ(sanitizeSegment("report. "), "report");
    EXPECT_EQ(sanitizeSegment("Plan ü.pdf"), "Plan ü.pdf");   // UTF-8 untouched
}

TEST(ZipNames, DuplicateSiblingsAreSuffixedCaseInsensitively) {
    SiblingNames n;
    EXPECT_EQ(n.claim("Report.pdf"), "Report.pdf");
    EXPECT_EQ(n.claim("report.PDF"), "report (2).PDF");
    EXPECT_EQ(n.claim("Report.pdf"), "Report (3).pdf");
    EXPECT_EQ(n.claim("Makefile"), "Makefile");
    EXPECT_EQ(n.claim("makefile"), "makefile (2)");
    EXPECT_EQ(n.claim(".env"), ".env");               // a leading dot is not an extension
    EXPECT_EQ(n.claim(".ENV"), ".ENV (2)");
}

TEST(ZipWriter, ProducesAWellFormedSmallArchive) {
    std::string out;
    Writer w = captureTo(out);
    const std::string a = "hello, world\n";
    ASSERT_TRUE(w.addDirectory("docs"));
    ASSERT_TRUE(w.beginFile("docs/a.txt", 1795444258));
    // In pieces, as the core delivers it.
    ASSERT_TRUE(w.data(a.data(), 5));
    ASSERT_TRUE(w.data(a.data() + 5, a.size() - 5));
    ASSERT_TRUE(w.endFile());
    ASSERT_TRUE(w.beginFile("empty.bin"));
    ASSERT_TRUE(w.endFile());
    ASSERT_TRUE(w.beginFile("Plan ü.txt"));
    ASSERT_TRUE(w.data("x", 1));
    ASSERT_TRUE(w.endFile());
    ASSERT_TRUE(w.finish());
    EXPECT_EQ(w.bytesWritten(), out.size());

    // A small archive needs no zip64 at all: classic EOCD as the last 22 bytes.
    ASSERT_GE(out.size(), 22u);
    const size_t eocd = out.size() - 22;
    EXPECT_EQ(rd32(out, eocd), 0x06054B50u);
    EXPECT_EQ(rd16(out, eocd + 10), 4);           // entries
    const uint32_t cdSize = rd32(out, eocd + 12);
    const uint32_t cdOff = rd32(out, eocd + 16);
    EXPECT_EQ(cdOff + cdSize, eocd);              // nothing between directory and EOCD
    EXPECT_EQ(out.find("\x50\x4b\x06\x06"), std::string::npos);   // no zip64 EOCD

    // Walk the central directory; check each entry's CRC/size against its data.
    size_t p = cdOff;
    int n = 0;
    while (p < eocd) {
        ASSERT_EQ(rd32(out, p), 0x02014B50u);
        const uint16_t flags = rd16(out, p + 8);
        const uint32_t crc = rd32(out, p + 16);
        const uint32_t usize = rd32(out, p + 24);
        const uint16_t nameLen = rd16(out, p + 28);
        const uint16_t extraLen = rd16(out, p + 30);
        const uint32_t localOff = rd32(out, p + 42);
        const std::string name = out.substr(p + 46, nameLen);
        EXPECT_TRUE(flags & 0x0800) << name;      // UTF-8 names
        EXPECT_EQ(extraLen, 0) << name;
        ASSERT_EQ(rd32(out, localOff), 0x04034B50u) << name;
        const size_t dataAt = localOff + 30 + rd16(out, localOff + 26) + rd16(out, localOff + 28);
        if (name == "docs/") {
            EXPECT_FALSE(flags & 0x0008);
            EXPECT_EQ(usize, 0u);
        } else {
            EXPECT_TRUE(flags & 0x0008) << name;  // sizes deferred to the descriptor
            const std::string body = out.substr(dataAt, usize);
            EXPECT_EQ(crc, crc32Update(0, body.data(), body.size())) << name;
            // 32-bit descriptor directly after the data.
            EXPECT_EQ(rd32(out, dataAt + usize), 0x08074B50u) << name;
            EXPECT_EQ(rd32(out, dataAt + usize + 4), crc) << name;
            EXPECT_EQ(rd32(out, dataAt + usize + 8), usize) << name;
        }
        if (name == "docs/a.txt") EXPECT_EQ(out.substr(dataAt, usize), a);
        p += 46 + nameLen + extraLen;
        ++n;
    }
    EXPECT_EQ(n, 4);
    dump("small.zip", out);
}

TEST(ZipWriter, ManyEntriesSwitchToZip64EndRecords) {
    // 70,000 entries is past the 16-bit count, so the archive needs the zip64
    // end records even though every size and offset still fits 32 bits.
    std::string out;
    Writer w = captureTo(out);
    for (int i = 0; i < 70000; ++i) {
        ASSERT_TRUE(w.beginFile("f/" + std::to_string(i)));
        const std::string b = std::to_string(i);
        ASSERT_TRUE(w.data(b.data(), b.size()));
        ASSERT_TRUE(w.endFile());
    }
    ASSERT_TRUE(w.finish());
    const size_t eocd = out.size() - 22;
    ASSERT_EQ(rd32(out, eocd), 0x06054B50u);
    EXPECT_EQ(rd16(out, eocd + 10), 0xFFFF);      // "see the zip64 record"
    const size_t locator = eocd - 20;
    ASSERT_EQ(rd32(out, locator), 0x07064B50u);
    const uint32_t z64At = rd32(out, locator + 8);   // low half of the u64 offset
    ASSERT_EQ(rd32(out, z64At), 0x06064B50u);
    EXPECT_EQ(rd32(out, z64At + 32), 70000u);     // total entries (low half)
    dump("many.zip", out);
}

TEST(ZipWriter, AGoneReceiverStopsEverything) {
    int calls = 0;
    Writer w([&calls](const char*, size_t) { return ++calls < 3; });
    EXPECT_TRUE(w.beginFile("a"));                // call 1
    EXPECT_TRUE(w.data("x", 1));                  // call 2
    EXPECT_FALSE(w.data("y", 1));                 // call 3 fails
    EXPECT_TRUE(w.failed());
    EXPECT_FALSE(w.endFile());
    EXPECT_FALSE(w.finish());
    EXPECT_EQ(calls, 3);                          // nothing further was attempted
}

TEST(ZipWriter, RefusesMisuse) {
    std::string out;
    Writer w = captureTo(out);
    EXPECT_FALSE(w.data("x", 1));                 // no open entry
    EXPECT_FALSE(w.endFile());
    ASSERT_TRUE(w.beginFile("a"));
    EXPECT_FALSE(w.beginFile("b"));               // one entry at a time
    EXPECT_FALSE(w.finish());                     // not with an entry open
    ASSERT_TRUE(w.endFile());
    ASSERT_TRUE(w.finish());
    EXPECT_FALSE(w.finish());                     // spent
}

TEST(ZipDisposition, CarriesTheUtf8NameAndASafeFallback) {
    EXPECT_EQ(attachmentDisposition("Q3 Drawings.zip"),
              "attachment; filename=\"Q3 Drawings.zip\"; filename*=UTF-8''Q3%20Drawings.zip");
    const std::string d = attachmentDisposition("Pläne \"neu\".zip");
    EXPECT_NE(d.find("filename=\"Plne _neu_.zip\""), std::string::npos) << d;
    EXPECT_NE(d.find("filename*=UTF-8''Pl%C3%A4ne%20%22neu%22.zip"), std::string::npos) << d;
    EXPECT_NE(attachmentDisposition("Ü.zip").find("filename=\"download.zip\""), std::string::npos);
}
