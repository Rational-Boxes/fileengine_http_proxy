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

/**
 * Resumable upload sessions.
 *
 * Two things here are security boundaries rather than housekeeping: the session
 * id becomes a directory path, and the part index becomes a file in it. And one
 * is a correctness trap — a part that arrived short must not be counted as
 * received, or resume skips it and commit hands the core a file with a hole.
 */
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "upload_session.h"

namespace fs = std::filesystem;
using httpbridge::UploadSession;

namespace {

struct Tmp {
    fs::path root;
    Tmp() {
        root = fs::temp_directory_path() /
               ("upl_test_" + std::to_string(::getpid()) + "_" +
                std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(root);
    }
    ~Tmp() { std::error_code ec; fs::remove_all(root, ec); }
};

UploadSession::Options opts(const Tmp& t) {
    UploadSession::Options o;
    o.root = t.root.string();
    return o;
}

}  // namespace

// ---- the id is a path component -------------------------------------------

TEST(UploadSessionId, AcceptsOnlyOurOwnShape) {
    EXPECT_TRUE(UploadSession::validId("0123456789abcdef0123456789abcdef"));
    EXPECT_FALSE(UploadSession::validId(""));
    EXPECT_FALSE(UploadSession::validId("0123456789abcdef"));           // too short
    EXPECT_FALSE(UploadSession::validId("0123456789ABCDEF0123456789ABCDEF")); // upper
    EXPECT_FALSE(UploadSession::validId("0123456789abcdef0123456789abcdeg")); // non-hex
}

TEST(UploadSessionId, RejectsTraversalAndAbsolutePaths) {
    // These become a directory under the session root and are handed to
    // remove_all. Validating (not sanitising) is what keeps that safe.
    EXPECT_FALSE(UploadSession::validId("../../etc/passwd"));
    EXPECT_FALSE(UploadSession::validId("/etc/passwd"));
    EXPECT_FALSE(UploadSession::validId(".."));
    EXPECT_FALSE(UploadSession::validId("abcdef01234567890123456789abc/.."));
}

TEST(UploadSessionId, DiscardIgnoresAnIdItDoesNotRecognise) {
    Tmp t;
    const auto victim = t.root / "keepme";
    fs::create_directories(victim);
    UploadSession s(opts(t));
    s.discard("../keepme");
    s.discard("/etc");
    EXPECT_TRUE(fs::exists(victim)) << "an unvalidated id reached remove_all";
}

// ---- part arithmetic -------------------------------------------------------

TEST(UploadSessionParts, CountsPartsIncludingAShortLastOne) {
    EXPECT_EQ(UploadSession::partCount(100, 10), 10);
    EXPECT_EQ(UploadSession::partCount(101, 10), 11);   // the remainder is its own part
    EXPECT_EQ(UploadSession::partCount(1, 10), 1);
    EXPECT_EQ(UploadSession::partCount(0, 10), 0);
    EXPECT_EQ(UploadSession::partCount(100, 0), 0);     // no divide-by-zero
}

TEST(UploadSessionParts, TheLastPartIsTheRemainder) {
    UploadSession::Meta m; m.size = 25; m.chunk_size = 10;
    EXPECT_EQ(UploadSession::expectedPartSize(m, 0), 10);
    EXPECT_EQ(UploadSession::expectedPartSize(m, 1), 10);
    EXPECT_EQ(UploadSession::expectedPartSize(m, 2), 5);
    EXPECT_EQ(UploadSession::expectedPartSize(m, 3), -1);  // out of range
    EXPECT_EQ(UploadSession::expectedPartSize(m, -1), -1);
}

TEST(UploadSessionParts, AnExactMultipleHasNoShortTail) {
    UploadSession::Meta m; m.size = 30; m.chunk_size = 10;
    EXPECT_EQ(UploadSession::expectedPartSize(m, 2), 10);
}

// ---- the round trip --------------------------------------------------------

TEST(UploadSessionFlow, CreateStoreResumeAssemble) {
    Tmp t; UploadSession s(opts(t));
    std::string err;
    const std::string id = s.create("uid-1", "alice", "acme", 25, 10, err);
    ASSERT_FALSE(id.empty()) << err;

    UploadSession::Meta m;
    ASSERT_TRUE(s.load(id, m));
    EXPECT_TRUE(UploadSession::owns(m, "uid-1", "alice", "acme"));
    EXPECT_FALSE(UploadSession::owns(m, "uid-1", "mallory", "acme"));
    EXPECT_FALSE(UploadSession::owns(m, "uid-2", "alice", "acme"));
    EXPECT_FALSE(UploadSession::owns(m, "uid-1", "alice", "other-tenant"));

    const std::string a(10, 'a'), b(10, 'b'), c(5, 'c');
    ASSERT_TRUE(s.putPart(m, 0, a.data(), a.size(), err)) << err;
    ASSERT_TRUE(s.putPart(m, 2, c.data(), c.size(), err)) << err;

    // The resume answer: 0 and 2 landed, 1 did not.
    auto got = s.received(m);
    EXPECT_EQ(got, (std::set<int>{0, 2}));
    EXPECT_FALSE(s.complete(m));

    ASSERT_TRUE(s.putPart(m, 1, b.data(), b.size(), err)) << err;
    EXPECT_TRUE(s.complete(m));

    std::string out;
    ASSERT_TRUE(s.readAssembled(m, [&](const char* p, std::size_t n) {
        out.append(p, n); return true;
    }, err)) << err;
    EXPECT_EQ(out, a + b + c);
}

TEST(UploadSessionFlow, ResendingAPartIsIdempotent) {
    // A client that retries after an ambiguous failure must not corrupt the file.
    Tmp t; UploadSession s(opts(t));
    std::string err;
    const std::string id = s.create("uid", "alice", "acme", 20, 10, err);
    UploadSession::Meta m; ASSERT_TRUE(s.load(id, m));
    const std::string x(10, 'x'), y(10, 'y');
    ASSERT_TRUE(s.putPart(m, 0, x.data(), 10, err));
    ASSERT_TRUE(s.putPart(m, 0, x.data(), 10, err));   // again
    ASSERT_TRUE(s.putPart(m, 1, y.data(), 10, err));
    std::string out;
    ASSERT_TRUE(s.readAssembled(m, [&](const char* p, std::size_t n) { out.append(p,n); return true; }, err));
    EXPECT_EQ(out, x + y);
}

TEST(UploadSessionFlow, AWrongSizedPartIsRefused) {
    // Refused on arrival, where it can still be explained — not discovered as a
    // corrupt file after commit.
    Tmp t; UploadSession s(opts(t));
    std::string err;
    const std::string id = s.create("uid", "alice", "acme", 20, 10, err);
    UploadSession::Meta m; ASSERT_TRUE(s.load(id, m));
    const std::string shrt(3, 'x');
    EXPECT_FALSE(s.putPart(m, 0, shrt.data(), shrt.size(), err));
    EXPECT_TRUE(s.received(m).empty()) << "a refused part must not count as received";
}

TEST(UploadSessionFlow, AnOutOfRangeIndexIsRefused) {
    Tmp t; UploadSession s(opts(t));
    std::string err;
    const std::string id = s.create("uid", "alice", "acme", 20, 10, err);
    UploadSession::Meta m; ASSERT_TRUE(s.load(id, m));
    const std::string x(10, 'x');
    EXPECT_FALSE(s.putPart(m, 2, x.data(), 10, err));
    EXPECT_FALSE(s.putPart(m, -1, x.data(), 10, err));
}

TEST(UploadSessionFlow, AssemblingWithAHoleFailsRatherThanTruncating) {
    // The alternative — streaming what we have — would commit a file that is
    // silently short. Better to refuse the commit.
    Tmp t; UploadSession s(opts(t));
    std::string err;
    const std::string id = s.create("uid", "alice", "acme", 20, 10, err);
    UploadSession::Meta m; ASSERT_TRUE(s.load(id, m));
    const std::string x(10, 'x');
    ASSERT_TRUE(s.putPart(m, 0, x.data(), 10, err));
    std::string out;
    EXPECT_FALSE(s.readAssembled(m, [&](const char* p, std::size_t n) { out.append(p,n); return true; }, err));
    EXPECT_NE(err.find("missing"), std::string::npos) << err;
}

TEST(UploadSessionFlow, DiscardRemovesTheSession) {
    Tmp t; UploadSession s(opts(t));
    std::string err;
    const std::string id = s.create("uid", "alice", "acme", 10, 10, err);
    UploadSession::Meta m; ASSERT_TRUE(s.load(id, m));
    s.discard(id);
    EXPECT_FALSE(s.load(id, m));
}

// ---- limits ----------------------------------------------------------------

TEST(UploadSessionLimits, RefusesSizesAndChunksOutOfRange) {
    Tmp t; auto o = opts(t); o.max_total_bytes = 1000; o.max_part_bytes = 100;
    UploadSession s(o);
    std::string err;
    EXPECT_TRUE(s.create("u", "a", "t", 500, 100, err).empty() == false) << err;
    EXPECT_TRUE(s.create("u", "a", "t", 5000, 100, err).empty());   // over total
    EXPECT_TRUE(s.create("u", "a", "t", 500, 500, err).empty());    // chunk too big
    EXPECT_TRUE(s.create("u", "a", "t", 500, 0, err).empty());      // chunk zero
    EXPECT_TRUE(s.create("u", "a", "t", 0, 100, err).empty());      // no size
}

TEST(UploadSessionLimits, RefusesAnAbsurdPartCount) {
    // A 1-byte chunk over a large file would put hundreds of thousands of files
    // in one directory.
    Tmp t; UploadSession s(opts(t));
    std::string err;
    EXPECT_TRUE(s.create("u", "a", "t", 1000000, 1, err).empty());
    EXPECT_NE(err.find("too many parts"), std::string::npos) << err;
}

TEST(UploadSessionLimits, BoundsOpenSessionsPerUser) {
    Tmp t; auto o = opts(t); o.max_sessions_per_user = 2;
    UploadSession s(o);
    std::string err;
    EXPECT_FALSE(s.create("u", "alice", "t", 10, 10, err).empty());
    EXPECT_FALSE(s.create("u", "alice", "t", 10, 10, err).empty());
    EXPECT_TRUE(s.create("u", "alice", "t", 10, 10, err).empty()) << "third should be refused";
    // Another user is unaffected — the bound is per user, not global.
    EXPECT_FALSE(s.create("u", "bob", "t", 10, 10, err).empty()) << err;
}

TEST(UploadSessionLimits, AnExpiredSessionIsGone) {
    Tmp t; auto o = opts(t); o.ttl_seconds = -1;   // already expired on creation
    UploadSession s(o);
    std::string err;
    const std::string id = s.create("u", "alice", "t", 10, 10, err);
    ASSERT_FALSE(id.empty()) << err;
    UploadSession::Meta m;
    EXPECT_FALSE(s.load(id, m)) << "an expired session must not load";
    EXPECT_GE(s.sweepExpired(), 1);
}
