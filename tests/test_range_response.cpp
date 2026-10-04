// Range responses and the playback media type (range_response.h).
//
// The bridge used to stream every file from byte zero and discard everything
// before a requested window, and answered 206 with `Content-Range: bytes N-/*` —
// no last byte, no total — which media elements' seeking depends on. With the
// core now able to serve a window and report the total (offset/length,
// total_size), a range is planned from that total, exactly.
#include <gtest/gtest.h>
#include "range_response.h"

using namespace httpbridge;

TEST(RangeResponse, WholeFileIsA200WithItsLength) {
    auto p = planRange(false, -1, -1, 1000);
    EXPECT_EQ(p.status, 200);
    EXPECT_EQ(p.length, 1000);
    EXPECT_TRUE(p.content_range.empty());
}

TEST(RangeResponse, ABoundedRangeIsA206WithStartEndAndTotal) {
    auto p = planRange(true, 100, 199, 1000);
    EXPECT_EQ(p.status, 206);
    EXPECT_EQ(p.start, 100);
    EXPECT_EQ(p.length, 100);
    EXPECT_EQ(p.content_range, "bytes 100-199/1000");
}

TEST(RangeResponse, AnOpenRangeRunsToTheEnd) {
    auto p = planRange(true, 900, -1, 1000);
    EXPECT_EQ(p.status, 206);
    EXPECT_EQ(p.length, 100);
    EXPECT_EQ(p.content_range, "bytes 900-999/1000");
}

TEST(RangeResponse, AnEndPastTheFileIsClamped) {
    auto p = planRange(true, 900, 5000, 1000);
    EXPECT_EQ(p.content_range, "bytes 900-999/1000");
    EXPECT_EQ(p.length, 100);
}

TEST(RangeResponse, AStartPastTheFileIs416WithTheTotal) {
    auto p = planRange(true, 1000, -1, 1000);
    EXPECT_EQ(p.status, 416);
    EXPECT_EQ(p.content_range, "bytes */1000");
}

TEST(RangeResponse, AnUnknownTotalNeverClaimsALength) {
    // An older core that reports no total: never invent one.
    auto p = planRange(false, -1, -1, 0);
    EXPECT_EQ(p.status, 200);
    EXPECT_EQ(p.length, -1);
}

TEST(RangeResponse, AnEmptyFileHasNoSatisfiableRange) {
    EXPECT_EQ(planRange(true, 0, -1, 0).status, 200);   // unknown total → whole body
}

TEST(PlaybackMime, OnlyAFixedSetOfMediaTypes) {
    EXPECT_EQ(playbackMimeFor("v2-media.webm"), "video/webm");
    EXPECT_EQ(playbackMimeFor("clip.MP4"), "video/mp4");
    EXPECT_EQ(playbackMimeFor("v2-audio.mp3"), "audio/mpeg");
    EXPECT_EQ(playbackMimeFor("talk.m4a"), "audio/mp4");
    EXPECT_EQ(playbackMimeFor("song.ogg"), "audio/ogg");
}

TEST(PlaybackMime, AnythingElseIsNotPlayable) {
    // The tenant origin must never serve something a browser would RUN.
    EXPECT_EQ(playbackMimeFor("page.html"), "");
    EXPECT_EQ(playbackMimeFor("image.svg"), "");
    EXPECT_EQ(playbackMimeFor("script.js"), "");
    EXPECT_EQ(playbackMimeFor("noext"), "");
    EXPECT_EQ(playbackMimeFor("clip.webm.html"), "");
}
