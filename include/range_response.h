// How the bridge answers a content GET with or without a Range, and which media
// type a playback ticket may serve.
//
// planRange is computed from the TOTAL the core reports on the first frame
// (GetFileResponse.total_size), so a 206 carries an exact
// `Content-Range: bytes start-end/total` and Content-Length — what a media
// element's seeking depends on. The bridge used to answer `bytes N-/*`.
#pragma once
#include <algorithm>
#include <cctype>
#include <string>

namespace httpbridge {

struct RangePlan {
    int status = 200;          // 200 | 206 | 416
    long start = 0;
    long length = -1;          // -1 = unknown (no Content-Length)
    std::string content_range; // empty for a 200
};

inline RangePlan planRange(bool hasRange, long rs, long re, long total) {
    RangePlan p;
    if (!hasRange || total <= 0) {
        // A whole-file answer. With no known total a range cannot be
        // planned honestly, so the whole body is sent rather than a guess.
        p.status = 200;
        p.length = total > 0 ? total : -1;
        return p;
    }
    if (rs >= total) {
        p.status = 416;
        p.content_range = "bytes */" + std::to_string(total);
        return p;
    }
    const long end = (re >= 0) ? std::min(re, total - 1) : total - 1;
    p.status = 206;
    p.start = rs;
    p.length = end - rs + 1;
    p.content_range = "bytes " + std::to_string(rs) + "-" + std::to_string(end) + "/" +
                      std::to_string(total);
    return p;
}

// The media type a PLAYBACK ticket serves its file as — from a fixed allowlist
// of audio/video containers, decided by extension at mint time. Anything else
// returns "" and is not playable: the tenant origin must never serve a type a
// browser would execute, so everything outside this list stays
// application/octet-stream with nosniff.
inline std::string playbackMimeFor(const std::string& name) {
    const auto dot = name.rfind('.');
    if (dot == std::string::npos) return "";
    std::string ext = name.substr(dot + 1);
    for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (ext == "webm") return "video/webm";
    if (ext == "mp4" || ext == "m4v") return "video/mp4";
    if (ext == "m4a") return "audio/mp4";
    if (ext == "mp3") return "audio/mpeg";
    if (ext == "ogg" || ext == "oga" || ext == "opus") return "audio/ogg";
    return "";
}

}  // namespace httpbridge
