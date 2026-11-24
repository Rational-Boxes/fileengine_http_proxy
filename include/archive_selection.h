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

// The "selected items" of a folder ZIP: POST /v1/dirs/{uid}/archive and
// POST /v1/dirs/{uid}/archive-ticket take an optional list of uids, each of
// which must be a direct child of that folder (http_server.cpp checks that
// against the folder's listing; this header only parses).
//
// Two body shapes, because there are two kinds of caller:
//   - application/json  {"uids":["…","…"]}          — API clients;
//   - application/x-www-form-urlencoded  uids=a,b,c  — the SPA, which submits a
//     plain HTML form so the BROWSER receives and saves the archive (an XHR
//     would have to hold the whole ZIP in the tab). The list may also be split
//     across repeated `uids` fields.
// A GET cannot carry the list: a few hundred uids overrun the URL limits of
// browsers and of nginx's request-line buffers.
//
// Uids are restricted to the characters a core uid can contain, so nothing
// from this list can reach a log line or a query as anything but an id.
#pragma once
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/URI.h>

#include <set>
#include <string>

namespace httpbridge {
namespace archive {

// Far above any selection a person makes by ticking boxes, and the walk's
// member cap still applies to what the selected folders contain.
constexpr size_t kMaxSelection = 10000;
constexpr size_t kMaxSelectionBody = 1 << 20;   // 10,000 uuids are ~370 KB

inline bool plausibleUid(const std::string& u) {
    if (u.empty() || u.size() > 64) return false;
    for (unsigned char c : u)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-'))
            return false;
    return true;
}

enum class SelectionParse { None, Ok, Invalid };

// Parses `body` per `contentType`. None = the body names no selection (an
// empty body, or a form/JSON without `uids`): the whole folder. Invalid sets
// `err` to a message fit for the client.
inline SelectionParse parseSelection(const std::string& contentType, const std::string& body,
                                     std::set<std::string>& out, std::string& err) {
    out.clear();
    if (body.empty()) return SelectionParse::None;
    if (body.size() > kMaxSelectionBody) { err = "selection is too large"; return SelectionParse::Invalid; }
    bool named = false;
    auto add = [&](const std::string& raw) -> bool {
        // trim spaces
        size_t b = raw.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) return true;          // tolerate "a,,b" / trailing comma
        size_t e = raw.find_last_not_of(" \t\r\n");
        const std::string u = raw.substr(b, e - b + 1);
        if (!plausibleUid(u)) { err = "not a uid: " + u.substr(0, 80); return false; }
        out.insert(u);
        if (out.size() > kMaxSelection) {
            err = "more than " + std::to_string(kMaxSelection) + " items selected";
            return false;
        }
        return true;
    };
    auto addList = [&](const std::string& list) -> bool {
        size_t start = 0;
        while (start <= list.size()) {
            size_t comma = list.find(',', start);
            if (comma == std::string::npos) comma = list.size();
            if (!add(list.substr(start, comma - start))) return false;
            start = comma + 1;
        }
        return true;
    };

    if (contentType.find("application/json") != std::string::npos) {
        Poco::JSON::Object::Ptr obj;
        try {
            Poco::JSON::Parser p;
            obj = p.parse(body).extract<Poco::JSON::Object::Ptr>();
        } catch (...) {
            err = "body is not a JSON object";
            return SelectionParse::Invalid;
        }
        if (!obj || !obj->has("uids")) return SelectionParse::None;
        Poco::JSON::Array::Ptr arr = obj->getArray("uids");
        if (!arr) { err = "'uids' must be an array of strings"; return SelectionParse::Invalid; }
        named = true;
        for (size_t i = 0; i < arr->size(); ++i) {
            const auto v = arr->get(static_cast<unsigned int>(i));
            if (!v.isString()) { err = "'uids' must be an array of strings"; return SelectionParse::Invalid; }
            if (!add(v.convert<std::string>())) return SelectionParse::Invalid;
        }
    } else if (contentType.find("application/x-www-form-urlencoded") != std::string::npos) {
        size_t start = 0;
        while (start < body.size()) {
            size_t amp = body.find('&', start);
            if (amp == std::string::npos) amp = body.size();
            const std::string pair = body.substr(start, amp - start);
            start = amp + 1;
            const size_t eq = pair.find('=');
            std::string key, val;
            try {
                Poco::URI::decode(pair.substr(0, eq), key, true);
                if (eq != std::string::npos) Poco::URI::decode(pair.substr(eq + 1), val, true);
            } catch (...) {
                err = "malformed form body";
                return SelectionParse::Invalid;
            }
            if (key != "uids") continue;                // e.g. a ticket field
            named = true;
            if (!addList(val)) return SelectionParse::Invalid;
        }
    } else {
        err = "send the selection as application/json or a form";
        return SelectionParse::Invalid;
    }
    if (!named) return SelectionParse::None;
    if (out.empty()) { err = "no items selected"; return SelectionParse::Invalid; }
    return SelectionParse::Ok;
}

}  // namespace archive
}  // namespace httpbridge
