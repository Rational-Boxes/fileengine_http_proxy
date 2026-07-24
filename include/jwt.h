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

#ifndef HTTP_BRIDGE_JWT_H
#define HTTP_BRIDGE_JWT_H

// Minimal, dependency-light HS256 JWT (sign + verify) for the bridge's bearer
// session tokens. Built on Poco (HMAC-SHA256, base64url, JSON) which the bridge
// already links. The token carries the resolved identity so every service can
// authorize LOCALLY from the signed claims — no per-request introspection.
//
// Claims (see http_server issueToken):
//   iss, sub (user), email, name, tenant (active), iat, exp, jti,
//   roles: { "<tenant>": ["role", ...], ... }   // ALL the user's tenants
//
// Security notes: the algorithm is pinned to HS256 (no "alg":"none" / alg
// confusion), the signature is compared in constant time, and exp is enforced.

#include <sstream>
#include <string>

#include <openssl/hmac.h>

#include <Poco/Base64Decoder.h>
#include <Poco/Base64Encoder.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>

namespace httpbridge {
namespace jwt {

inline std::string b64urlEncode(const std::string& in) {
    std::ostringstream os;
    Poco::Base64Encoder enc(os, Poco::BASE64_URL_ENCODING);
    enc.rdbuf()->setLineLength(0);
    enc << in;
    enc.close();
    std::string s = os.str();
    while (!s.empty() && s.back() == '=') s.pop_back();  // JWT uses no padding
    return s;
}

inline std::string b64urlDecode(const std::string& in) {
    std::string padded = in;
    while (padded.size() % 4) padded.push_back('=');
    std::istringstream is(padded);
    Poco::Base64Decoder dec(is, Poco::BASE64_URL_ENCODING);
    return std::string((std::istreambuf_iterator<char>(dec)), std::istreambuf_iterator<char>());
}

inline std::string hmac256(const std::string& key, const std::string& msg) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), out, &len);
    return std::string(reinterpret_cast<char*>(out), len);
}

inline bool constTimeEq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char r = 0;
    for (size_t i = 0; i < a.size(); ++i)
        r |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return r == 0;
}

// Serialize a claims object and return a signed HS256 JWT.
inline std::string sign(const Poco::JSON::Object::Ptr& claims, const std::string& secret) {
    std::ostringstream ps;
    claims->stringify(ps);
    const std::string header = R"({"alg":"HS256","typ":"JWT"})";
    std::string signingInput = b64urlEncode(header) + "." + b64urlEncode(ps.str());
    return signingInput + "." + b64urlEncode(hmac256(secret, signingInput));
}

// Verify signature (HS256, constant-time) + exp. On success fills `claims`.
// `now` is unix epoch seconds. Returns false with `err` set otherwise.
inline bool verify(const std::string& token, const std::string& secret, long now,
                   Poco::JSON::Object::Ptr& claims, std::string& err) {
    size_t p1 = token.find('.');
    size_t p2 = (p1 == std::string::npos) ? std::string::npos : token.find('.', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || token.find('.', p2 + 1) != std::string::npos) {
        err = "malformed";
        return false;
    }
    const std::string h = token.substr(0, p1);
    const std::string p = token.substr(p1 + 1, p2 - p1 - 1);
    const std::string s = token.substr(p2 + 1);

    const std::string expected = b64urlEncode(hmac256(secret, h + "." + p));
    if (!constTimeEq(expected, s)) {
        err = "bad signature";
        return false;
    }
    try {
        Poco::JSON::Parser hp;
        auto ho = hp.parse(b64urlDecode(h)).extract<Poco::JSON::Object::Ptr>();
        if (ho->optValue<std::string>("alg", "") != "HS256") {
            err = "unsupported alg";
            return false;
        }
    } catch (...) {
        err = "bad header";
        return false;
    }
    try {
        Poco::JSON::Parser pp;
        claims = pp.parse(b64urlDecode(p)).extract<Poco::JSON::Object::Ptr>();
    } catch (...) {
        err = "bad payload";
        return false;
    }
    if (claims->has("exp")) {
        long exp = static_cast<long>(claims->optValue<Poco::Int64>("exp", 0));
        if (now >= exp) {
            err = "expired";
            return false;
        }
    }
    return true;
}

}  // namespace jwt
}  // namespace httpbridge

#endif  // HTTP_BRIDGE_JWT_H
