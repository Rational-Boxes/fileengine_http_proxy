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

#include "oidc_verify.h"

#include "jwt.h"  // jwt::b64urlDecode

#include <ctime>

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Dynamic/Var.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

namespace httpbridge {

namespace {

using Object = Poco::JSON::Object;

// Split "a.b.c" into its three non-empty parts (rejects any other shape).
bool split3(const std::string& s, std::string& h, std::string& p, std::string& sig) {
    auto d1 = s.find('.');
    if (d1 == std::string::npos) return false;
    auto d2 = s.find('.', d1 + 1);
    if (d2 == std::string::npos) return false;
    if (s.find('.', d2 + 1) != std::string::npos) return false;  // more than 3 parts
    h = s.substr(0, d1);
    p = s.substr(d1 + 1, d2 - d1 - 1);
    sig = s.substr(d2 + 1);
    return !h.empty() && !p.empty() && !sig.empty();
}

std::string strField(const Object::Ptr& o, const std::string& k) {
    if (!o || !o->has(k) || o->isNull(k)) return "";
    try {
        return o->getValue<std::string>(k);
    } catch (...) {
        return "";
    }
}

long numField(const Object::Ptr& o, const std::string& k) {
    if (!o || !o->has(k) || o->isNull(k)) return 0;
    try {
        return static_cast<long>(o->getValue<double>(k));
    } catch (...) {
        return 0;
    }
}

bool boolField(const Object::Ptr& o, const std::string& k) {
    if (!o || !o->has(k)) return false;
    Poco::Dynamic::Var v = o->get(k);
    try {
        if (v.isBoolean()) return v.convert<bool>();
        if (v.isString()) {
            std::string s = v.convert<std::string>();
            return s == "true" || s == "1";
        }
        return v.convert<bool>();
    } catch (...) {
        return false;
    }
}

// `aud` may be a single string or an array of strings (RFC 7519); accept when
// client_id appears.
bool audienceMatches(const Object::Ptr& claims, const std::string& client_id) {
    if (!claims || !claims->has("aud")) return false;
    Poco::Dynamic::Var v = claims->get("aud");
    if (v.isString()) return v.convert<std::string>() == client_id;
    try {
        auto arr = claims->getArray("aud");
        if (arr) {
            for (std::size_t i = 0; i < arr->size(); ++i) {
                if (arr->getElement<std::string>(static_cast<unsigned>(i)) == client_id) return true;
            }
        }
    } catch (...) {
    }
    return false;
}

// Build an RSA public EVP_PKEY from base64url modulus (n) + exponent (e).
EVP_PKEY* rsaPubKeyFromJwk(const std::string& n_b64, const std::string& e_b64) {
    std::string n_raw = jwt::b64urlDecode(n_b64);
    std::string e_raw = jwt::b64urlDecode(e_b64);
    if (n_raw.empty() || e_raw.empty()) return nullptr;

    BIGNUM* n = BN_bin2bn(reinterpret_cast<const unsigned char*>(n_raw.data()),
                          static_cast<int>(n_raw.size()), nullptr);
    BIGNUM* e = BN_bin2bn(reinterpret_cast<const unsigned char*>(e_raw.data()),
                          static_cast<int>(e_raw.size()), nullptr);
    EVP_PKEY* pkey = nullptr;
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    if (n && e && bld &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) &&
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) &&
        (params = OSSL_PARAM_BLD_to_param(bld)) &&
        (ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr)) &&
        EVP_PKEY_fromdata_init(ctx) > 0) {
        if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            pkey = nullptr;
        }
    }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    BN_free(n);
    BN_free(e);
    return pkey;  // caller frees
}

// RS256 verify: RSA-PKCS#1v1.5 over SHA-256("<header>.<payload>").
bool rs256Verify(EVP_PKEY* pkey, const std::string& signing_input, const std::string& sig_raw) {
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    bool ok = false;
    if (md && EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(
                 md,
                 reinterpret_cast<const unsigned char*>(sig_raw.data()), sig_raw.size(),
                 reinterpret_cast<const unsigned char*>(signing_input.data()),
                 signing_input.size()) == 1;
    }
    EVP_MD_CTX_free(md);
    return ok;
}

}  // namespace

bool verifyIdToken(const std::string& id_token, const std::string& issuer,
                   const std::string& client_id, const std::string& expected_nonce,
                   const std::string& jwks_json, IdTokenClaims& out, std::string& err,
                   long now_epoch) {
    std::string h, p, sig;
    if (!split3(id_token, h, p, sig)) {
        err = "malformed id_token";
        return false;
    }

    Object::Ptr hdr, claims;
    try {
        Poco::JSON::Parser hp;
        hdr = hp.parse(jwt::b64urlDecode(h)).extract<Object::Ptr>();
        Poco::JSON::Parser pp;
        claims = pp.parse(jwt::b64urlDecode(p)).extract<Object::Ptr>();
    } catch (...) {
        err = "id_token header/payload not valid JSON";
        return false;
    }
    if (strField(hdr, "alg") != "RS256") {
        err = "unsupported id_token alg (expected RS256)";
        return false;
    }
    const std::string kid = strField(hdr, "kid");

    // Find the signing key in the JWKS (by kid when present; else the sole RSA key).
    Object::Ptr jwk;
    try {
        Poco::JSON::Parser jp;
        auto root = jp.parse(jwks_json).extract<Object::Ptr>();
        auto keys = root->getArray("keys");
        if (keys) {
            for (std::size_t i = 0; i < keys->size(); ++i) {
                auto k = keys->getObject(static_cast<unsigned>(i));
                if (!k || strField(k, "kty") != "RSA") continue;
                const std::string kkid = strField(k, "kid");
                if (!kid.empty() && !kkid.empty() && kkid != kid) continue;
                jwk = k;
                if (!kid.empty() && kkid == kid) break;  // exact match wins
            }
        }
    } catch (...) {
        err = "invalid JWKS document";
        return false;
    }
    if (!jwk) {
        err = "no matching JWKS key (kid=" + kid + ")";
        return false;
    }

    EVP_PKEY* pkey = rsaPubKeyFromJwk(strField(jwk, "n"), strField(jwk, "e"));
    if (!pkey) {
        err = "could not build RSA key from JWK";
        return false;
    }
    const bool sig_ok = rs256Verify(pkey, h + "." + p, jwt::b64urlDecode(sig));
    EVP_PKEY_free(pkey);
    if (!sig_ok) {
        err = "id_token signature verification failed";
        return false;
    }

    // Claims. Signature is verified, so these are the IdP's authoritative claims.
    if (strField(claims, "iss") != issuer) {
        err = "id_token issuer mismatch";
        return false;
    }
    if (!audienceMatches(claims, client_id)) {
        err = "id_token audience mismatch";
        return false;
    }
    const long now = now_epoch ? now_epoch : static_cast<long>(std::time(nullptr));
    const long exp = numField(claims, "exp");
    if (exp && now > exp + 60) {  // 60s leeway for clock skew
        err = "id_token expired";
        return false;
    }
    if (!expected_nonce.empty() && strField(claims, "nonce") != expected_nonce) {
        err = "id_token nonce mismatch";
        return false;
    }

    out.subject = strField(claims, "sub");
    out.email = strField(claims, "email");
    out.email_verified = boolField(claims, "email_verified");
    return true;
}

}  // namespace httpbridge
