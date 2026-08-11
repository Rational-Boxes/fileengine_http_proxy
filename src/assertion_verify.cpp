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

#include "assertion_verify.h"

#include "jwt.h"  // jwt::b64urlDecode

#include <ctime>

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/Dynamic/Var.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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

// `aud` may be a single string or an array of strings (RFC 7519); accept when
// expected appears.
bool audienceMatches(const Object::Ptr& claims, const std::string& expected) {
    if (!claims || !claims->has("aud")) return false;
    Poco::Dynamic::Var v = claims->get("aud");
    if (v.isString()) return v.convert<std::string>() == expected;
    try {
        auto arr = claims->getArray("aud");
        if (arr) {
            for (std::size_t i = 0; i < arr->size(); ++i) {
                if (arr->getElement<std::string>(static_cast<unsigned>(i)) == expected) return true;
            }
        }
    } catch (...) {
    }
    return false;
}

EVP_PKEY* loadPublicKeyPem(const std::string& pem) {
    if (pem.empty()) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return key;  // caller frees
}

// RS256: RSA-PKCS#1v1.5 over SHA-256("<header>.<payload>").
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

// ES256: the JOSE signature is the raw 64-byte concatenation r||s (P-256). OpenSSL
// expects a DER-encoded ECDSA_SIG, so convert before verifying over SHA-256.
bool es256Verify(EVP_PKEY* pkey, const std::string& signing_input, const std::string& jose_sig) {
    if (jose_sig.size() != 64) return false;  // P-256 => 32-byte r + 32-byte s
    const auto* rb = reinterpret_cast<const unsigned char*>(jose_sig.data());
    BIGNUM* r = BN_bin2bn(rb, 32, nullptr);
    BIGNUM* s = BN_bin2bn(rb + 32, 32, nullptr);
    ECDSA_SIG* sig = ECDSA_SIG_new();
    bool ok = false;
    if (r && s && sig && ECDSA_SIG_set0(sig, r, s) == 1) {
        // set0 took ownership of r and s; ECDSA_SIG_free frees them below.
        unsigned char* der = nullptr;
        int der_len = i2d_ECDSA_SIG(sig, &der);
        if (der_len > 0) {
            EVP_MD_CTX* md = EVP_MD_CTX_new();
            if (md && EVP_DigestVerifyInit(md, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
                ok = EVP_DigestVerify(
                         md, der, static_cast<size_t>(der_len),
                         reinterpret_cast<const unsigned char*>(signing_input.data()),
                         signing_input.size()) == 1;
            }
            EVP_MD_CTX_free(md);
            OPENSSL_free(der);
        }
        ECDSA_SIG_free(sig);
    } else {
        BN_free(r);
        BN_free(s);
        if (sig) ECDSA_SIG_free(sig);
    }
    return ok;
}

}  // namespace

bool verifyIntegrationAssertion(const std::string& assertion,
                                const std::string& expected_issuer,
                                const std::string& expected_audience,
                                const std::string& pem_public_key,
                                IntegrationClaims& out,
                                std::string& err,
                                long now_epoch) {
    std::string h, p, sig;
    if (!split3(assertion, h, p, sig)) {
        err = "malformed assertion";
        return false;
    }

    Object::Ptr hdr, claims;
    try {
        Poco::JSON::Parser hp;
        hdr = hp.parse(jwt::b64urlDecode(h)).extract<Object::Ptr>();
        Poco::JSON::Parser pp;
        claims = pp.parse(jwt::b64urlDecode(p)).extract<Object::Ptr>();
    } catch (...) {
        err = "assertion header/payload not valid JSON";
        return false;
    }

    const std::string alg = strField(hdr, "alg");
    if (alg != "RS256" && alg != "ES256") {
        err = "unsupported assertion alg (expected RS256 or ES256)";
        return false;
    }

    EVP_PKEY* pkey = loadPublicKeyPem(pem_public_key);
    if (!pkey) {
        err = "could not load integration public key (PEM)";
        return false;
    }
    const std::string signing_input = h + "." + p;
    const std::string sig_raw = jwt::b64urlDecode(sig);
    const bool sig_ok = (alg == "RS256") ? rs256Verify(pkey, signing_input, sig_raw)
                                         : es256Verify(pkey, signing_input, sig_raw);
    EVP_PKEY_free(pkey);
    if (!sig_ok) {
        err = "assertion signature verification failed";
        return false;
    }

    // Signature verified — the claims below are the integration's authoritative claims.
    const std::string iss = strField(claims, "iss");
    if (iss.empty() || iss != expected_issuer) {
        err = "assertion issuer mismatch";
        return false;
    }
    if (!audienceMatches(claims, expected_audience)) {
        err = "assertion audience mismatch";
        return false;
    }
    const long exp = numField(claims, "exp");
    if (exp == 0) {
        err = "assertion missing exp";
        return false;
    }
    const long now = now_epoch ? now_epoch : static_cast<long>(std::time(nullptr));
    if (now > exp + 60) {  // 60s leeway for clock skew
        err = "assertion expired";
        return false;
    }
    const std::string sub = strField(claims, "sub");
    if (sub.empty()) {
        err = "assertion missing sub";
        return false;
    }

    out.issuer = iss;
    out.subject = sub;
    out.tenant = strField(claims, "tenant");
    out.scope = strField(claims, "scope");
    out.jti = strField(claims, "jti");
    out.token_type = strField(claims, "token_type");
    out.expires_at = exp;
    // `amr` (RFC 8176): the auth methods the integration asserts for this user (e.g.
    // ["pwd","otp"]). Propagated into the minted session so an integration that already
    // 2FA'd the user against the shared directory carries that trust forward.
    out.amr.clear();
    if (claims->has("amr")) {
        try {
            auto arr = claims->getArray("amr");
            if (arr)
                for (std::size_t i = 0; i < arr->size(); ++i)
                    out.amr.push_back(arr->getElement<std::string>(static_cast<unsigned>(i)));
        } catch (...) {
        }
    }
    return true;
}

}  // namespace httpbridge
