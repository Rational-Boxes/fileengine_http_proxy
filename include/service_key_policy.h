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

#pragma once

// The rules for a session minted from a generated key:secret (scope "api").
//
// Header-only and free of LDAP/HTTP so they can be tested offline, like
// tenant_role_policy.h. The flow they govern: the key is presented once at
// POST /v1/auth/token, an ordinary session bearer comes back, and
// POST /v1/auth/refresh renews it only while the key is still live and
// unrotated. Each rule below is one way that flow could quietly widen what a
// key is good for.

#include <map>
#include <string>
#include <vector>

namespace fileengine {
namespace service_key {

//: The public key_id prefix ldap_manager mints (service_cred.py _KEY_PREFIX).
//: A directory uid never starts with it, so it routes the Basic credential to
//: the key path instead of an LDAP bind.
constexpr const char* kKeyIdPrefix = "fesk_";

//: The amr value recorded for a key session.
constexpr const char* kAmr = "svc";

inline bool isServiceKeyId(const std::string& s) {
    return s.rfind(kKeyIdPrefix, 0) == 0;
}

//: A key is bound to ONE tenant, so its session carries that tenant's roles and
//: nothing else. With the user's full {tenant:[roles]} map, X-Tenant — and every
//: downstream door that reads the map — would let a single-tenant key act in all
//: of the user's tenants.
inline std::map<std::string, std::vector<std::string>>
rolesForKeySession(const std::map<std::string, std::vector<std::string>>& byTenant,
                   const std::string& tenant) {
    std::map<std::string, std::vector<std::string>> only;
    auto it = byTenant.find(tenant);
    if (it != byTenant.end()) only.insert(*it);
    return only;
}

//: How an ldap_manager /internal/service-cred/* answer is read.
enum class KeyVerdict {
    Valid,          // 200 with a uid and a generation
    Invalid,        // 401: the credential is no good — tell the client 401
    Unavailable,    // anything else: this deployment's fault — tell the client 503
};

//: 401 is ldap_manager's ONLY "this credential is no good" answer. A 403 (wrong
//: internal secret), 404 (internal API off), 422 or 5xx is a configuration or
//: availability fault, and reporting it as a bad key would send the user off to
//: regenerate a credential that was never the problem. A 200 that lacks a uid
//: or a generation (an ldap_manager too old to send one) cannot support a safe
//: refresh, so it is not treated as valid either.
inline KeyVerdict classifyVerifyAnswer(int httpStatus, const std::string& uid,
                                       const std::string& generation) {
    if (httpStatus == 401) return KeyVerdict::Invalid;
    if (httpStatus != 200) return KeyVerdict::Unavailable;
    if (uid.empty() || generation.empty()) return KeyVerdict::Unavailable;
    return KeyVerdict::Valid;
}

//: Whether a key session may be renewed. The key must still verify (status
//: check), for the SAME user, with the SAME secret generation the session was
//: minted under — rotating in place keeps the key_id, so without the
//: generation a session from the old secret could be renewed forever — and the
//: user must still be a member of the key's tenant.
inline bool mayRefresh(KeyVerdict verdict,
                       const std::string& statusUid, const std::string& statusGeneration,
                       const std::string& sessionUser, const std::string& sessionGeneration,
                       const std::vector<std::string>& userTenants,
                       const std::string& sessionTenant) {
    if (verdict != KeyVerdict::Valid) return false;
    if (statusUid != sessionUser) return false;
    if (sessionGeneration.empty() || statusGeneration != sessionGeneration) return false;
    for (const auto& t : userTenants)
        if (t == sessionTenant) return true;
    return false;
}

}  // namespace service_key

namespace session_amr {

//: A session whose amr carries any of these has satisfied a second factor (or
//: federated the check to an IdP) and may operate in any 2FA-requiring tenant.
//: A password-only session (["pwd"]) has not. "svc" is a session minted from a
//: generated key:secret: a 256-bit secret issued to a signed-in user for one
//: tenant — the standing it already has on the WebDAV/MCP doors, which accept it
//: in a 2FA-requiring tenant without a challenge.
inline bool satisfiesSecondFactor(const std::vector<std::string>& amr) {
    for (const auto& m : amr)
        if (m == "otp" || m == "totp" || m == "email" || m == "recovery" || m == "oauth" ||
            m == service_key::kAmr)
            return true;
    return false;
}

}  // namespace session_amr
}  // namespace fileengine
