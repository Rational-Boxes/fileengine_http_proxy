// Download and playback tickets — the bridge's two URL-borne credentials.
//
// A browser cannot attach an Authorization header to a navigation (a download
// that should stream to disk) or to a <video src> (a player that issues its own
// Range requests), so both carry the credential in the query string. Anything in
// a URL ends up in history, referrers and proxy logs, so a ticket is built to be
// nearly useless if it leaks:
//
//   * scoped to ONE file uid (`dl`) — it opens nothing else;
//   * short-lived — seconds for a download, and a playback ticket is capped at
//     kPlaybackTicketMaxTtl whatever is configured (decided 2026-10-03: a
//     viewing outlives seconds, but nothing very long is served from here);
//   * typed (`typ`), and authenticate() refuses EVERY ticket type as a bearer,
//     so a leaked URL can never be replayed as a session;
//   * bound to the session that minted it (`sid`), so signing out revokes the
//     tickets it handed out instead of leaving them live for their lifetime.
//
// It carries the caller's own identity and roles: a narrowed, time-boxed
// re-presentation of authority the caller already had, never an escalation. The
// core still enforces READ on the bytes.
#pragma once
#include <algorithm>
#include <string>
#include <vector>

#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>

namespace httpbridge {

//: The longest a playback ticket may live: 30 minutes.
constexpr long kPlaybackTicketMaxTtl = 1800;

inline bool isTicketType(const std::string& typ) {
    return typ == "download" || typ == "playback";
}

// The configured playback lifetime, clamped to the cap. Unset or nonsensical
// means the cap itself — never "unlimited".
inline long clampPlaybackTtl(long configured) {
    if (configured <= 0) return kPlaybackTicketMaxTtl;
    return std::min(configured, kPlaybackTicketMaxTtl);
}

inline Poco::JSON::Object::Ptr buildTicketClaims(
    const std::string& issuer, const std::string& subject, const std::string& tenant,
    const std::vector<std::string>& roles, const std::string& uid,
    const std::string& typ, const std::string& sid, long now, long ttl) {
    Poco::JSON::Object::Ptr c = new Poco::JSON::Object();
    c->set("iss", issuer);
    c->set("sub", subject);
    c->set("tenant", tenant);
    c->set("iat", static_cast<Poco::Int64>(now));
    c->set("exp", static_cast<Poco::Int64>(now + ttl));
    c->set("typ", typ);
    c->set("dl", uid);
    if (!sid.empty()) c->set("sid", sid);
    Poco::JSON::Array::Ptr arr = new Poco::JSON::Array();
    for (const auto& r : roles) arr->add(r);
    Poco::JSON::Object::Ptr rolesObj = new Poco::JSON::Object();
    rolesObj->set(tenant, arr);      // {tenant: [roles]} — the same shape as a session
    c->set("roles", rolesObj);
    return c;
}

enum class TicketCheck { Ok, WrongType, WrongUid };

// The ticket-specific checks on already-VERIFIED claims (signature and expiry
// are jwt::verify's job). The uid check is what keeps a ticket from being a
// general bearer that merely happens to travel in a query string.
inline TicketCheck checkTicketClaims(const Poco::JSON::Object::Ptr& claims,
                                     const std::string& uid) {
    if (!isTicketType(claims->optValue<std::string>("typ", std::string())))
        return TicketCheck::WrongType;
    if (claims->optValue<std::string>("dl", std::string()) != uid)
        return TicketCheck::WrongUid;
    return TicketCheck::Ok;
}

}  // namespace httpbridge
