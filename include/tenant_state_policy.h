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

// Which tenant states admit a login, and what to tell someone refused.
//
// PROPOSAL_system_administration_application.md §3.4c. Header-only and free of
// gRPC and libpq so it can be tested offline, and SHARED VERBATIM between the
// doors rather than reimplemented in each — §3.4c is explicit about why:
//
//     "The last time something was added across every door, a local shortcut in
//     one of them plus a flattened role search let a member of one tenant
//     administer another (fixed as 1.9.17). Adding a check to N doors is N
//     chances to add it subtly differently, and one chance to forget a door
//     entirely."
//
// The state itself lives in the core's global `tenants` registry and is read
// over gRPC. It is deliberately NOT cached in LDAP or duplicated per door: two
// write paths would make a tenant suspended in one place and live in another,
// reachable through whichever door read the stale copy, and that failure is
// silent.

#include <string>

namespace fileengine {
namespace tenant_state {

// The lifecycle, from §3.4c:
//
//   requested -> awaiting_dns -> provisioning -> live
//                                                 |-- suspended --+ (reversible)
//                                                 +---------------+-> decommissioning -> decommissioned
constexpr const char* kRequested = "requested";
constexpr const char* kAwaitingDns = "awaiting_dns";
constexpr const char* kProvisioning = "provisioning";
constexpr const char* kLive = "live";
constexpr const char* kSuspended = "suspended";
constexpr const char* kDecommissioning = "decommissioning";
constexpr const char* kDecommissioned = "decommissioned";

//: ONLY `live` admits a user.
//
// Everything else refuses, and two of them are worth spelling out because they
// look like edge cases and are not:
//
//   * `provisioning` — a half-built tenant must not be reachable. Its schema may
//     exist while its roles, ACLs or vhost do not.
//   * `decommissioned` — the registry row survives the data (§3.4b) precisely so
//     the name cannot be silently reused, and it must not become a way back in.
//
// Written as an allowlist of one rather than a denylist of six. A denylist is
// wrong by construction here: a state added to the enum later would be
// admitted by default, which is the opposite of what a lifecycle gate needs.
inline bool admits(const std::string& state) {
    return state == kLive;
}

//: True when the state is one this build knows about.
//
// Not the same question as `admits`. An unrecognised state must refuse (see
// below) but it should refuse as "cannot determine" rather than as "suspended",
// because the two need different operator responses.
inline bool known(const std::string& state) {
    return state == kRequested || state == kAwaitingDns || state == kProvisioning
        || state == kLive || state == kSuspended || state == kDecommissioning
        || state == kDecommissioned;
}

//: FAIL CLOSED. §3.4c property 1: "A state that cannot be determined refuses the
//: login. The failure that matters is a suspended tenant admitted because a
//: lookup errored — and 'allow on error' is how that happens."
//
// So an empty string, an unknown value, or an unreachable core all land here and
// all refuse. This function exists so a door cannot express the alternative
// without deleting it.
inline bool admits_or_refuses_unknown(const std::string& state, bool lookup_succeeded) {
    if (!lookup_succeeded) return false;
    if (!known(state)) return false;
    return admits(state);
}

//: What to tell the caller. §3.4c property 4: "A suspended tenant is not a bad
//: password, and a user told 'invalid credentials' will try again, then call
//: support, who will also not know. This is one of the few refusals where saying
//: why is right: it is the tenant's own state and the user is entitled to it."
//
// So the reason is specific per state. It names no other tenant and leaks
// nothing about anybody else — it is the caller's own tenant's status.
inline std::string refusal_reason(const std::string& state, bool lookup_succeeded) {
    if (!lookup_succeeded) {
        // Deliberately does NOT say "suspended". An operator reading this needs
        // to know the lookup failed, not to go looking for a suspension that
        // does not exist.
        return "tenant status could not be determined; access is refused until it can";
    }
    if (state == kSuspended) return "this tenant is suspended";
    if (state == kProvisioning) return "this tenant is still being provisioned";
    if (state == kRequested || state == kAwaitingDns)
        return "this tenant is not yet provisioned";
    if (state == kDecommissioning) return "this tenant is being decommissioned";
    if (state == kDecommissioned) return "this tenant has been decommissioned";
    if (!known(state)) return "tenant status is not recognised by this build; access is refused";
    return "";   // live
}

//: A machine-readable code for the response body, so a SPA can act on it
//: without parsing prose.
inline std::string refusal_code(const std::string& state, bool lookup_succeeded) {
    if (!lookup_succeeded) return "tenant_state_unknown";
    if (!known(state)) return "tenant_state_unknown";
    if (state == kLive) return "";
    return "tenant_" + state;
}

}  // namespace tenant_state
}  // namespace fileengine
