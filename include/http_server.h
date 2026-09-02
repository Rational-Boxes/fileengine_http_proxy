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

#ifndef HTTP_BRIDGE_HTTP_SERVER_H
#define HTTP_BRIDGE_HTTP_SERVER_H

#include <memory>
#include <string>

#include <Poco/Net/HTTPServer.h>
#include <Poco/ThreadPool.h>

#include "audit_publisher.h"
#include "session_store.h"
#include "grpc_client_wrapper.h"
#include "ldap_authenticator.h"
#include "oauth_provider.h"
#include "oauth_state_store.h"
#include "token_store.h"
#include "token_denylist.h"

namespace httpbridge {

struct Config {
    std::string http_host = "0.0.0.0";
    int http_port = 8090;
    int thread_pool = 16;
    // Dedicated reporter listener (pool usage / health). Unauthenticated, so it
    // binds to loopback by default — protect it by network isolation, not auth.
    std::string monitoring_host = "127.0.0.1";
    int monitoring_port = 8091;
    std::vector<std::string> monitoring_allow_ips;  // optional client-IP allowlist for the monitor (security review L2)
    // Trusted reverse-proxy IPs/CIDRs (FILEENGINE_TRUSTED_PROXIES). When set, the
    // real client IP is resolved from X-Forwarded-For only via a trusted proxy peer
    // (right-most untrusted hop), hardening the MFA IP binding + audit source_addr
    // against XFF spoofing. Empty = development (trust the first XFF hop). See
    // client_ip.h.
    std::vector<std::string> trusted_proxies;
    // Bearer session tokens are signed HS256 JWTs. token_ttl is deliberately
    // SHORT: a token is re-minted periodically (POST /v1/auth/refresh) from live
    // LDAP, so role changes take effect within ~the refresh interval and a token
    // that stops being refreshed (access revoked) expires quickly.
    int token_ttl = 900;                     // JWT lifetime (s)
    // Download tickets ride in a URL, so they are scoped to one file uid and
    // live for seconds — long enough for the browser to follow a navigation,
    // far too short to be worth harvesting from a log. See mintDownloadTicket.
    int download_ticket_ttl = 30;            // download ticket lifetime (s)
    std::string login_subdomain = "login";   // shared sign-in origin's DNS label
    std::string jwt_secret;                  // HS256 shared secret (REQUIRED)
    std::string jwt_issuer = "fileengine-bridge";
    long max_body_bytes = 100L * 1024 * 1024;  // 100 MiB request-body cap
    // Separate allowance for the ONE route that streams. PUT /v1/files/{uid}/
    // content reads 256 KiB at a time into the gRPC stream and never holds the
    // body, so the limit that protects the buffered JSON handlers is the wrong
    // limit for it — and it was the binding one: nginx allows 1 GiB in front,
    // the bridge refused at 100 MiB, so a video failed with "request body too
    // large" a tenth of the way to the edge's actual ceiling. 0 = no bridge
    // limit, leaving the edge (client_max_body_size) as the ceiling.
    long max_upload_bytes = 5368709120L;  // 5 GiB
    std::string cors_origin;                   // legacy single origin (HTTP_CORS_ORIGIN)
    std::vector<std::string> cors_origins;     // allow-list (HTTP_CORS_ORIGINS CSV + the legacy one); exact match, never "*"
    std::string grpc_address = "localhost:50051";

    // OAuth2 / OIDC login (BFF). Empty oauth_redirect_base disables OAuth routes.
    std::string oauth_redirect_base;        // public base URL of the bridge
    std::string oauth_return_allowlist;     // CSV of permitted SPA return-URL prefixes
    int oauth_state_ttl = 300;              // pending-authorization lifetime (s)

    // Commercial-integration token exchange (RFC 7523; §14.2). ONE integration per
    // bespoke deployment: FileEngine imports only the integration's PUBLIC key.
    // Empty integration_issuer or integration_public_key disables POST
    // /v1/auth/exchange (route returns 404).
    std::string integration_issuer;            // expected assertion `iss` (the integration id)
    std::string integration_public_key;        // imported RS256/ES256 PUBLIC key (PEM, inline)
    std::string integration_audience;          // expected assertion `aud` (the exchange endpoint id)
    std::vector<std::string> integration_allowed_ips;  // optional client-IP allow-list (empty = disabled); echoed as `aip`
    bool integration_allow_service = false;            // permit non-delegated token_type:service exchanges
    std::vector<std::string> integration_service_roles;  // roles a service token carries (NOT from LDAP)

    // Deep-link SSO hand-off (§5.5): a host with a live session mints a short-lived,
    // single-use code; the SPA redeems it for a fresh session. TTL kept SHORT.
    int sso_handoff_ttl = 60;                          // hand-off code lifetime (s)

    // Two-factor auth orchestration (PROPOSAL §4.6). When mfa_enabled, a
    // password-verified login that ldap_manager reports as MFA-required receives a
    // short-lived, IP-bound `mfa_pending` challenge token instead of a full
    // session; POST /v1/auth/2fa completes it. Verification is delegated to
    // ldap_manager's internal API (shared MFA_INTERNAL_SECRET). Fail-closed: if the
    // required-check cannot reach ldap_manager, no session is issued.
    bool mfa_enabled = false;
    std::string ldap_manager_url;            // e.g. http://127.0.0.1:8093 (internal 2FA API)
    std::string mfa_internal_secret;         // X-Internal-Auth for /internal/2fa/*
    int mfa_challenge_ttl = 300;             // mfa_pending token lifetime (s)

    // Durable audit emission (usage_logging_and_auditing §5). Shares the core's
    // Redis broker + stream; login_success/login_failure emit from this door.
    bool audit_enabled = false;
    std::string redis_host = "localhost";
    int redis_port = 6379;
    std::string redis_password;
    int redis_db = 0;
    std::string audit_stream = "fileengine:audit";
    long long audit_stream_maxlen = 1000000;

    // WebDAV session-presence gate (PROPOSAL §14). When enabled, a full session
    // mint (login / refresh) records the user's presence in Redis and logout
    // removes it, so webdav_bridge can require a live Web-UI session for external
    // WebDAV. Shares the same Redis broker as auditing. The per-tenant TTL is
    // fetched from ldap_manager (/internal/webdav/session-ttl); this default is the
    // fallback when that lookup is unavailable.
    bool webdav_ip_binding_enabled = false;
    int webdav_session_ttl_default = 43200;  // 12h fallback score window

    // Revoked-token denylist, keyed by jti, in the same Redis. Session tokens are
    // stateless JWTs, so without this DELETE /v1/auth/token ends nothing: the
    // token keeps working, in every other copy of it, until exp. See
    // token_denylist.h for the fail-closed reasoning and the cache trade-off.
    bool revocation_enabled = true;
    int revocation_cache_ttl = 5;       // seconds a verdict is trusted = revocation latency
    bool revocation_fail_open = false;  // honour a token whose status is unknown
};

// Lightweight, concurrent REST front-end over the FileEngine gRPC FileService.
// One server owns one shared gRPC wrapper and one LDAP authenticator; Poco's
// HTTPServer dispatches each connection on a worker-pool thread.
class HttpBridgeServer {
public:
    HttpBridgeServer(const Config& cfg,
                     std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                     std::shared_ptr<webdav::LDAPAuthenticator> ldap);
    ~HttpBridgeServer();

    void start();
    void stop();

    // True unless auditing is enabled but the process cannot publish (built
    // without hiredis, or Redis unreachable). Startup gate + probe helper (A-i).
    bool auditReady() { return !audit_->enabled() || audit_->healthy(); }

    // True unless revocation is enabled but the denylist cannot be reached
    // (built without hiredis, or Redis unreachable). Same startup gate as
    // auditing, for the same reason: "enabled but unable to revoke" must not run
    // as though sign-out worked. Fail-open deployments have said they would
    // rather serve requests, so they are not gated.
    bool revocationReady() {
        return !denylist_->enabled() || denylist_->failOpen() || denylist_->healthy();
    }

private:
    Config cfg_;
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
    std::shared_ptr<TokenStore> tokens_;
    std::shared_ptr<OAuthProvider> oauth_;
    std::shared_ptr<OAuthStateStore> oauth_states_;
    std::shared_ptr<AuditPublisher> audit_;
    std::shared_ptr<SessionStore> sessions_;
    std::shared_ptr<TokenDenylist> denylist_;
    // Dedicated worker pool sized to cfg_.thread_pool. Declared before server_ so
    // it is destroyed *after* the server stops using it.
    std::unique_ptr<Poco::ThreadPool> pool_;
    std::unique_ptr<Poco::Net::HTTPServer> server_;
    // Dedicated reporter: its own single held-back thread + listener, so pool
    // usage / health are answerable even when every worker thread is mid-transfer.
    std::unique_ptr<Poco::ThreadPool> monitor_pool_;
    std::unique_ptr<Poco::Net::HTTPServer> monitor_server_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_HTTP_SERVER_H
