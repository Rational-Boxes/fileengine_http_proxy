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

#include "http_server.h"
#include "utils.h"

#include <Poco/Net/SSLManager.h>
#include <Poco/Net/Context.h>
#include <Poco/Net/RejectCertificateHandler.h>
#include <Poco/Net/HTTPSStreamFactory.h>

#include <csignal>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

namespace {

volatile std::sig_atomic_t g_stop = 0;
void onSignal(int) { g_stop = 1; }

// Load KEY=VALUE lines from a .env file into the process environment without
// overriding values already set in the environment.
void loadDotEnv(const std::string& path) {
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        line = webdav::trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = webdav::trim(line.substr(0, eq));
        std::string val = webdav::trim(line.substr(eq + 1));
        if (!key.empty()) setenv(key.c_str(), val.c_str(), 0);
    }
}

}  // namespace

// Register a process-wide TLS client context for outbound IdP calls. Certificate
// validation is ON (VERIFY_RELAXED against the system CA store): the OAuth design
// trusts the IdP's userinfo/token responses on the strength of validated TLS in
// place of verifying id_token JWKS signatures, so this must never be VERIFY_NONE.
void initOutboundTLS() {
    Poco::Net::initializeSSL();
    Poco::Net::HTTPSStreamFactory::registerFactory();
    Poco::SharedPtr<Poco::Net::InvalidCertificateHandler> certHandler =
        new Poco::Net::RejectCertificateHandler(false);  // false => client side
    // The 7th argument (loadDefaultCAs=true) trusts the system CA bundle.
    Poco::Net::Context::Ptr ctx = new Poco::Net::Context(
        Poco::Net::Context::TLS_CLIENT_USE, "", "", "",
        Poco::Net::Context::VERIFY_RELAXED, 9, true,
        "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    Poco::Net::SSLManager::instance().initializeClient(nullptr, certHandler, ctx);
}

int main() {
    loadDotEnv(".env");
    initOutboundTLS();

    httpbridge::Config cfg;
    cfg.http_host = webdav::getEnvOrDefault("HTTP_HOST", "0.0.0.0");
    cfg.http_port = std::stoi(webdav::getEnvOrDefault("HTTP_PORT", "8090"));
    cfg.thread_pool = std::stoi(webdav::getEnvOrDefault("HTTP_THREAD_POOL", "16"));
    cfg.monitoring_host = webdav::getEnvOrDefault("HTTP_MONITORING_HOST", "127.0.0.1");
    cfg.monitoring_port = std::stoi(webdav::getEnvOrDefault("HTTP_MONITORING_PORT", "8091"));
    {
        // Optional comma-separated client-IP allowlist for the unauthenticated
        // monitoring listener (L2). Empty = allow any host reaching the bound addr.
        std::string ips = webdav::getEnvOrDefault("HTTP_MONITORING_ALLOW_IPS", "");
        for (auto& ip : webdav::splitString(ips, ',')) {
            std::string t = webdav::trim(ip);
            if (!t.empty()) cfg.monitoring_allow_ips.push_back(t);
        }
    }
    {
        // Trusted reverse-proxy IPs/CIDRs for real-client-IP resolution (production
        // hardening). Empty = development (first X-Forwarded-For hop is trusted).
        std::string proxies = webdav::getEnvOrDefault("FILEENGINE_TRUSTED_PROXIES", "");
        for (auto& p : webdav::splitString(proxies, ',')) {
            std::string t = webdav::trim(p);
            if (!t.empty()) cfg.trusted_proxies.push_back(t);
        }
    }
    cfg.token_ttl = std::stoi(webdav::getEnvOrDefault("TOKEN_TTL_SECONDS", "900"));
    cfg.download_ticket_ttl =
        std::stoi(webdav::getEnvOrDefault("DOWNLOAD_TICKET_TTL_SECONDS", "30"));
    // Shared HS256 secret for signing/verifying bearer JWTs. Every service that
    // verifies these tokens must share this exact value.
    cfg.jwt_secret = webdav::getEnvOrDefault("FILEENGINE_JWT_SECRET", "");
    cfg.jwt_issuer = webdav::getEnvOrDefault("FILEENGINE_JWT_ISSUER", "fileengine-bridge");
    if (cfg.jwt_secret.empty()) {
        webdav::errorLog("FATAL: FILEENGINE_JWT_SECRET is not set — cannot sign session tokens");
        return 1;
    }
    cfg.max_body_bytes = std::stol(webdav::getEnvOrDefault("HTTP_MAX_BODY_BYTES", "104857600"));
    // The streaming upload route gets its own, larger allowance — see
    // Config::max_upload_bytes. Kept separate from HTTP_MAX_BODY_BYTES because
    // raising THAT to fit a video would also let a JSON body of the same size be
    // buffered whole by readBody, on any of fifteen handlers, on every worker
    // thread. 0 disables the bridge-side limit.
    cfg.max_upload_bytes = std::stol(webdav::getEnvOrDefault("HTTP_MAX_UPLOAD_BYTES", "5368709120"));

    // Resumable chunked upload. The part directory holds in-flight uploads only
    // — parts are deleted as soon as a commit reaches the core, and abandoned
    // sessions are swept after UPLOAD_TTL_SECONDS — but it does need room for
    // whatever is mid-transfer, so it is configurable rather than assumed.
    cfg.upload_dir = webdav::getEnvOrDefault("UPLOAD_SESSION_DIR", "/var/tmp/fileengine-uploads");
    cfg.upload_max_bytes = std::stoll(webdav::getEnvOrDefault("UPLOAD_MAX_BYTES", "5368709120"));
    cfg.upload_max_part_bytes = std::stol(webdav::getEnvOrDefault("UPLOAD_MAX_PART_BYTES", "134217728"));
    cfg.upload_ttl_seconds = std::stoi(webdav::getEnvOrDefault("UPLOAD_TTL_SECONDS", "86400"));
    cfg.upload_max_sessions_per_user = std::stoi(webdav::getEnvOrDefault("UPLOAD_MAX_SESSIONS_PER_USER", "8"));
    cfg.cors_origin = webdav::getEnvOrDefault("HTTP_CORS_ORIGIN", "");
    // Multi-origin allow-list (a bespoke deployment may embed FileEngine in several
    // host origins). HTTP_CORS_ORIGINS is a CSV; the legacy single HTTP_CORS_ORIGIN
    // is folded in for back-compat. Exact match only, never "*".
    for (auto& o : webdav::splitString(webdav::getEnvOrDefault("HTTP_CORS_ORIGINS", ""), ',')) {
        const std::string t = webdav::trim(o);
        if (!t.empty()) cfg.cors_origins.push_back(t);
    }
    if (!cfg.cors_origin.empty()) cfg.cors_origins.push_back(cfg.cors_origin);
    cfg.grpc_address = webdav::getEnvOrDefault("FILEENGINE_GRPC_HOST", "localhost") + ":" +
                       webdav::getEnvOrDefault("FILEENGINE_GRPC_PORT", "50051");
    cfg.oauth_redirect_base = webdav::getEnvOrDefault("OAUTH_REDIRECT_BASE", "");
    // The shared sign-in origin's DNS label. Reserved from tenancy, and served
    // to the SPA so a prebuilt image learns it at run time rather than at build.
    cfg.login_subdomain = webdav::getEnvOrDefault("LOGIN_SUBDOMAIN", "login");
    {
        // Fatal rather than a warning. A label no hostname can equal reserves
        // nothing, so the sign-in origin would resolve as an ordinary tenant
        // while signed-out users are bounced to a host that does not exist —
        // and neither symptom points at this setting. Refusing to start says it
        // once, at the only moment anyone is looking.
        std::string why;
        if (!webdav::setLoginLabel(cfg.login_subdomain, &why)) {
            webdav::errorLog("FATAL: LOGIN_SUBDOMAIN \"" + cfg.login_subdomain + "\" " + why);
            return 1;
        }
        // Report what was actually adopted, so the value in the log is the one
        // in force rather than the one someone believes they set.
        cfg.login_subdomain = webdav::loginLabel();
    }
    cfg.oauth_return_allowlist = webdav::getEnvOrDefault("OAUTH_RETURN_ALLOWLIST", "");
    cfg.oauth_state_ttl = std::stoi(webdav::getEnvOrDefault("OAUTH_STATE_TTL_SECONDS", "300"));

    // Commercial-integration token exchange (§14.2). The public key may be supplied
    // inline (INTEGRATION_PUBLIC_KEY) or via a file path (INTEGRATION_PUBLIC_KEY_FILE).
    cfg.integration_issuer = webdav::getEnvOrDefault("INTEGRATION_ISSUER", "");
    cfg.integration_audience = webdav::getEnvOrDefault(
        "INTEGRATION_AUDIENCE",
        cfg.oauth_redirect_base.empty() ? "" : cfg.oauth_redirect_base + "/v1/auth/exchange");
    cfg.integration_public_key = webdav::getEnvOrDefault("INTEGRATION_PUBLIC_KEY", "");
    if (cfg.integration_public_key.empty()) {
        const std::string keyPath = webdav::getEnvOrDefault("INTEGRATION_PUBLIC_KEY_FILE", "");
        if (!keyPath.empty()) {
            std::ifstream kf(keyPath);
            if (kf) {
                std::stringstream ss; ss << kf.rdbuf();
                cfg.integration_public_key = ss.str();
            } else {
                webdav::errorLog("WARNING: INTEGRATION_PUBLIC_KEY_FILE set but unreadable: " + keyPath);
            }
        }
    }
    for (auto& ip : webdav::splitString(webdav::getEnvOrDefault("INTEGRATION_ALLOWED_IPS", ""), ',')) {
        const std::string t = webdav::trim(ip);
        if (!t.empty()) cfg.integration_allowed_ips.push_back(t);
    }
    cfg.sso_handoff_ttl = std::stoi(webdav::getEnvOrDefault("SSO_HANDOFF_TTL_SECONDS", "60"));
    cfg.integration_allow_service =
        webdav::getEnvOrDefault("INTEGRATION_ALLOW_SERVICE", "false") == "true";
    for (auto& r : webdav::splitString(webdav::getEnvOrDefault("INTEGRATION_SERVICE_ROLES", ""), ',')) {
        const std::string t = webdav::trim(r);
        if (!t.empty()) cfg.integration_service_roles.push_back(t);
    }
    if (!cfg.integration_issuer.empty() && !cfg.integration_public_key.empty()) {
        webdav::errorLog("Integration token exchange ENABLED for issuer '" + cfg.integration_issuer + "'");
    }

    // Two-factor auth orchestration (PROPOSAL §4.6). Disabled unless MFA_ENABLED
    // and the ldap_manager internal API URL + shared secret are configured.
    {
        std::string me = webdav::getEnvOrDefault("MFA_ENABLED", "");
        cfg.mfa_enabled = (me == "true" || me == "1" || me == "yes" || me == "on");
    }
    cfg.ldap_manager_url = webdav::getEnvOrDefault("LDAP_MANAGER_URL", "");
    cfg.mfa_internal_secret = webdav::getEnvOrDefault("MFA_INTERNAL_SECRET", "");
    cfg.mfa_challenge_ttl = std::stoi(webdav::getEnvOrDefault("MFA_CHALLENGE_TTL_SECONDS", "300"));
    if (cfg.mfa_enabled && (cfg.ldap_manager_url.empty() || cfg.mfa_internal_secret.empty())) {
        webdav::errorLog("FATAL: MFA_ENABLED but LDAP_MANAGER_URL / MFA_INTERNAL_SECRET is unset "
                         "— refusing to start with an unenforceable 2FA gate");
        return 1;
    }

    // Durable audit emission — shares the core's Redis broker + stream names.
    {
        std::string ae = webdav::getEnvOrDefault("FILEENGINE_AUDIT_ENABLED", "");
        cfg.audit_enabled = (ae == "true" || ae == "1" || ae == "yes" || ae == "on");
    }
    cfg.redis_host = webdav::getEnvOrDefault("FILEENGINE_REDIS_HOST", "localhost");
    cfg.redis_port = std::stoi(webdav::getEnvOrDefault("FILEENGINE_REDIS_PORT", "6379"));
    cfg.redis_password = webdav::getEnvOrDefault("FILEENGINE_REDIS_PASSWORD",
                             webdav::getEnvOrDefault("REDDIS_PASSWORD", ""));
    cfg.redis_db = std::stoi(webdav::getEnvOrDefault("FILEENGINE_REDIS_DB", "0"));
    cfg.audit_stream = webdav::getEnvOrDefault("FILEENGINE_AUDIT_STREAM", "fileengine:audit");
    cfg.audit_stream_maxlen = std::stoll(webdav::getEnvOrDefault("FILEENGINE_AUDIT_STREAM_MAXLEN", "1000000"));

    // WebDAV session-presence gate (PROPOSAL §14): when enabled, login/refresh
    // record the user's Web-UI session in Redis and logout removes it.
    {
        std::string we = webdav::getEnvOrDefault("WEBDAV_IP_BINDING_ENABLED", "");
        cfg.webdav_ip_binding_enabled = (we == "1" || we == "true" || we == "yes" || we == "on");
    }
    cfg.webdav_session_ttl_default = std::stoi(webdav::getEnvOrDefault("WEBDAV_IP_BIND_TTL_SECONDS", "43200"));

    // Revoked-token denylist (shared, in the same Redis). ON by default: a
    // stateless session token that outlives its own sign-out is a defect, not a
    // feature to opt into, and every deployment that runs this bridge already
    // runs the Redis it needs. A deployment that genuinely cannot must turn it
    // off deliberately — the startup gate below refuses to pretend.
    {
        std::string re = webdav::getEnvOrDefault("AUTH_REVOCATION_ENABLED", "true");
        cfg.revocation_enabled = (re == "1" || re == "true" || re == "yes" || re == "on");
        // How long a verdict is cached, and therefore the worst-case lag between
        // signing out and the token dying. 0 asks Redis on every request.
        cfg.revocation_cache_ttl =
            std::stoi(webdav::getEnvOrDefault("AUTH_REVOCATION_CACHE_TTL_SECONDS", "5"));
        // Honour tokens whose revocation status cannot be established. Trades the
        // sign-out guarantee for availability during a Redis outage; off unless
        // asked for, because failing open here silently restores the old bug.
        std::string fo = webdav::getEnvOrDefault("AUTH_REVOCATION_FAIL_OPEN", "");
        cfg.revocation_fail_open = (fo == "1" || fo == "true" || fo == "yes" || fo == "on");
    }

    auto grpc = std::make_shared<webdav::GRPCClientWrapper>(cfg.grpc_address);
    auto ldap = std::make_shared<webdav::LDAPAuthenticator>(
        webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_PASSWORD", "admin"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com"),
        // Read-only replica directory for failover (empty = disabled; see
        // REPLICATION_FAILOVER.md).
        webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT_REPLICA", ""),
        std::stod(webdav::getEnvOrDefault("FILEENGINE_FAILOVER_COOLDOWN_S", "30")));

    httpbridge::HttpBridgeServer server(cfg, grpc, ldap);

    // A-i: fail loudly rather than silently drop the audit guarantee. If auditing
    // is enabled but this process cannot publish (built without hiredis, or Redis
    // unreachable at boot), refuse to start — "enabled but unable to record" must
    // not run as if it were auditing.
    if (!server.auditReady()) {
        webdav::errorLog("FATAL: FILEENGINE_AUDIT_ENABLED=true but the audit log is "
                         "unavailable (built without hiredis, or Redis unreachable). Refusing to start.");
        Poco::Net::uninitializeSSL();
        return 1;
    }

    // Same gate, same reasoning, for sign-out. Running with revocation enabled but
    // no reachable denylist would mean every logout reported success while the
    // token stayed live — the exact failure this feature exists to end, and
    // invisible from the outside. Fail-open deployments have already accepted
    // that trade explicitly, so they are not held back here.
    if (!server.revocationReady()) {
        webdav::errorLog("FATAL: AUTH_REVOCATION_ENABLED=true but the token denylist is "
                         "unavailable (built without hiredis, or Redis unreachable). "
                         "Refusing to start: sign-out could not be enforced. Set "
                         "AUTH_REVOCATION_FAIL_OPEN=true to run anyway, or "
                         "AUTH_REVOCATION_ENABLED=false to disable revocation.");
        Poco::Net::uninitializeSSL();
        return 1;
    }

    server.start();

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    while (!g_stop) {
        struct timespec ts{1, 0};
        nanosleep(&ts, nullptr);
    }

    webdav::infoLog("Shutting down HTTP bridge");
    server.stop();
    Poco::Net::uninitializeSSL();
    return 0;
}
