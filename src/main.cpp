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
    cfg.token_ttl = std::stoi(webdav::getEnvOrDefault("TOKEN_TTL_SECONDS", "900"));
    // Shared HS256 secret for signing/verifying bearer JWTs. Every service that
    // verifies these tokens must share this exact value.
    cfg.jwt_secret = webdav::getEnvOrDefault("FILEENGINE_JWT_SECRET", "");
    cfg.jwt_issuer = webdav::getEnvOrDefault("FILEENGINE_JWT_ISSUER", "fileengine-bridge");
    if (cfg.jwt_secret.empty()) {
        webdav::errorLog("FATAL: FILEENGINE_JWT_SECRET is not set — cannot sign session tokens");
        return 1;
    }
    cfg.max_body_bytes = std::stol(webdav::getEnvOrDefault("HTTP_MAX_BODY_BYTES", "104857600"));
    cfg.cors_origin = webdav::getEnvOrDefault("HTTP_CORS_ORIGIN", "");
    cfg.grpc_address = webdav::getEnvOrDefault("FILEENGINE_GRPC_HOST", "localhost") + ":" +
                       webdav::getEnvOrDefault("FILEENGINE_GRPC_PORT", "50051");
    cfg.oauth_redirect_base = webdav::getEnvOrDefault("OAUTH_REDIRECT_BASE", "");
    cfg.oauth_return_allowlist = webdav::getEnvOrDefault("OAUTH_RETURN_ALLOWLIST", "");
    cfg.oauth_state_ttl = std::stoi(webdav::getEnvOrDefault("OAUTH_STATE_TTL_SECONDS", "300"));

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
