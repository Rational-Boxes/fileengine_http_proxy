#ifndef HTTP_BRIDGE_HTTP_SERVER_H
#define HTTP_BRIDGE_HTTP_SERVER_H

#include <memory>
#include <string>

#include <Poco/Net/HTTPServer.h>
#include <Poco/ThreadPool.h>

#include "audit_publisher.h"
#include "grpc_client_wrapper.h"
#include "ldap_authenticator.h"
#include "oauth_provider.h"
#include "oauth_state_store.h"
#include "token_store.h"

namespace httpbridge {

struct Config {
    std::string http_host = "0.0.0.0";
    int http_port = 8090;
    int thread_pool = 16;
    // Dedicated reporter listener (pool usage / health). Unauthenticated, so it
    // binds to loopback by default — protect it by network isolation, not auth.
    std::string monitoring_host = "127.0.0.1";
    int monitoring_port = 8091;
    // Bearer session tokens are signed HS256 JWTs. token_ttl is deliberately
    // SHORT: a token is re-minted periodically (POST /v1/auth/refresh) from live
    // LDAP, so role changes take effect within ~the refresh interval and a token
    // that stops being refreshed (access revoked) expires quickly.
    int token_ttl = 900;                     // JWT lifetime (s)
    std::string jwt_secret;                  // HS256 shared secret (REQUIRED)
    std::string jwt_issuer = "fileengine-bridge";
    long max_body_bytes = 100L * 1024 * 1024;  // 100 MiB request-body cap
    std::string cors_origin;                   // empty => no CORS header
    std::string grpc_address = "localhost:50051";

    // OAuth2 / OIDC login (BFF). Empty oauth_redirect_base disables OAuth routes.
    std::string oauth_redirect_base;        // public base URL of the bridge
    std::string oauth_return_allowlist;     // CSV of permitted SPA return-URL prefixes
    int oauth_state_ttl = 300;              // pending-authorization lifetime (s)

    // Durable audit emission (usage_logging_and_auditing §5). Shares the core's
    // Redis broker + stream; login_success/login_failure emit from this door.
    bool audit_enabled = false;
    std::string redis_host = "localhost";
    int redis_port = 6379;
    std::string redis_password;
    int redis_db = 0;
    std::string audit_stream = "fileengine:audit";
    long long audit_stream_maxlen = 1000000;
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

private:
    Config cfg_;
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
    std::shared_ptr<TokenStore> tokens_;
    std::shared_ptr<OAuthProvider> oauth_;
    std::shared_ptr<OAuthStateStore> oauth_states_;
    std::shared_ptr<AuditPublisher> audit_;
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
