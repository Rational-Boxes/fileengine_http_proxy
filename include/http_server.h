#ifndef HTTP_BRIDGE_HTTP_SERVER_H
#define HTTP_BRIDGE_HTTP_SERVER_H

#include <memory>
#include <string>

#include <Poco/Net/HTTPServer.h>

#include "grpc_client_wrapper.h"
#include "ldap_authenticator.h"
#include "token_store.h"

namespace httpbridge {

struct Config {
    std::string http_host = "0.0.0.0";
    int http_port = 8090;
    int thread_pool = 16;
    int token_ttl = 3600;
    long max_body_bytes = 100L * 1024 * 1024;  // 100 MiB request-body cap
    std::string cors_origin;                   // empty => no CORS header
    std::string grpc_address = "localhost:50051";
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
    std::unique_ptr<Poco::Net::HTTPServer> server_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_HTTP_SERVER_H
