#include "http_server.h"
#include "utils.h"

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

int main() {
    loadDotEnv(".env");

    httpbridge::Config cfg;
    cfg.http_host = webdav::getEnvOrDefault("HTTP_HOST", "0.0.0.0");
    cfg.http_port = std::stoi(webdav::getEnvOrDefault("HTTP_PORT", "8090"));
    cfg.thread_pool = std::stoi(webdav::getEnvOrDefault("HTTP_THREAD_POOL", "16"));
    cfg.grpc_address = webdav::getEnvOrDefault("FILEENGINE_GRPC_HOST", "localhost") + ":" +
                       webdav::getEnvOrDefault("FILEENGINE_GRPC_PORT", "50051");

    auto grpc = std::make_shared<webdav::GRPCClientWrapper>(cfg.grpc_address);
    auto ldap = std::make_shared<webdav::LDAPAuthenticator>(
        webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_PASSWORD", "admin"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com"),
        webdav::getEnvOrDefault("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com"));

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
    return 0;
}
