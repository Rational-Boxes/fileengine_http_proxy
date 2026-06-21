#include "http_server.h"
#include "utils.h"

#include <Poco/Net/HTTPRequestHandler.h>
#include <Poco/Net/HTTPRequestHandlerFactory.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTTPServerParams.h>
#include <Poco/Net/ServerSocket.h>
#include <Poco/Base64Decoder.h>
#include <Poco/StreamCopier.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <Poco/Dynamic/Var.h>

#include <cstdio>
#include <istream>
#include <ostream>
#include <sstream>
#include <vector>

namespace httpbridge {

using Poco::Net::HTTPRequestHandler;
using Poco::Net::HTTPRequestHandlerFactory;
using Poco::Net::HTTPServerRequest;
using Poco::Net::HTTPServerResponse;
using Poco::Net::HTTPResponse;

namespace {

std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

std::string jsonArray(const std::vector<std::string>& v) {
    std::string o = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o += ",";
        o += "\"" + jsonEscape(v[i]) + "\"";
    }
    o += "]";
    return o;
}

void sendJson(HTTPServerResponse& resp, HTTPResponse::HTTPStatus status, const std::string& body) {
    resp.setStatus(status);
    resp.setContentType("application/json");
    resp.setContentLength(static_cast<std::streamsize>(body.size()));
    std::ostream& os = resp.send();
    os << body;
}

void sendStatus(HTTPServerResponse& resp, HTTPResponse::HTTPStatus status) {
    resp.setStatus(status);
    resp.setContentLength(0);
    resp.send();
}

std::string readBody(HTTPServerRequest& req) {
    std::string s;
    Poco::StreamCopier::copyToString(req.stream(), s);
    return s;
}

// Extract a top-level string field from a JSON body; "" if absent/not parseable.
std::string jsonField(const std::string& body, const std::string& key) {
    try {
        Poco::JSON::Parser p;
        auto obj = p.parse(body).extract<Poco::JSON::Object::Ptr>();
        if (obj && obj->has(key)) return obj->getValue<std::string>(key);
    } catch (...) {
    }
    return "";
}

int jsonFieldInt(const std::string& body, const std::string& key, int def) {
    try {
        Poco::JSON::Parser p;
        auto obj = p.parse(body).extract<Poco::JSON::Object::Ptr>();
        if (obj && obj->has(key)) return obj->getValue<int>(key);
    } catch (...) {
    }
    return def;
}

const char* fileTypeName(int t) {
    switch (t) {
        case fileengine_rpc::DIRECTORY: return "directory";
        case fileengine_rpc::SYMLINK:   return "symlink";
        default:                        return "file";
    }
}

std::vector<std::string> pathSegments(const std::string& path) {
    std::vector<std::string> out;
    for (auto& s : webdav::splitString(path, '/')) {
        if (!s.empty()) out.push_back(s);
    }
    return out;
}

// Translate a gRPC core error string to the right HTTP status.
void mapError(HTTPServerResponse& resp, const std::string& err) {
    HTTPResponse::HTTPStatus status = HTTPResponse::HTTP_INTERNAL_SERVER_ERROR;
    if (err.find("permission") != std::string::npos) {
        status = HTTPResponse::HTTP_FORBIDDEN;
    } else if (err.find("not exist") != std::string::npos || err.find("not found") != std::string::npos) {
        status = HTTPResponse::HTTP_NOT_FOUND;
    } else if (err.find("subtree") != std::string::npos || err.find("already") != std::string::npos) {
        status = HTTPResponse::HTTP_CONFLICT;
    }
    sendJson(resp, status, std::string("{\"error\":\"") + jsonEscape(err) + "\"}");
}

// One handler instance per request (Poco contract). Holds shared, thread-safe
// dependencies by pointer.
class RequestHandler : public HTTPRequestHandler {
public:
    RequestHandler(std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                   std::shared_ptr<webdav::LDAPAuthenticator> ldap)
        : grpc_(std::move(grpc)), ldap_(std::move(ldap)) {}

    void handleRequest(HTTPServerRequest& req, HTTPServerResponse& resp) override {
        const std::string& uri = req.getURI();
        std::string path = uri.substr(0, uri.find('?'));
        if (path == "/healthz") return healthz(resp);
        if (path == "/readyz") return readyz(resp);
        if (path.rfind("/v1/", 0) == 0) return handleV1(req, resp, path);
        sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"not found"})");
    }

private:
    // Identity resolved for a request: who (LDAP), which tenant, and roles.
    struct AuthIdentity {
        std::string user;
        std::string tenant;
        std::vector<std::string> roles;
    };

    // All /v1 routes are authenticated, then dispatched by resource + method.
    void handleV1(HTTPServerRequest& req, HTTPServerResponse& resp, const std::string& path) {
        AuthIdentity id;
        if (!authenticate(req, id)) return unauthorized(resp);

        auto segs = pathSegments(path);            // [v1, <resource>, <uid>, <sub>?]
        std::string method = req.getMethod();

        if (segs.size() == 2 && segs[1] == "whoami") return whoami(resp, id);

        if (segs.size() >= 3) {
            const std::string& resource = segs[1];
            std::string uid = (segs[2] == "root") ? "" : segs[2];  // "root" alias; all-zeros handled by core
            const std::string sub = segs.size() >= 4 ? segs[3] : "";

            if (resource == "dirs") {
                if (segs.size() == 3) {
                    if (method == "POST")   return makeDir(req, resp, id, uid);
                    if (method == "GET")    return listDir(req, resp, id, uid);
                    if (method == "DELETE") return removeDir(resp, id, uid);
                } else if (segs.size() == 4 && sub == "files" && method == "POST") {
                    return touchFile(req, resp, id, uid);
                }
            } else if (resource == "files") {
                if (segs.size() == 3) {
                    if (method == "DELETE") return removeFile(resp, id, uid);
                } else if (segs.size() == 4) {
                    if (sub == "content" && method == "PUT")    return putContent(req, resp, id, uid);
                    if (sub == "content" && method == "GET")    return getContent(resp, id, uid);
                    if (sub == "undelete" && method == "POST")  return undelete(resp, id, uid);
                    if (sub == "versions" && method == "GET")   return listVersions(resp, id, uid);
                    if (sub == "restore" && method == "POST")   return restoreVersion(req, resp, id, uid);
                    if (sub == "purge" && method == "POST")     return purgeVersions(req, resp, id, uid);
                } else if (segs.size() == 5 && sub == "versions" && method == "GET") {
                    return getVersion(resp, id, uid, segs[4]);
                }
            } else if (resource == "nodes") {
                if (segs.size() == 3) {
                    if (method == "GET") return statNode(resp, id, uid);
                } else if (segs.size() == 4) {
                    if (sub == "exists" && method == "GET")     return existsNode(resp, id, uid);
                    if (sub == "rename" && method == "POST")    return renameNode(req, resp, id, uid);
                    if (sub == "move" && method == "POST")      return moveNode(req, resp, id, uid);
                    if (sub == "copy" && method == "POST")      return copyNode(req, resp, id, uid);
                    if (sub == "metadata" && method == "GET")   return getAllMeta(resp, id, uid);
                } else if (segs.size() == 5 && sub == "metadata") {
                    const std::string& key = segs[4];
                    if (method == "GET")    return getMeta(resp, id, uid, key);
                    if (method == "PUT")    return setMeta(req, resp, id, uid, key);
                    if (method == "DELETE") return deleteMeta(resp, id, uid, key);
                }
            }
        }
        sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"not found"})");
    }

    void fillAuth(fileengine_rpc::AuthenticationContext* a, const AuthIdentity& id) {
        a->set_user(id.user);
        a->set_tenant(id.tenant);
        for (const auto& r : id.roles) a->add_roles(r);
    }

    template <typename Resp>
    std::string entriesJson(const Resp& r) {
        std::string body = "{\"entries\":[";
        bool first = true;
        for (const auto& e : r.entries()) {
            if (!first) body += ",";
            first = false;
            body += "{\"uid\":\"" + jsonEscape(e.uid()) + "\",\"name\":\"" + jsonEscape(e.name()) +
                    "\",\"type\":\"" + fileTypeName(e.type()) + "\",\"size\":" + std::to_string(e.size()) +
                    ",\"version_count\":" + std::to_string(e.version_count()) + "}";
        }
        body += "]}";
        return body;
    }

    void makeDir(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& parent) {
        std::string name = jsonField(readBody(req), "name");
        if (name.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'name'"})");
        fileengine_rpc::MakeDirectoryRequest rq;
        rq.set_parent_uid(parent);
        rq.set_name(name);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->makeDirectory(rq);
        if (r.success()) sendJson(resp, HTTPResponse::HTTP_CREATED, "{\"uid\":\"" + jsonEscape(r.uid()) + "\"}");
        else mapError(resp, r.error());
    }

    void touchFile(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& parent) {
        std::string name = jsonField(readBody(req), "name");
        if (name.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'name'"})");
        fileengine_rpc::TouchRequest rq;
        rq.set_parent_uid(parent);
        rq.set_name(name);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->touch(rq);
        if (r.success()) sendJson(resp, HTTPResponse::HTTP_CREATED, "{\"uid\":\"" + jsonEscape(r.uid()) + "\"}");
        else mapError(resp, r.error());
    }

    void putContent(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string data = readBody(req);
        fileengine_rpc::PutFileRequest rq;
        rq.set_uid(uid);
        rq.set_data(data);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->putFile(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void getContent(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::GetFileRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getFile(rq);
        if (!r.success()) return mapError(resp, r.error());
        resp.setStatus(HTTPResponse::HTTP_OK);
        resp.setContentType("application/octet-stream");
        const std::string& data = r.data();
        resp.setContentLength(static_cast<std::streamsize>(data.size()));
        resp.send().write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    void statNode(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::StatRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->stat(rq);
        if (!r.success()) return mapError(resp, r.error());
        const auto& i = r.info();
        std::string body = "{\"uid\":\"" + jsonEscape(i.uid()) + "\",\"name\":\"" + jsonEscape(i.name()) +
                           "\",\"parent_uid\":\"" + jsonEscape(i.parent_uid()) + "\",\"type\":\"" + fileTypeName(i.type()) +
                           "\",\"size\":" + std::to_string(i.size()) + ",\"owner\":\"" + jsonEscape(i.owner()) +
                           "\",\"version\":\"" + jsonEscape(i.version()) + "\"}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
    }

    void listDir(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        bool deleted = req.getURI().find("deleted=true") != std::string::npos;
        if (deleted) {
            fileengine_rpc::ListDirectoryWithDeletedRequest rq;
            rq.set_uid(uid);
            fillAuth(rq.mutable_auth(), id);
            auto r = grpc_->listDirectoryWithDeleted(rq);
            if (!r.success()) return mapError(resp, r.error());
            sendJson(resp, HTTPResponse::HTTP_OK, entriesJson(r));
        } else {
            fileengine_rpc::ListDirectoryRequest rq;
            rq.set_uid(uid);
            fillAuth(rq.mutable_auth(), id);
            auto r = grpc_->listDirectory(rq);
            if (!r.success()) return mapError(resp, r.error());
            sendJson(resp, HTTPResponse::HTTP_OK, entriesJson(r));
        }
    }

    void removeFile(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::RemoveFileRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->removeFile(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void removeDir(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::RemoveDirectoryRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->removeDirectory(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // --- manipulation ---
    void renameNode(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string nn = jsonField(readBody(req), "new_name");
        if (nn.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'new_name'"})");
        fileengine_rpc::RenameRequest rq;
        rq.set_uid(uid);
        rq.set_new_name(nn);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->rename(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void moveNode(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string dest = jsonField(readBody(req), "destination_parent_uid");
        fileengine_rpc::MoveRequest rq;
        rq.set_source_uid(uid);
        rq.set_destination_parent_uid(dest);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->move(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void copyNode(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string dest = jsonField(readBody(req), "destination_parent_uid");
        fileengine_rpc::CopyRequest rq;
        rq.set_source_uid(uid);
        rq.set_destination_parent_uid(dest);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->copy(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void existsNode(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::ExistsRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->exists(rq);
        if (!r.success()) return mapError(resp, r.error());
        sendJson(resp, HTTPResponse::HTTP_OK, std::string("{\"exists\":") + (r.exists() ? "true" : "false") + "}");
    }

    void undelete(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::UndeleteFileRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->undeleteFile(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // --- versioning ---
    void listVersions(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::ListVersionsRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->listVersions(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::vector<std::string> v(r.versions().begin(), r.versions().end());
        sendJson(resp, HTTPResponse::HTTP_OK, "{\"versions\":" + jsonArray(v) + "}");
    }

    void getVersion(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid, const std::string& ts) {
        fileengine_rpc::GetVersionRequest rq;
        rq.set_uid(uid);
        rq.set_version_timestamp(ts);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getVersion(rq);
        if (!r.success()) return mapError(resp, r.error());
        resp.setStatus(HTTPResponse::HTTP_OK);
        resp.setContentType("application/octet-stream");
        const std::string& data = r.data();
        resp.setContentLength(static_cast<std::streamsize>(data.size()));
        resp.send().write(data.data(), static_cast<std::streamsize>(data.size()));
    }

    void restoreVersion(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string ts = jsonField(readBody(req), "version_timestamp");
        fileengine_rpc::RestoreToVersionRequest rq;
        rq.set_uid(uid);
        rq.set_version_timestamp(ts);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->restoreToVersion(rq);
        if (r.success()) sendJson(resp, HTTPResponse::HTTP_OK, "{\"restored_version\":\"" + jsonEscape(r.restored_version()) + "\"}");
        else mapError(resp, r.error());
    }

    void purgeVersions(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        int keep = jsonFieldInt(readBody(req), "keep_count", 1);
        fileengine_rpc::PurgeOldVersionsRequest rq;
        rq.set_uid(uid);
        rq.set_keep_count(keep);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->purgeOldVersions(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // --- metadata ---
    void getAllMeta(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::GetAllMetadataRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getAllMetadata(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::string body = "{\"metadata\":{";
        bool first = true;
        for (const auto& kv : r.metadata()) {
            if (!first) body += ",";
            first = false;
            body += "\"" + jsonEscape(kv.first) + "\":\"" + jsonEscape(kv.second) + "\"";
        }
        body += "}}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
    }

    void getMeta(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid, const std::string& key) {
        fileengine_rpc::GetMetadataRequest rq;
        rq.set_uid(uid);
        rq.set_key(key);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getMetadata(rq);
        if (r.success()) sendJson(resp, HTTPResponse::HTTP_OK, "{\"value\":\"" + jsonEscape(r.value()) + "\"}");
        else mapError(resp, r.error());
    }

    void setMeta(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid, const std::string& key) {
        std::string value = jsonField(readBody(req), "value");
        fileengine_rpc::SetMetadataRequest rq;
        rq.set_uid(uid);
        rq.set_key(key);
        rq.set_value(value);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->setMetadata(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void deleteMeta(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid, const std::string& key) {
        fileengine_rpc::DeleteMetadataRequest rq;
        rq.set_uid(uid);
        rq.set_key(key);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->deleteMetadata(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // HTTP Basic -> LDAP bind. Tenant: X-Tenant header > host subdomain >
    // "default". Returns false on missing/invalid credentials.
    bool authenticate(HTTPServerRequest& req, AuthIdentity& out) {
        std::string h = req.get("Authorization", "");
        if (h.size() < 6 || h.compare(0, 6, "Basic ") != 0) return false;
        std::istringstream iss(webdav::trim(h.substr(6)));
        Poco::Base64Decoder dec(iss);
        std::string creds((std::istreambuf_iterator<char>(dec)), std::istreambuf_iterator<char>());
        auto colon = creds.find(':');
        if (colon == std::string::npos) return false;
        std::string user = creds.substr(0, colon);
        std::string pass = creds.substr(colon + 1);

        webdav::UserInfo info = ldap_->authenticateUser(user, pass);
        if (!info.authenticated) return false;

        out.user = info.user_id.empty() ? user : info.user_id;
        out.roles = info.roles;

        std::string xt = req.get("X-Tenant", "");
        if (!xt.empty()) {
            out.tenant = xt;
        } else {
            std::string t = webdav::extractTenantFromHostname(req.getHost());
            out.tenant = t.empty() ? "default" : t;
        }
        return true;
    }

    void unauthorized(HTTPServerResponse& resp) {
        resp.set("WWW-Authenticate", "Basic realm=\"FileEngine\"");
        sendJson(resp, HTTPResponse::HTTP_UNAUTHORIZED, R"({"error":"authentication required"})");
    }

    void whoami(HTTPServerResponse& resp, const AuthIdentity& id) {
        std::string body = "{\"user\":\"" + jsonEscape(id.user) +
                           "\",\"tenant\":\"" + jsonEscape(id.tenant) +
                           "\",\"roles\":" + jsonArray(id.roles) + "}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
    }

    // Liveness: the process is up and serving.
    void healthz(HTTPServerResponse& resp) {
        sendJson(resp, HTTPResponse::HTTP_OK, R"({"status":"ok"})");
    }

    // Readiness: the gRPC core is reachable. Probe with a root ListDirectory
    // under a system_admin context (no LDAP needed for the probe).
    void readyz(HTTPServerResponse& resp) {
        fileengine_rpc::ListDirectoryRequest request;
        request.set_uid("");
        auto* auth = request.mutable_auth();
        auth->set_user("healthz");
        auth->set_tenant("default");
        auth->add_roles("system_admin");

        auto r = grpc_->listDirectory(request);
        if (r.success()) {
            sendJson(resp, HTTPResponse::HTTP_OK, R"({"status":"ready"})");
        } else {
            sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                     std::string(R"({"status":"unavailable","error":")") + r.error() + R"("})");
        }
    }

    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
};

class HandlerFactory : public HTTPRequestHandlerFactory {
public:
    HandlerFactory(std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                   std::shared_ptr<webdav::LDAPAuthenticator> ldap)
        : grpc_(std::move(grpc)), ldap_(std::move(ldap)) {}

    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest&) override {
        return new RequestHandler(grpc_, ldap_);
    }

private:
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
};

}  // namespace

HttpBridgeServer::HttpBridgeServer(const Config& cfg,
                                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                                   std::shared_ptr<webdav::LDAPAuthenticator> ldap)
    : cfg_(cfg), grpc_(std::move(grpc)), ldap_(std::move(ldap)) {}

HttpBridgeServer::~HttpBridgeServer() { stop(); }

void HttpBridgeServer::start() {
    auto params = new Poco::Net::HTTPServerParams;
    params->setMaxThreads(cfg_.thread_pool);
    params->setMaxQueued(cfg_.thread_pool * 8);
    params->setKeepAlive(true);

    Poco::Net::ServerSocket socket(
        Poco::Net::SocketAddress(cfg_.http_host, static_cast<Poco::UInt16>(cfg_.http_port)));

    server_ = std::make_unique<Poco::Net::HTTPServer>(
        new HandlerFactory(grpc_, ldap_), socket, params);
    server_->start();
    webdav::infoLog("HTTP bridge listening on " + cfg_.http_host + ":" + std::to_string(cfg_.http_port) +
                    " (threads=" + std::to_string(cfg_.thread_pool) + ")");
}

void HttpBridgeServer::stop() {
    if (server_) {
        server_->stop();
        server_.reset();
    }
}

}  // namespace httpbridge
