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
#include <Poco/URI.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <istream>
#include <map>
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

// Accept a single-letter alias (r/w/x/d/...) or an enum name (READ/WRITE/...).
fileengine_rpc::Permission coercePermission(const std::string& s) {
    static const std::map<std::string, fileengine_rpc::Permission> letters = {
        {"r", fileengine_rpc::READ}, {"w", fileengine_rpc::WRITE}, {"x", fileengine_rpc::EXECUTE},
        {"d", fileengine_rpc::DELETE}, {"l", fileengine_rpc::LIST_DELETED}, {"u", fileengine_rpc::UNDELETE},
        {"v", fileengine_rpc::VIEW_VERSIONS}, {"b", fileengine_rpc::RETRIEVE_BACK_VERSION},
        {"s", fileengine_rpc::RESTORE_TO_VERSION}, {"m", fileengine_rpc::MANAGE_ACL}, {"i", fileengine_rpc::ACL_INHERIT},
    };
    auto it = letters.find(s);
    if (it != letters.end()) return it->second;
    std::string upper = s;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    fileengine_rpc::Permission p;
    if (fileengine_rpc::Permission_Parse(upper, &p)) return p;
    return fileengine_rpc::READ;
}

fileengine_rpc::AclEffect coerceEffect(const std::string& s) {
    return (s == "deny" || s == "DENY") ? fileengine_rpc::DENY : fileengine_rpc::ALLOW;
}

const char* fileTypeName(int t) {
    switch (t) {
        case fileengine_rpc::DIRECTORY: return "directory";
        case fileengine_rpc::SYMLINK:   return "symlink";
        default:                        return "file";
    }
}

// Parse "bytes=START-END" / "bytes=START-" Range header. end = -1 means open.
bool parseRange(const std::string& h, long& start, long& end) {
    if (h.compare(0, 6, "bytes=") != 0) return false;
    std::string r = h.substr(6);
    auto dash = r.find('-');
    if (dash == std::string::npos) return false;
    try {
        start = std::stol(r.substr(0, dash));
        std::string e = r.substr(dash + 1);
        end = e.empty() ? -1 : std::stol(e);
    } catch (...) {
        return false;
    }
    return start >= 0;
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
    RequestHandler(Config cfg,
                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                   std::shared_ptr<webdav::LDAPAuthenticator> ldap,
                   std::shared_ptr<TokenStore> tokens)
        : cfg_(std::move(cfg)), grpc_(std::move(grpc)), ldap_(std::move(ldap)), tokens_(std::move(tokens)) {}

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
        std::string method = req.getMethod();

        // Token endpoint: issue via Basic, revoke via Bearer. Handled before the
        // general authenticate() so issuing a token needs no existing token.
        if (path == "/v1/auth/token") {
            if (method == "POST")   return issueToken(req, resp);
            if (method == "DELETE") return revokeToken(req, resp);
            return sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"not found"})");
        }

        AuthIdentity id;
        if (!authenticate(req, id)) return unauthorized(resp);

        auto segs = pathSegments(path);            // [v1, <resource>, <uid>, <sub>?]

        if (segs.size() == 2 && segs[1] == "whoami") return whoami(resp, id);

        // Top-level admin / role resources (no uid in the path).
        const std::string res0 = segs.size() >= 2 ? segs[1] : "";
        if (res0 == "storage" && segs.size() == 2 && method == "GET")  return storageUsage(resp, id);
        if (res0 == "sync" && segs.size() == 2 && method == "POST")    return triggerSync(resp, id);
        if (res0 == "roles") {
            if (segs.size() == 2 && method == "GET")    return getAllRoles(resp, id);
            if (segs.size() == 2 && method == "POST")   return createRole(req, resp, id);
            if (segs.size() == 3 && method == "DELETE") return deleteRole(resp, id, segs[2]);
            if (segs.size() == 4 && segs[3] == "users" && method == "GET") return getUsersForRole(resp, id, segs[2]);
            if (segs.size() == 5 && segs[3] == "users" && method == "PUT")    return assignUserToRole(resp, id, segs[2], segs[4]);
            if (segs.size() == 5 && segs[3] == "users" && method == "DELETE") return removeUserFromRole(resp, id, segs[2], segs[4]);
        }
        if (res0 == "users" && segs.size() == 4 && segs[3] == "roles" && method == "GET") {
            return getRolesForUser(resp, id, segs[2]);
        }

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
                    if (sub == "content" && method == "GET")    return getContent(req, resp, id, uid);
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
                    if (sub == "permissions" && method == "GET")    return checkPerm(req, resp, id, uid);
                    if (sub == "permissions" && method == "POST")   return grantPerm(req, resp, id, uid);
                    if (sub == "permissions" && method == "DELETE") return revokePerm(req, resp, id, uid);
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

    // PUT content via client-streaming upload — reads the HTTP body in chunks
    // and streams to gRPC, so memory does not scale with file size.
    void putContent(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::AuthenticationContext auth;
        fillAuth(&auth, id);
        std::istream& body = req.stream();
        std::vector<char> buf(256 * 1024);
        auto r = grpc_->streamFileUpload(uid, auth, [&](std::string& out) -> bool {
            body.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            std::streamsize n = body.gcount();
            if (n <= 0) return false;
            out.assign(buf.data(), static_cast<size_t>(n));
            return true;
        });
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // GET content via server-streaming download — writes chunks straight to the
    // socket (chunked transfer). Honors a single Range request (206 + windowing).
    void getContent(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        long rs = -1, re = -1;
        bool hasRange = parseRange(req.get("Range", ""), rs, re);

        fileengine_rpc::GetFileRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);

        std::ostream* os = nullptr;
        long offset = 0;
        bool headerSent = false;
        auto sendHeader = [&]() {
            resp.setStatus(hasRange ? HTTPResponse::HTTP_PARTIAL_CONTENT : HTTPResponse::HTTP_OK);
            resp.setContentType("application/octet-stream");
            resp.set("Accept-Ranges", "bytes");
            if (hasRange) {
                resp.set("Content-Range", "bytes " + std::to_string(rs) + "-" +
                                              (re >= 0 ? std::to_string(re) : std::string()) + "/*");
            }
            os = &resp.send();
            headerSent = true;
        };

        auto result = grpc_->streamFileDownload(rq, [&](const std::string& chunk) -> bool {
            long cstart = offset;
            long cend = offset + static_cast<long>(chunk.size()) - 1;
            offset += static_cast<long>(chunk.size());
            if (!hasRange) {
                if (!headerSent) sendHeader();
                os->write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
                return true;
            }
            long ws = std::max(cstart, rs);
            long we = (re >= 0) ? std::min(cend, re) : cend;
            if (ws <= we) {
                if (!headerSent) sendHeader();
                os->write(chunk.data() + (ws - cstart), static_cast<std::streamsize>(we - ws + 1));
            }
            return !(re >= 0 && offset > re);  // stop once past the requested end
        });

        if (!result.success) {
            if (!headerSent) return mapError(resp, result.error);
            return;  // already streaming; can't change status mid-body
        }
        if (!headerSent) {  // empty content
            resp.setStatus(hasRange ? HTTPResponse::HTTP_PARTIAL_CONTENT : HTTPResponse::HTTP_OK);
            resp.setContentLength(0);
            resp.send();
        }
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

    // --- ACL ---
    // ?user=&permission=&roles=  — evaluates the named principal (impersonated
    // for the check), defaulting to the requesting identity.
    void checkPerm(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string qUser, qPerm, qRoles;
        for (const auto& kv : Poco::URI(req.getURI()).getQueryParameters()) {
            if (kv.first == "user") qUser = kv.second;
            else if (kv.first == "permission") qPerm = kv.second;
            else if (kv.first == "roles") qRoles = kv.second;
        }
        fileengine_rpc::CheckPermissionRequest rq;
        rq.set_resource_uid(uid);
        rq.set_required_permission(coercePermission(qPerm));
        auto* a = rq.mutable_auth();
        a->set_user(qUser.empty() ? id.user : qUser);
        a->set_tenant(id.tenant);
        for (auto& r : webdav::splitString(qRoles, ',')) if (!r.empty()) a->add_roles(r);
        auto r = grpc_->checkPermission(rq);
        if (!r.success()) return mapError(resp, r.error());
        sendJson(resp, HTTPResponse::HTTP_OK, std::string("{\"has_permission\":") + (r.has_permission() ? "true" : "false") + "}");
    }

    void grantPerm(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string body = readBody(req);
        std::string principal = jsonField(body, "principal");
        if (principal.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'principal'"})");
        fileengine_rpc::GrantPermissionRequest rq;
        rq.set_resource_uid(uid);
        rq.set_principal(principal);
        rq.set_permission(coercePermission(jsonField(body, "permission")));
        rq.set_effect(coerceEffect(jsonField(body, "effect")));
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->grantPermission(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void revokePerm(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string body = readBody(req);
        std::string principal = jsonField(body, "principal");
        if (principal.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'principal'"})");
        fileengine_rpc::RevokePermissionRequest rq;
        rq.set_resource_uid(uid);
        rq.set_principal(principal);
        rq.set_permission(coercePermission(jsonField(body, "permission")));
        rq.set_effect(coerceEffect(jsonField(body, "effect")));
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->revokePermission(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // --- roles ---
    void createRole(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id) {
        std::string role = jsonField(readBody(req), "role");
        if (role.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'role'"})");
        fileengine_rpc::CreateRoleRequest rq;
        rq.set_role(role);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->createRole(rq);
        if (r.success()) sendJson(resp, HTTPResponse::HTTP_CREATED, "{\"role\":\"" + jsonEscape(role) + "\"}");
        else mapError(resp, r.error());
    }

    void deleteRole(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& role) {
        fileengine_rpc::DeleteRoleRequest rq;
        rq.set_role(role);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->deleteRole(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void getAllRoles(HTTPServerResponse& resp, const AuthIdentity& id) {
        fileengine_rpc::GetAllRolesRequest rq;
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getAllRoles(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::vector<std::string> v(r.roles().begin(), r.roles().end());
        sendJson(resp, HTTPResponse::HTTP_OK, "{\"roles\":" + jsonArray(v) + "}");
    }

    void assignUserToRole(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& role, const std::string& user) {
        fileengine_rpc::AssignUserToRoleRequest rq;
        rq.set_user(user);
        rq.set_role(role);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->assignUserToRole(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void removeUserFromRole(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& role, const std::string& user) {
        fileengine_rpc::RemoveUserFromRoleRequest rq;
        rq.set_user(user);
        rq.set_role(role);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->removeUserFromRole(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void getUsersForRole(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& role) {
        fileengine_rpc::GetUsersForRoleRequest rq;
        rq.set_role(role);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getUsersForRole(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::vector<std::string> v(r.users().begin(), r.users().end());
        sendJson(resp, HTTPResponse::HTTP_OK, "{\"users\":" + jsonArray(v) + "}");
    }

    void getRolesForUser(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& user) {
        fileengine_rpc::GetRolesForUserRequest rq;
        rq.set_user(user);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getRolesForUser(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::vector<std::string> v(r.roles().begin(), r.roles().end());
        sendJson(resp, HTTPResponse::HTTP_OK, "{\"roles\":" + jsonArray(v) + "}");
    }

    // --- admin ---
    void storageUsage(HTTPServerResponse& resp, const AuthIdentity& id) {
        fileengine_rpc::StorageUsageRequest rq;
        rq.set_tenant(id.tenant);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getStorageUsage(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::string body = "{\"total_space\":" + std::to_string(r.total_space()) +
                           ",\"used_space\":" + std::to_string(r.used_space()) +
                           ",\"available_space\":" + std::to_string(r.available_space()) +
                           ",\"usage_percentage\":" + std::to_string(r.usage_percentage()) + "}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
    }

    void triggerSync(HTTPServerResponse& resp, const AuthIdentity& id) {
        fileengine_rpc::TriggerSyncRequest rq;
        rq.set_tenant(id.tenant);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->triggerSync(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    // Authenticate via a cached Bearer token (no LDAP) or HTTP Basic (LDAP).
    bool authenticate(HTTPServerRequest& req, AuthIdentity& out) {
        std::string h = req.get("Authorization", "");
        if (h.compare(0, 7, "Bearer ") == 0) {
            Session s;
            if (!tokens_->lookup(webdav::trim(h.substr(7)), s)) return false;
            out.user = s.user;
            out.tenant = s.tenant;
            out.roles = s.roles;
            return true;
        }
        return authenticateBasic(req, out);
    }

    // HTTP Basic -> LDAP bind. Tenant: X-Tenant header > host subdomain >
    // "default". Returns false on missing/invalid credentials.
    bool authenticateBasic(HTTPServerRequest& req, AuthIdentity& out) {
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

    void issueToken(HTTPServerRequest& req, HTTPServerResponse& resp) {
        AuthIdentity id;
        if (!authenticateBasic(req, id)) return unauthorized(resp);
        std::string token = tokens_->issue(id.user, id.tenant, id.roles);
        sendJson(resp, HTTPResponse::HTTP_OK,
                 "{\"token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" + std::to_string(tokens_->ttl()) + "}");
    }

    void revokeToken(HTTPServerRequest& req, HTTPServerResponse& resp) {
        std::string h = req.get("Authorization", "");
        if (h.compare(0, 7, "Bearer ") == 0) tokens_->revoke(webdav::trim(h.substr(7)));
        sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
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

    Config cfg_;
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
    std::shared_ptr<TokenStore> tokens_;
};

class HandlerFactory : public HTTPRequestHandlerFactory {
public:
    HandlerFactory(Config cfg,
                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                   std::shared_ptr<webdav::LDAPAuthenticator> ldap,
                   std::shared_ptr<TokenStore> tokens)
        : cfg_(std::move(cfg)), grpc_(std::move(grpc)), ldap_(std::move(ldap)), tokens_(std::move(tokens)) {}

    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest&) override {
        return new RequestHandler(cfg_, grpc_, ldap_, tokens_);
    }

private:
    Config cfg_;
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
    std::shared_ptr<TokenStore> tokens_;
};

}  // namespace

HttpBridgeServer::HttpBridgeServer(const Config& cfg,
                                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                                   std::shared_ptr<webdav::LDAPAuthenticator> ldap)
    : cfg_(cfg), grpc_(std::move(grpc)), ldap_(std::move(ldap)),
      tokens_(std::make_shared<TokenStore>(cfg.token_ttl)) {}

HttpBridgeServer::~HttpBridgeServer() { stop(); }

void HttpBridgeServer::start() {
    auto params = new Poco::Net::HTTPServerParams;
    params->setMaxThreads(cfg_.thread_pool);
    params->setMaxQueued(cfg_.thread_pool * 8);
    params->setKeepAlive(true);

    Poco::Net::ServerSocket socket(
        Poco::Net::SocketAddress(cfg_.http_host, static_cast<Poco::UInt16>(cfg_.http_port)));

    server_ = std::make_unique<Poco::Net::HTTPServer>(
        new HandlerFactory(cfg_, grpc_, ldap_, tokens_), socket, params);
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
