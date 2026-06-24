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
#include <Poco/SHA2Engine.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
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

// base64url without padding (RFC 4648 §5) — the encoding PKCE and JWT use.
std::string base64UrlEncode(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = data[i] << 16;
        int n = 1;
        if (i + 1 < len) { v |= data[i + 1] << 8; n = 2; }
        if (i + 2 < len) { v |= data[i + 2]; n = 3; }
        out += tbl[(v >> 18) & 0x3f];
        out += tbl[(v >> 12) & 0x3f];
        if (n >= 2) out += tbl[(v >> 6) & 0x3f];
        if (n >= 3) out += tbl[v & 0x3f];
    }
    return out;
}

// A PKCE code verifier: 32 random bytes -> 43 base64url chars (all unreserved).
std::string randomCodeVerifier() {
    unsigned char buf[32] = {0};
    std::ifstream f("/dev/urandom", std::ios::binary);
    f.read(reinterpret_cast<char*>(buf), sizeof(buf));
    return base64UrlEncode(buf, sizeof(buf));
}

// PKCE S256 challenge = base64url(SHA-256(verifier)).
std::string pkceChallengeS256(const std::string& verifier) {
    Poco::SHA2Engine engine(Poco::SHA2Engine::SHA_256);
    engine.update(verifier);
    const Poco::DigestEngine::Digest& d = engine.digest();
    return base64UrlEncode(d.data(), d.size());
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
                   std::shared_ptr<TokenStore> tokens,
                   std::shared_ptr<OAuthProvider> oauth,
                   std::shared_ptr<OAuthStateStore> oauth_states)
        : cfg_(std::move(cfg)), grpc_(std::move(grpc)), ldap_(std::move(ldap)), tokens_(std::move(tokens)),
          oauth_(std::move(oauth)), oauth_states_(std::move(oauth_states)) {}

    void handleRequest(HTTPServerRequest& req, HTTPServerResponse& resp) override {
        auto start = std::chrono::steady_clock::now();
        const std::string method = req.getMethod();
        const std::string& uri = req.getURI();
        std::string path = uri.substr(0, uri.find('?'));  // query stripped from logs

        // CORS scoped to a configured origin (never "*"); answer preflight here.
        if (!cfg_.cors_origin.empty()) {
            resp.set("Access-Control-Allow-Origin", cfg_.cors_origin);
            resp.set("Vary", "Origin");
            resp.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Range, X-Tenant");
            resp.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            if (method == "OPTIONS") {
                sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
                return accessLog(method, path, resp, start);
            }
        }

        // Reject over-large declared bodies up front (413).
        std::streamsize clen = req.getContentLength();
        if (clen != Poco::Net::HTTPMessage::UNKNOWN_CONTENT_LENGTH &&
            static_cast<long>(clen) > cfg_.max_body_bytes) {
            sendJson(resp, HTTPResponse::HTTP_REQUEST_ENTITY_TOO_LARGE, R"({"error":"request body too large"})");
            return accessLog(method, path, resp, start);
        }

        if (path == "/healthz") healthz(resp);
        else if (path == "/readyz") readyz(resp);
        else if (path.rfind("/v1/", 0) == 0) handleV1(req, resp, path);
        else sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"not found"})");

        accessLog(method, path, resp, start);
    }

private:
    // Structured access log. Never logs the Authorization header, credentials,
    // tokens, or the query string.
    void accessLog(const std::string& method, const std::string& path,
                   HTTPServerResponse& resp, std::chrono::steady_clock::time_point start) {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start).count();
        webdav::infoLog(method + " " + path + " -> " +
                        std::to_string(static_cast<int>(resp.getStatus())) +
                        " (" + std::to_string(ms) + "ms)");
    }

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

        // OAuth2 login (BFF). Pre-auth: the browser has no bearer token yet.
        //   GET /v1/auth/oauth/{provider}            -> redirect to the IdP
        //   GET /v1/auth/oauth/{provider}/callback   -> exchange + issue token
        {
            auto s = pathSegments(path);
            if (s.size() >= 4 && s[1] == "auth" && s[2] == "oauth") {
                if (s.size() == 4 && method == "GET")
                    return oauthStart(req, resp, s[3]);
                if (s.size() == 5 && s[4] == "callback" && method == "GET")
                    return oauthCallback(req, resp, s[3]);
                return sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"not found"})");
            }
        }

        AuthIdentity id;
        if (!authenticate(req, id)) return unauthorized(resp);

        auto segs = pathSegments(path);            // [v1, <resource>, <uid>, <sub>?]

        if (segs.size() == 2 && segs[1] == "whoami") return whoami(resp, id);

        // Top-level admin / role resources (no uid in the path).
        const std::string res0 = segs.size() >= 2 ? segs[1] : "";
        if (res0 == "tenants" && segs.size() == 2 && method == "GET") return listTenants(resp, id);
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
        if (res0 == "principals" && segs.size() == 2 && method == "GET") {
            return searchPrincipals(req, resp, id);
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
                    if (sub == "renditions" && method == "GET") return listRenditions(resp, id, uid);
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
                    ",\"version_count\":" + std::to_string(e.version_count()) +
                    ",\"rendition_count\":" + std::to_string(e.rendition_count()) +
                    ",\"has_renditions\":" + (e.rendition_count() > 0 ? "true" : "false") + "}";
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
                           "\",\"version\":\"" + jsonEscape(i.version()) +
                           "\",\"rendition_count\":" + std::to_string(i.rendition_count()) +
                           ",\"has_renditions\":" + (i.rendition_count() > 0 ? "true" : "false") + "}";
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

    // List a file's hidden renditions on demand (children of the file UID).
    // Normal browsing never surfaces these; this is the explicit opt-in path.
    void listRenditions(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::ListDirectoryRequest rq;
        rq.set_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->listDirectory(rq);
        if (!r.success()) return mapError(resp, r.error());
        sendJson(resp, HTTPResponse::HTTP_OK, entriesJson(r));
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

    // GET /v1/principals?q=<prefix>&types=role,claim,user&limit=<n>
    // Type-ahead source for the ACL editor. Returns the roles, claims, and users
    // whose identifier begins (case-insensitively) with `q`. `types` selects
    // which categories to include (comma-separated; default all three); `limit`
    // caps each category. Roles come from core's role registry (filtered here),
    // claims from core's ACL claim catalog (ListClaims), users from LDAP.
    void searchPrincipals(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id) {
        std::string q, typesParam;
        int limit = 20;
        for (const auto& kv : Poco::URI(req.getURI()).getQueryParameters()) {
            if (kv.first == "q" || kv.first == "prefix") q = kv.second;
            else if (kv.first == "types") typesParam = kv.second;
            else if (kv.first == "limit") { try { limit = std::stoi(kv.second); } catch (...) {} }
        }
        if (limit <= 0 || limit > 100) limit = 20;

        bool wantRoles = true, wantClaims = true, wantUsers = true;
        if (!typesParam.empty()) {
            wantRoles = wantClaims = wantUsers = false;
            for (auto& t : webdav::splitString(typesParam, ',')) {
                if (t == "role" || t == "roles")  wantRoles = true;
                else if (t == "claim" || t == "claims") wantClaims = true;
                else if (t == "user" || t == "users")   wantUsers = true;
            }
        }

        auto lower = [](std::string s) { for (char& c : s) if (c >= 'A' && c <= 'Z') c += 32; return s; };
        std::string lq = lower(q);

        std::vector<std::string> roles, claims, users;

        if (wantRoles) {
            fileengine_rpc::GetAllRolesRequest rq;
            fillAuth(rq.mutable_auth(), id);
            auto r = grpc_->getAllRoles(rq);
            if (!r.success()) return mapError(resp, r.error());
            for (const auto& role : r.roles()) {
                if (lq.empty() || lower(role).compare(0, lq.size(), lq) == 0) {
                    roles.push_back(role);
                    if (static_cast<int>(roles.size()) >= limit) break;
                }
            }
        }

        if (wantClaims) {
            fileengine_rpc::ListClaimsRequest rq;
            fillAuth(rq.mutable_auth(), id);
            rq.set_prefix(q);
            rq.set_limit(limit);
            auto r = grpc_->listClaims(rq);
            if (!r.success()) return mapError(resp, r.error());
            claims.assign(r.claims().begin(), r.claims().end());
        }

        if (wantUsers && ldap_) {
            users = ldap_->searchUsers(q, limit);
        }

        std::string body = "{\"users\":" + jsonArray(users) +
                           ",\"roles\":" + jsonArray(roles) +
                           ",\"claims\":" + jsonArray(claims) + "}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
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

    // --- OAuth2 login (BFF) ---

    // Tenant resolution shared with Basic auth: X-Tenant > host subdomain > default.
    std::string resolveTenant(HTTPServerRequest& req) {
        std::string xt = req.get("X-Tenant", "");
        if (!xt.empty()) return xt;
        std::string t = webdav::extractTenantFromHostname(req.getHost());
        return t.empty() ? "default" : t;
    }

    // A return URL is allowed only if it begins with a configured prefix. Without
    // this, the callback would hand a valid bridge token to any attacker URL.
    bool returnAllowed(const std::string& url) {
        for (auto& p : webdav::splitString(cfg_.oauth_return_allowlist, ',')) {
            std::string pre = webdav::trim(p);
            if (!pre.empty() && url.rfind(pre, 0) == 0) return true;
        }
        return false;
    }

    void oauthStart(HTTPServerRequest& req, HTTPServerResponse& resp, const std::string& provider) {
        const OAuthProviderConfig* cfg = oauth_ ? oauth_->get(provider) : nullptr;
        if (!cfg) return sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"unknown provider"})");

        std::string return_to;
        for (const auto& kv : Poco::URI(req.getURI()).getQueryParameters()) {
            if (kv.first == "return_to") return_to = kv.second;
        }
        if (return_to.empty()) {  // default to the first configured prefix
            auto prefixes = webdav::splitString(cfg_.oauth_return_allowlist, ',');
            if (!prefixes.empty()) return_to = webdav::trim(prefixes[0]);
        }
        if (return_to.empty() || !returnAllowed(return_to)) {
            return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"return_to not allowed"})");
        }

        std::string verifier = randomCodeVerifier();
        std::string challenge = pkceChallengeS256(verifier);

        OAuthState st;
        st.provider = provider;
        st.code_verifier = verifier;
        st.tenant = resolveTenant(req);
        st.return_to = return_to;
        std::string state = oauth_states_->create(std::move(st));

        resp.redirect(oauth_->buildAuthorizeUrl(*cfg, state, challenge), HTTPResponse::HTTP_FOUND);
    }

    void oauthCallback(HTTPServerRequest& req, HTTPServerResponse& resp, const std::string& provider) {
        std::string code, state, idp_error;
        for (const auto& kv : Poco::URI(req.getURI()).getQueryParameters()) {
            if (kv.first == "code") code = kv.second;
            else if (kv.first == "state") state = kv.second;
            else if (kv.first == "error") idp_error = kv.second;
        }

        // state is the CSRF + replay + binding token; consume it exactly once.
        OAuthState st;
        if (state.empty() || !oauth_states_->consume(state, st)) {
            return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"invalid or expired state"})");
        }
        if (st.provider != provider) {
            return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"provider mismatch"})");
        }
        if (!idp_error.empty() || code.empty()) {
            return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"authorization denied"})");
        }

        const OAuthProviderConfig* cfg = oauth_->get(provider);
        if (!cfg) return sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"unknown provider"})");

        std::string access_token, err;
        if (!oauth_->exchangeCode(*cfg, code, st.code_verifier, access_token, err)) {
            webdav::warnLog("oauth: code exchange failed for '" + provider + "': " + err);
            return sendJson(resp, HTTPResponse::HTTP_BAD_GATEWAY, R"({"error":"token exchange failed"})");
        }

        VerifiedIdentity vid;
        if (!oauth_->fetchIdentity(*cfg, access_token, vid, err)) {
            webdav::warnLog("oauth: identity fetch failed for '" + provider + "': " + err);
            return sendJson(resp, HTTPResponse::HTTP_BAD_GATEWAY, R"({"error":"identity lookup failed"})");
        }
        if (!vid.email_verified) {
            return sendJson(resp, HTTPResponse::HTTP_FORBIDDEN, R"({"error":"email not verified by provider"})");
        }

        // Map the verified email to the LDAP identity so OAuth and Basic logins
        // resolve to the same uid/roles for gRPC ACL purposes.
        webdav::UserInfo info = ldap_->getUserInfoByEmail(vid.email);
        if (!info.authenticated || info.user_id.empty()) {
            return sendJson(resp, HTTPResponse::HTTP_FORBIDDEN, R"({"error":"no matching user"})");
        }

        std::string token = tokens_->issue(info.user_id, st.tenant, info.roles);

        // Token returned in the URL fragment (not the query) so it is not sent to
        // the SPA's server or leaked via Referer. The SPA scrubs it from history.
        std::string sep = st.return_to.find('#') == std::string::npos ? "#" : "&";
        std::string location = st.return_to + sep + "token=" + webdav::urlEncode(token) +
                               "&token_type=Bearer&expires_in=" + std::to_string(tokens_->ttl());
        resp.redirect(location, HTTPResponse::HTTP_FOUND);
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
            // Per-request tenant selection: an X-Tenant header overrides the
            // tenant bound to the token at issue time, letting a single session
            // operate across the tenants it can access without re-authenticating.
            // The core still enforces ACLs, so a tenant the user cannot reach
            // simply yields permission errors / empty listings.
            std::string xt = req.get("X-Tenant", "");
            if (!xt.empty()) out.tenant = xt;
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

    // The tenants the authenticated user can operate in (from LDAP group
    // membership), plus the tenant active on this request so the caller can
    // present a selector with the current choice highlighted. Always includes at
    // least the active tenant; falls back to "default" if nothing resolves.
    void listTenants(HTTPServerResponse& resp, const AuthIdentity& id) {
        std::vector<std::string> tenants = ldap_->getTenantsForUser(id.user);
        if (!id.tenant.empty() &&
            std::find(tenants.begin(), tenants.end(), id.tenant) == tenants.end()) {
            tenants.push_back(id.tenant);
        }
        if (tenants.empty()) tenants.push_back("default");
        std::sort(tenants.begin(), tenants.end());
        tenants.erase(std::unique(tenants.begin(), tenants.end()), tenants.end());

        std::string current = id.tenant.empty() ? "default" : id.tenant;
        std::string body = "{\"tenants\":" + jsonArray(tenants) +
                           ",\"current\":\"" + jsonEscape(current) + "\"}";
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
    std::shared_ptr<OAuthProvider> oauth_;
    std::shared_ptr<OAuthStateStore> oauth_states_;
};

class HandlerFactory : public HTTPRequestHandlerFactory {
public:
    HandlerFactory(Config cfg,
                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                   std::shared_ptr<webdav::LDAPAuthenticator> ldap,
                   std::shared_ptr<TokenStore> tokens,
                   std::shared_ptr<OAuthProvider> oauth,
                   std::shared_ptr<OAuthStateStore> oauth_states)
        : cfg_(std::move(cfg)), grpc_(std::move(grpc)), ldap_(std::move(ldap)), tokens_(std::move(tokens)),
          oauth_(std::move(oauth)), oauth_states_(std::move(oauth_states)) {}

    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest&) override {
        return new RequestHandler(cfg_, grpc_, ldap_, tokens_, oauth_, oauth_states_);
    }

private:
    Config cfg_;
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
    std::shared_ptr<TokenStore> tokens_;
    std::shared_ptr<OAuthProvider> oauth_;
    std::shared_ptr<OAuthStateStore> oauth_states_;
};

}  // namespace

HttpBridgeServer::HttpBridgeServer(const Config& cfg,
                                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                                   std::shared_ptr<webdav::LDAPAuthenticator> ldap)
    : cfg_(cfg), grpc_(std::move(grpc)), ldap_(std::move(ldap)),
      tokens_(std::make_shared<TokenStore>(cfg.token_ttl)),
      oauth_(std::make_shared<OAuthProvider>(OAuthProvider::fromEnv(cfg.oauth_redirect_base))),
      oauth_states_(std::make_shared<OAuthStateStore>(cfg.oauth_state_ttl)) {}

HttpBridgeServer::~HttpBridgeServer() { stop(); }

// ---- Monitoring / reporting API (consistent across the HTTP services) --------
namespace {
std::string poolFields(Poco::ThreadPool& pool, int maxQueued) {
    return std::string("\"pool\":{\"capacity\":") + std::to_string(pool.capacity()) +
           ",\"used\":" + std::to_string(pool.used()) +
           ",\"available\":" + std::to_string(pool.available()) +
           ",\"max_queued\":" + std::to_string(maxQueued) + "}";
}

// Served on the reporter's own held-back thread, so these answer even when every
// worker thread is mid-transfer. /healthz = liveness; /readyz = has free worker
// capacity (503 when saturated → LB drains this instance); /poolz = live usage.
class MonitorHandler : public HTTPRequestHandler {
public:
    MonitorHandler(Poco::ThreadPool* pool, int maxQueued, std::string service)
        : pool_(pool), maxQueued_(maxQueued), service_(std::move(service)) {}
    void handleRequest(HTTPServerRequest& req, HTTPServerResponse& resp) override {
        const std::string path = req.getURI();
        const bool hasCapacity = pool_->available() > 0;
        if (path == "/healthz") {
            sendJson(resp, HTTPResponse::HTTP_OK,
                     std::string("{\"status\":\"ok\",\"service\":\"") + service_ + "\"}");
        } else if (path == "/readyz") {
            sendJson(resp, hasCapacity ? HTTPResponse::HTTP_OK : HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                     std::string("{\"ready\":") + (hasCapacity ? "true" : "false") +
                     "," + poolFields(*pool_, maxQueued_) + "}");
        } else if (path == "/poolz") {
            sendJson(resp, HTTPResponse::HTTP_OK,
                     std::string("{") + poolFields(*pool_, maxQueued_) +
                     ",\"saturated\":" + (hasCapacity ? "false" : "true") + "}");
        } else {
            sendJson(resp, HTTPResponse::HTTP_NOT_FOUND, R"({"error":"not found"})");
        }
    }
private:
    Poco::ThreadPool* pool_;
    int maxQueued_;
    std::string service_;
};

class MonitorHandlerFactory : public HTTPRequestHandlerFactory {
public:
    MonitorHandlerFactory(Poco::ThreadPool* pool, int maxQueued, std::string service)
        : pool_(pool), maxQueued_(maxQueued), service_(std::move(service)) {}
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest&) override {
        return new MonitorHandler(pool_, maxQueued_, service_);
    }
private:
    Poco::ThreadPool* pool_;
    int maxQueued_;
    std::string service_;
};
}  // namespace

void HttpBridgeServer::start() {
    const int threads = cfg_.thread_pool > 0 ? cfg_.thread_pool : 16;

    auto params = new Poco::Net::HTTPServerParams;
    params->setMaxThreads(threads);
    params->setMaxQueued(threads * 8);
    params->setKeepAlive(true);

    // Use a *dedicated* pool sized to `threads` rather than Poco's shared
    // defaultPool() (capacity 16) — otherwise setMaxThreads is silently capped at
    // 16 and HTTP_THREAD_POOL above 16 has no effect. Each long-lived transfer
    // pins one of these threads for its duration, so this is the real concurrency.
    pool_ = std::make_unique<Poco::ThreadPool>(
        std::min(2, threads), threads, 60 /* idle seconds */);

    Poco::Net::ServerSocket socket(
        Poco::Net::SocketAddress(cfg_.http_host, static_cast<Poco::UInt16>(cfg_.http_port)));

    server_ = std::make_unique<Poco::Net::HTTPServer>(
        new HandlerFactory(cfg_, grpc_, ldap_, tokens_, oauth_, oauth_states_), *pool_, socket, params);
    server_->start();
    webdav::infoLog("HTTP bridge listening on " + cfg_.http_host + ":" + std::to_string(cfg_.http_port) +
                    " (threads=" + std::to_string(cfg_.thread_pool) + ")");

    // Dedicated reporter: a single held-back thread + listener so pool usage /
    // health stay answerable for the load balancer even at full saturation.
    monitor_pool_ = std::make_unique<Poco::ThreadPool>(1, 1, 60);
    auto mparams = new Poco::Net::HTTPServerParams;
    mparams->setMaxThreads(1);
    mparams->setMaxQueued(64);
    mparams->setKeepAlive(false);  // free the reporter thread after each response
    Poco::Net::ServerSocket msocket(
        Poco::Net::SocketAddress(cfg_.http_host, static_cast<Poco::UInt16>(cfg_.monitoring_port)));
    monitor_server_ = std::make_unique<Poco::Net::HTTPServer>(
        new MonitorHandlerFactory(pool_.get(), threads * 8, "http_bridge"), *monitor_pool_, msocket, mparams);
    monitor_server_->start();
    webdav::infoLog("HTTP bridge monitoring (/healthz /readyz /poolz) listening on " +
                    cfg_.http_host + ":" + std::to_string(cfg_.monitoring_port));
}

void HttpBridgeServer::stop() {
    if (monitor_server_) {
        monitor_server_->stop();
        monitor_server_.reset();
    }
    if (server_) {
        server_->stop();
        server_.reset();
    }
}

}  // namespace httpbridge
