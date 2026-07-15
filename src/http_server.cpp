#include "http_server.h"
#include "utils.h"
#include "jwt.h"
#include "http_client.h"
#include "client_ip.h"

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
#include <Poco/JSON/Array.h>
#include <Poco/Dynamic/Var.h>
#include <Poco/URI.h>
#include <Poco/SHA2Engine.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <mutex>
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

bool jsonFieldBool(const std::string& body, const std::string& key) {
    try {
        Poco::JSON::Parser p;
        auto obj = p.parse(body).extract<Poco::JSON::Object::Ptr>();
        if (obj && obj->has(key)) return obj->getValue<bool>(key);
    } catch (...) {
    }
    return false;
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
                   std::shared_ptr<OAuthStateStore> oauth_states,
                   std::shared_ptr<AuditPublisher> audit,
                   std::shared_ptr<SessionStore> sessions)
        : cfg_(std::move(cfg)), grpc_(std::move(grpc)), ldap_(std::move(ldap)), tokens_(std::move(tokens)),
          oauth_(std::move(oauth)), oauth_states_(std::move(oauth_states)), audit_(std::move(audit)),
          sessions_(std::move(sessions)) {}

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
        std::vector<std::string> amr;   // auth methods from the verified token (RFC 8176)
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

        // Second-factor completion. Pre-auth: the caller holds only the short-lived
        // mfa_pending token from issueToken, not a full session, so it is handled
        // before the general authenticate().
        if (path == "/v1/auth/2fa") {
            if (method == "POST") return verifyMfa(req, resp);
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
        if (!authenticate(req, resp, id)) return;  // authenticate() emitted 401/403

        auto segs = pathSegments(path);            // [v1, <resource>, <uid>, <sub>?]

        if (segs.size() == 2 && segs[1] == "whoami") return whoami(resp, id);

        // Periodic token refresh: re-mint a fresh JWT from live LDAP roles. Needs a
        // currently-valid token (authenticate() above), so it can't outlive a
        // revoked session beyond token_ttl.
        if (segs.size() == 3 && segs[1] == "auth" && segs[2] == "refresh" && method == "POST")
            return refreshToken(req, resp, id);

        // Token introspection for downstream services (e.g. convert_search_ai):
        // validate the caller's bearer token and return the resolved identity, so
        // one bridge-issued token (LDAP or OAuth) authenticates across services.
        if (segs.size() == 3 && segs[1] == "auth" && segs[2] == "introspect" && method == "GET")
            return introspect(resp, id);

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
                    if (sub == "acls" && method == "GET")           return getAcls(resp, id, uid);
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

    // Add roles to the auth context, aliasing the tenant "administrators" role to
    // the tenant-scoped "tenant_admin" so the core grants a tenant admin full
    // access to THEIR OWN tenant's files — and never beyond it (security review
    // H2). The global "system_admin" bypass is NOT granted here; a platform
    // operator gets it only by being a member of a group literally named
    // "system_admin", which passes through verbatim below.
    static void addRolesAliased(fileengine_rpc::AuthenticationContext* a,
                                const std::vector<std::string>& roles) {
        bool tenantAdmin = false;
        for (const auto& r : roles) {
            if (r.empty()) continue;
            a->add_roles(r);  // verbatim — includes "system_admin" iff the user is in that group
            if (r == "administrators") tenantAdmin = true;
        }
        if (tenantAdmin) a->add_roles("tenant_admin");
    }

    void fillAuth(fileengine_rpc::AuthenticationContext* a, const AuthIdentity& id) {
        a->set_user(id.user);
        a->set_tenant(id.tenant);
        addRolesAliased(a, id.roles);
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
                    ",\"has_renditions\":" + (e.rendition_count() > 0 ? "true" : "false") +
                    ",\"deleted\":" + (e.deleted() ? "true" : "false") +
                    ",\"created_at\":" + std::to_string(e.created_at()) +
                    ",\"modified_at\":" + std::to_string(e.modified_at()) +
                    ",\"owner\":\"" + jsonEscape(e.owner()) + "\"" +
                    ",\"created_by\":\"" + jsonEscape(e.created_by()) + "\"" +
                    ",\"modified_by\":\"" + jsonEscape(e.modified_by()) + "\"}";
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
        // The core soft-deletes the directory node; a non-empty directory is
        // allowed and its subtree is hidden by reachability (a descendant of a
        // deleted folder is unreachable), so no client-side recursion is needed.
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
        // Default to the requesting identity (user + roles + tenant) so a plain
        // self-check reflects the caller's real permissions — including the
        // system_admin bypass. But when impersonating a different principal via
        // ?user, DO NOT inherit the caller's roles: use only ?roles (possibly
        // empty), else the impersonated user would be evaluated with the caller's
        // privileges (e.g. an admin's system_admin bypass).
        fillAuth(a, id);
        if (!qUser.empty()) {
            a->set_user(qUser);
            a->clear_roles();  // impersonation: caller's roles must not leak
            addRolesAliased(a, webdav::splitString(qRoles, ','));
        } else if (!qRoles.empty()) {
            a->clear_roles();
            addRolesAliased(a, webdav::splitString(qRoles, ','));
        }
        auto r = grpc_->checkPermission(rq);
        if (!r.success()) return mapError(resp, r.error());
        sendJson(resp, HTTPResponse::HTTP_OK, std::string("{\"has_permission\":") + (r.has_permission() ? "true" : "false") + "}");
    }

    // List a node's ACL entries (for the ACL editor). Requires MANAGE_ACL on the
    // node (enforced by the core). type: 0 user, 1 role, 2 group, 3 other, 4 claim.
    void getAcls(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        fileengine_rpc::GetResourceAclsRequest rq;
        rq.set_resource_uid(uid);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->getResourceAcls(rq);
        if (!r.success()) return mapError(resp, r.error());
        std::string body = "{\"acls\":[";
        bool first = true;
        for (const auto& e : r.acls()) {
            if (!first) body += ",";
            first = false;
            body += "{\"principal\":\"" + jsonEscape(e.principal()) +
                    "\",\"type\":" + std::to_string(e.type()) +
                    ",\"permissions\":" + std::to_string(e.permissions()) +
                    ",\"effect\":" + std::to_string(e.effect()) + "}";
        }
        body += "]}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
    }

    // Depth-first collect the uids of all descendant DIRECTORIES under `root`,
    // using the caller's identity to list (so a cascade only reaches subtrees the
    // caller can see). Bounded to avoid pathological/cyclic trees.
    // Depth-first collect the uids of ALL descendant entities (files AND
    // directories) under `root`, recursing into directories. Uses the caller's
    // identity to list, so a cascade only reaches subtrees they can see. Bounded
    // to avoid pathological/cyclic trees.
    void collectDescendants(const std::string& root, const AuthIdentity& id,
                            std::vector<std::string>& out, int depth) {
        static const int kMaxAclCascadeDepth = 64;
        if (depth >= kMaxAclCascadeDepth) return;
        fileengine_rpc::ListDirectoryRequest rq;
        rq.set_uid(root);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->listDirectory(rq);
        if (!r.success()) return;
        for (const auto& e : r.entries()) {
            if (e.deleted()) continue;
            out.push_back(e.uid());  // apply to files and directories alike
            if (e.type() == fileengine_rpc::DIRECTORY) {
                collectDescendants(e.uid(), id, out, depth + 1);  // recurse to reach nested files
            }
        }
    }

    void grantPerm(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string body = readBody(req);
        std::string principal = jsonField(body, "principal");
        if (principal.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'principal'"})");
        auto permission = coercePermission(jsonField(body, "permission"));
        auto effect = coerceEffect(jsonField(body, "effect"));
        bool recursive = jsonFieldBool(body, "recursive");

        auto grantOne = [&](const std::string& target) {
            fileengine_rpc::GrantPermissionRequest rq;
            rq.set_resource_uid(target);
            rq.set_principal(principal);
            rq.set_permission(permission);
            rq.set_effect(effect);
            fillAuth(rq.mutable_auth(), id);
            return grpc_->grantPermission(rq);
        };
        auto r = grantOne(uid);
        if (!r.success()) return mapError(resp, r.error());
        if (recursive) {
            // Apply the same grant to every descendant file and directory. Not
            // atomic — a mid-walk failure leaves a partial cascade, safe to re-run.
            std::vector<std::string> nodes;
            collectDescendants(uid, id, nodes, 0);
            for (const auto& n : nodes) {
                auto rr = grantOne(n);
                if (!rr.success()) return mapError(resp, rr.error());
            }
        }
        sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
    }

    void revokePerm(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id, const std::string& uid) {
        std::string body = readBody(req);
        std::string principal = jsonField(body, "principal");
        if (principal.empty()) return sendJson(resp, HTTPResponse::HTTP_BAD_REQUEST, R"({"error":"missing 'principal'"})");
        auto permission = coercePermission(jsonField(body, "permission"));
        auto effect = coerceEffect(jsonField(body, "effect"));
        bool recursive = jsonFieldBool(body, "recursive");

        auto revokeOne = [&](const std::string& target) {
            fileengine_rpc::RevokePermissionRequest rq;
            rq.set_resource_uid(target);
            rq.set_principal(principal);
            rq.set_permission(permission);
            rq.set_effect(effect);
            fillAuth(rq.mutable_auth(), id);
            return grpc_->revokePermission(rq);
        };
        auto r = revokeOne(uid);
        if (!r.success()) return mapError(resp, r.error());
        if (recursive) {
            // Remove the same rule from every descendant file and directory. Not
            // atomic — a mid-walk failure leaves a partial cascade, safe to re-run.
            std::vector<std::string> nodes;
            collectDescendants(uid, id, nodes, 0);
            for (const auto& n : nodes) {
                auto rr = revokeOne(n);
                if (!rr.success()) return mapError(resp, rr.error());
            }
        }
        sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
    }

    // --- roles ---
    // Role administration is admin-only. The core trusts the AuthenticationContext
    // and does NOT gate role RPCs, so this bridge is the enforcement point: without
    // it any authenticated user could self-assign system_admin and bypass every
    // ACL. A tenant admin carries the "administrators" role (aliased to
    // "system_admin" for the active tenant). (Security review C1.)
    bool requireTenantAdmin(const AuthIdentity& id, HTTPServerResponse& resp) {
        for (const auto& r : id.roles)
            if (r == "administrators" || r == "tenant_admin" || r == "system_admin") return true;
        sendJson(resp, HTTPResponse::HTTP_FORBIDDEN, R"({"error":"admin role required"})");
        return false;
    }

    void createRole(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id) {
        if (!requireTenantAdmin(id, resp)) return;
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
        if (!requireTenantAdmin(id, resp)) return;
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
        if (!requireTenantAdmin(id, resp)) return;
        fileengine_rpc::AssignUserToRoleRequest rq;
        rq.set_user(user);
        rq.set_role(role);
        fillAuth(rq.mutable_auth(), id);
        auto r = grpc_->assignUserToRole(rq);
        if (r.success()) sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
        else mapError(resp, r.error());
    }

    void removeUserFromRole(HTTPServerResponse& resp, const AuthIdentity& id, const std::string& role, const std::string& user) {
        if (!requireTenantAdmin(id, resp)) return;
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

        std::vector<std::string> roles, claims, users;

        if (wantRoles && ldap_) {
            // Roles are LDAP groupOfNames under the tenant's subtree — the same set
            // authorization resolves from and the admin console manages. (Formerly
            // sourced from core's role registry, which never sees LDAP-created
            // roles, so tenant roles like "engineering" never appeared.) The LDAP
            // search already does the prefix match, cap, and sort.
            roles = ldap_->searchRoles(id.tenant, q, limit);
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
    // Pure logic lives in webdav::resolveTenant (unit-tested in test_utils.cpp).
    std::string resolveTenant(HTTPServerRequest& req) {
        return webdav::resolveTenant(req.get("X-Tenant", ""), req.getHost());
    }

    // A return URL is allowed only if it begins with a configured prefix. Without
    // this, the callback would hand a valid bridge token to any attacker URL.
    // Pure logic lives in webdav::returnUrlAllowed (unit-tested in test_utils.cpp).
    bool returnAllowed(const std::string& url) {
        return webdav::returnUrlAllowed(cfg_.oauth_return_allowlist, url);
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
        const std::string ip = clientIp(req);
        webdav::UserInfo info = ldap_->getUserInfoByEmail(vid.email);
        if (!info.authenticated || info.user_id.empty()) {
            audit_->emitAuth("login_failure", "denied", vid.email, st.tenant, ip);  // best-effort
            return sendJson(resp, HTTPResponse::HTTP_FORBIDDEN, R"({"error":"no matching user"})");
        }

        // Fail-closed audit (B): OAuth logins are recorded like Basic logins —
        // do not issue a session we cannot audit (when auditing is enabled).
        if (!audit_->emitAuth("login_success", "ok", info.user_id, st.tenant, ip)) {
            return sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                            R"({"error":"audit log unavailable"})");
        }
        // Federated login: the second factor (if any) is enforced by the external
        // IdP, so the session records amr=["oauth"] and is not sent through the
        // bridge's own TOTP/email challenge.
        std::string jti;
        std::string token = mintJwt(info.user_id, st.tenant, {"oauth"}, &jti);
        recordSession(st.tenant, info.user_id, jti, ip);

        // Token returned in the URL fragment (not the query) so it is not sent to
        // the SPA's server or leaked via Referer. The SPA scrubs it from history.
        std::string sep = st.return_to.find('#') == std::string::npos ? "#" : "&";
        std::string location = st.return_to + sep + "token=" + webdav::urlEncode(token) +
                               "&token_type=Bearer&expires_in=" + std::to_string(cfg_.token_ttl);
        resp.redirect(location, HTTPResponse::HTTP_FOUND);
    }

    // True iff the token attests membership in `tenant`: it must appear as a key
    // in the {tenant:[roles]} map, which is built from getRolesByTenant — i.e.
    // the tenants the user actually has roles in. We deliberately do NOT trust
    // the token's active `tenant` claim as a membership proof: issueToken sets it
    // from the request context (host/X-Tenant/default), which can name a tenant
    // the user is not a member of (e.g. the "default" fallback on a bare host).
    // (Security review M3.)
    static bool tokenTenantMember(const Poco::JSON::Object::Ptr& claims, const std::string& tenant) {
        if (tenant.empty()) return false;
        Poco::JSON::Object::Ptr rolesObj = claims->getObject("roles");
        return rolesObj && rolesObj->has(tenant);
    }

    void forbidTenant(HTTPServerResponse& resp, const std::string& tenant) {
        webdav::debugLog("authenticate: tenant membership denied for '" + tenant + "'");
        sendJson(resp, HTTPResponse::HTTP_FORBIDDEN,
                 R"({"error":"not a member of the requested tenant"})");
    }

    // Authenticate via a signed Bearer token (no LDAP) or HTTP Basic (LDAP), and
    // enforce that the caller is a member of the selected tenant. Emits the
    // response (401/403) itself on failure and returns false.
    bool authenticate(HTTPServerRequest& req, HTTPServerResponse& resp, AuthIdentity& out) {
        std::string h = req.get("Authorization", "");
        if (h.compare(0, 7, "Bearer ") == 0) {
            // Verify the signed JWT locally (signature + exp) — no state lookup.
            Poco::JSON::Object::Ptr claims;
            std::string err;
            long now = static_cast<long>(std::time(nullptr));
            if (!jwt::verify(webdav::trim(h.substr(7)), cfg_.jwt_secret, now, claims, err)) {
                webdav::debugLog("authenticate: JWT rejected: " + err);
                unauthorized(resp);
                return false;
            }
            // A pre-auth challenge token (issued before the 2FA step) carries no
            // roles and MUST NOT reach any resource — reject it here (defence in
            // depth; it also has no roles, so it would authorize nothing anyway).
            if (claims->optValue<bool>("mfa_pending", false)) {
                webdav::debugLog("authenticate: rejected mfa_pending token on a resource path");
                unauthorized(resp);
                return false;
            }
            // Per-request tenant selection: an X-Tenant header picks which tenant's
            // roles apply (from the token's {tenant:[roles]} map); otherwise the
            // token's default `tenant` claim is used.
            std::string activeTenant = claims->optValue<std::string>("tenant", std::string());
            std::string xt = req.get("X-Tenant", "");
            if (!xt.empty()) activeTenant = xt;
            // M3: the client cannot pick a tenant it is not a member of.
            if (!tokenTenantMember(claims, activeTenant)) {
                forbidTenant(resp, activeTenant);
                return false;
            }
            identityFromClaims(claims, activeTenant, out);
            // Per-tenant 2FA enforcement on tenant switch (PROPOSAL §4.6): 2FA
            // enrollment is per-user, but the requirement to USE it is per-tenant.
            // A password-only session that becomes active in a tenant which
            // requires 2FA is refused here, so the SPA forces a fresh login (which
            // runs the challenge). Sessions that already cleared a second factor
            // satisfy any requiring tenant. Applies to the bearer (SPA) path only;
            // Basic-auth API/WebDAV is covered by its own (IP-binding) track.
            if (cfg_.mfa_enabled && !sessionHas2fa(out.amr)
                && tenantRequires2fa(out.user, activeTenant)) {
                sendJson(resp, HTTPResponse::HTTP_FORBIDDEN,
                         "{\"error\":\"2fa_required\",\"tenant\":\"" + activeTenant + "\"}");
                return false;
            }
            return true;
        }
        if (!authenticateBasic(req, out)) {
            unauthorized(resp);
            return false;
        }
        // M3: when the client explicitly overrides the tenant via X-Tenant (the
        // attacker-controlled vector), verify LDAP membership. Host/subdomain
        // routing is set by the trusted proxy and left as-is.
        if (!req.get("X-Tenant", "").empty()) {
            bool member = false;
            for (const auto& t : ldap_->getTenantsForUser(out.user))
                if (t == out.tenant) { member = true; break; }
            if (!member) {
                forbidTenant(resp, out.tenant);
                return false;
            }
        }
        return true;
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

        // Record the attempted identity up front so a caller (issueToken) can
        // audit a login_failure with the username even when the bind fails.
        out.user = user;

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

    // Build a signed HS256 JWT carrying the user's identity and their roles in
    // EVERY tenant they belong to ({tenant:[roles]}). `activeTenant` is recorded
    // as the token's default tenant context. Roles are resolved live from LDAP.
    // `amr` records the authentication methods that produced this session (RFC
    // 8176-style): ["pwd"] for a password-only login, and once a second factor is
    // verified the descriptive method name is appended —
    // ["pwd","totp"|"email"|"recovery"] (or ["oauth"] for a federated login).
    std::string mintJwt(const std::string& user, const std::string& activeTenant,
                        const std::vector<std::string>& amr = {"pwd"},
                        std::string* outJti = nullptr) {
        auto byTenant = ldap_->getRolesByTenant(user);

        Poco::JSON::Object::Ptr claims = new Poco::JSON::Object();
        long now = static_cast<long>(std::time(nullptr));
        claims->set("iss", cfg_.jwt_issuer);
        claims->set("sub", user);
        claims->set("email", user);
        claims->set("tenant", activeTenant);
        claims->set("iat", static_cast<Poco::Int64>(now));
        claims->set("exp", static_cast<Poco::Int64>(now + cfg_.token_ttl));
        std::string jti = randomCodeVerifier();
        if (outJti) *outJti = jti;
        claims->set("jti", jti);

        Poco::JSON::Object::Ptr rolesObj = new Poco::JSON::Object();
        for (const auto& kv : byTenant) {
            Poco::JSON::Array::Ptr arr = new Poco::JSON::Array();
            for (const auto& r : kv.second) arr->add(r);
            rolesObj->set(kv.first, arr);
        }
        claims->set("roles", rolesObj);

        Poco::JSON::Array::Ptr amrArr = new Poco::JSON::Array();
        for (const auto& m : amr) amrArr->add(m);
        claims->set("amr", amrArr);
        return jwt::sign(claims, cfg_.jwt_secret);
    }

    // ---- WebDAV session presence (PROPOSAL §14) ------------------------------
    // The tenant's effective (clamped) session TTL, from ldap_manager, cached
    // briefly. Falls back to the deployment default when the lookup is unavailable.
    long sessionTtl(const std::string& tenant, const std::string& ip) {
        long now = static_cast<long>(std::time(nullptr));
        {
            std::lock_guard<std::mutex> g(sessTtlMu_);
            auto it = sessTtlCache_.find(tenant);
            if (it != sessTtlCache_.end() && it->second.second > now) return it->second.first;
        }
        long ttl = cfg_.webdav_session_ttl_default;
        if (!cfg_.ldap_manager_url.empty() && !cfg_.mfa_internal_secret.empty()) {
            HttpClient client(3);
            Poco::JSON::Object::Ptr body = new Poco::JSON::Object();
            body->set("tenant", tenant);
            std::ostringstream bs; body->stringify(bs);
            HttpResult r = client.postJson(cfg_.ldap_manager_url + "/internal/webdav/session-ttl",
                                           bs.str(), mfaHeaders(ip));
            if (r.ok && r.status == 200) {
                try {
                    Poco::JSON::Parser p;
                    auto o = p.parse(r.body).extract<Poco::JSON::Object::Ptr>();
                    ttl = o->optValue<Poco::Int64>("ttl_seconds", static_cast<Poco::Int64>(ttl));
                } catch (...) {}
            }
        }
        {
            std::lock_guard<std::mutex> g(sessTtlMu_);
            sessTtlCache_[tenant] = {ttl, now + 60};  // 60s cache
        }
        return ttl;
    }

    // Record a live Web-UI session so webdav_bridge can gate external WebDAV on it.
    // Best-effort — never blocks login/refresh (§14: a failed write just means the
    // gate can't see this session until the next refresh).
    void recordSession(const std::string& tenant, const std::string& uid,
                       const std::string& jti, const std::string& ip) {
        if (!sessions_ || !sessions_->enabled() || jti.empty()) return;
        long score = static_cast<long>(std::time(nullptr)) + sessionTtl(tenant, ip);
        sessions_->add(tenant, uid, jti + "|" + ip, score);
    }

    // Remove a session on logout. member = "{jti}|{ip}" with the CURRENT request IP;
    // a mid-session egress-IP change means logout misses and the member ages out at
    // its score instead (the §14 backstop).
    void dropSession(const std::string& tenant, const std::string& uid,
                     const std::string& jti, const std::string& ip) {
        if (!sessions_ || !sessions_->enabled() || jti.empty()) return;
        sessions_->remove(tenant, uid, jti + "|" + ip);
    }

    // Mint a short-lived, IP-bound pre-auth token issued after a password succeeds
    // but before the second factor is verified (PROPOSAL §4.6). It carries NO roles
    // and an explicit `mfa_pending` marker, so even if a resource path failed to
    // gate it, it authorizes nothing. `mip` binds it to the client IP that logged
    // in, so a stolen challenge token can't be completed from elsewhere.
    std::string mintMfaPending(const std::string& user, const std::string& tenant,
                               const std::string& ip) {
        Poco::JSON::Object::Ptr claims = new Poco::JSON::Object();
        long now = static_cast<long>(std::time(nullptr));
        claims->set("iss", cfg_.jwt_issuer);
        claims->set("sub", user);
        claims->set("tenant", tenant);
        claims->set("iat", static_cast<Poco::Int64>(now));
        claims->set("exp", static_cast<Poco::Int64>(now + cfg_.mfa_challenge_ttl));
        claims->set("jti", randomCodeVerifier());
        claims->set("mfa_pending", true);
        claims->set("mip", ip);
        Poco::JSON::Array::Ptr amrArr = new Poco::JSON::Array();
        amrArr->add("pwd");
        claims->set("amr", amrArr);
        return jwt::sign(claims, cfg_.jwt_secret);
    }

    // ---- ldap_manager internal 2FA API (server-to-server) --------------------
    // All calls carry X-Internal-Auth (shared secret) and forward the end-user's
    // IP as X-Forwarded-For so ldap_manager rate-limits on the real client.

    std::map<std::string, std::string> mfaHeaders(const std::string& ip) {
        return {{"X-Internal-Auth", cfg_.mfa_internal_secret}, {"X-Forwarded-For", ip}};
    }

    // POST /internal/2fa/required. Returns true on a clean 200 and fills the outs;
    // returns false on any transport/HTTP/parse failure (caller fails closed).
    // `required` = challenge at login (enrolled OR tenant mandates); `tenantRequires`
    // = the tenant's mandate alone (for the tenant-switch gate).
    bool mfaRequired(const std::string& user, const std::string& tenant,
                     bool& required, bool& mustEnroll, std::vector<std::string>& methods,
                     bool& tenantRequires) {
        HttpClient client(5);
        Poco::JSON::Object::Ptr body = new Poco::JSON::Object();
        body->set("uid", user);
        body->set("tenant", tenant);
        std::ostringstream bs; body->stringify(bs);
        HttpResult r = client.postJson(cfg_.ldap_manager_url + "/internal/2fa/required",
                                       bs.str(), mfaHeaders(""));
        if (!r.ok || r.status != 200) {
            webdav::warnLog("mfaRequired: ldap_manager unreachable/failed (status " +
                            std::to_string(r.status) + " " + r.error + ")");
            return false;
        }
        try {
            Poco::JSON::Parser p;
            auto o = p.parse(r.body).extract<Poco::JSON::Object::Ptr>();
            required = o->optValue<bool>("required", true);
            mustEnroll = o->optValue<bool>("must_enroll", false);
            tenantRequires = o->optValue<bool>("tenant_requires", required);
            methods.clear();
            if (auto arr = o->getArray("methods"))
                for (size_t i = 0; i < arr->size(); ++i)
                    methods.push_back(arr->getElement<std::string>(i));
        } catch (...) {
            return false;
        }
        return true;
    }

    // POST /internal/2fa/verify. Returns true only on {ok:true}.
    bool mfaVerify(const std::string& user, const std::string& tenant,
                   const std::string& method, const std::string& code, const std::string& ip) {
        HttpClient client(5);
        Poco::JSON::Object::Ptr body = new Poco::JSON::Object();
        body->set("uid", user);
        body->set("tenant", tenant);
        body->set("method", method);
        body->set("code", code);
        std::ostringstream bs; body->stringify(bs);
        HttpResult r = client.postJson(cfg_.ldap_manager_url + "/internal/2fa/verify",
                                       bs.str(), mfaHeaders(ip));
        if (!r.ok || r.status != 200) return false;
        try {
            Poco::JSON::Parser p;
            auto o = p.parse(r.body).extract<Poco::JSON::Object::Ptr>();
            return o->optValue<bool>("ok", false);
        } catch (...) {
            return false;
        }
    }

    // POST /internal/2fa/email-challenge — asks ldap_manager to mail a one-time
    // code. Returns true if the request was accepted (best-effort delivery).
    bool mfaEmailChallenge(const std::string& user, const std::string& tenant,
                           const std::string& ip) {
        HttpClient client(5);
        Poco::JSON::Object::Ptr body = new Poco::JSON::Object();
        body->set("uid", user);
        body->set("tenant", tenant);
        std::ostringstream bs; body->stringify(bs);
        HttpResult r = client.postJson(cfg_.ldap_manager_url + "/internal/2fa/email-challenge",
                                       bs.str(), mfaHeaders(ip));
        return r.ok && r.status == 200;
    }

    // Grace enrollment (mandated-but-unenrolled user, during login). begin returns
    // the setup blob (secret + otpauth uri) to pass through to the SPA.
    HttpResult mfaEnrollBegin(const std::string& user, const std::string& tenant,
                              const std::string& ip) {
        HttpClient client(5);
        Poco::JSON::Object::Ptr body = new Poco::JSON::Object();
        body->set("uid", user);
        body->set("tenant", tenant);
        std::ostringstream bs; body->stringify(bs);
        return client.postJson(cfg_.ldap_manager_url + "/internal/2fa/enroll-begin",
                               bs.str(), mfaHeaders(ip));
    }

    // complete verifies the code against the pending secret + enables 2FA; on
    // success `recoveryJson` receives the recovery_codes array (verbatim JSON).
    bool mfaEnrollComplete(const std::string& user, const std::string& tenant,
                           const std::string& code, const std::string& ip,
                           std::string& recoveryJson) {
        HttpClient client(5);
        Poco::JSON::Object::Ptr body = new Poco::JSON::Object();
        body->set("uid", user);
        body->set("tenant", tenant);
        body->set("code", code);
        std::ostringstream bs; body->stringify(bs);
        HttpResult r = client.postJson(cfg_.ldap_manager_url + "/internal/2fa/enroll-complete",
                                       bs.str(), mfaHeaders(ip));
        if (!r.ok || r.status != 200) return false;
        try {
            Poco::JSON::Parser p;
            auto o = p.parse(r.body).extract<Poco::JSON::Object::Ptr>();
            if (!o->optValue<bool>("ok", false)) return false;
            if (auto arr = o->getArray("recovery_codes")) {
                std::ostringstream rs; arr->stringify(rs); recoveryJson = rs.str();
            } else {
                recoveryJson = "[]";
            }
            return true;
        } catch (...) {
            return false;
        }
    }

    // A session that carries any of these amr values has satisfied a second factor
    // (or federated the check to an IdP) and may operate in any requiring tenant.
    // A password-only session (amr = ["pwd"]) has not.
    static bool sessionHas2fa(const std::vector<std::string>& amr) {
        for (const auto& m : amr)
            if (m == "otp" || m == "totp" || m == "email" || m == "recovery" || m == "oauth")
                return true;
        return false;
    }

    // Whether the tenant requires 2FA (per-tenant policy; user-independent), cached
    // briefly. Only consulted for password-only sessions, so most requests never
    // hit it. Fail-closed on an ldap_manager error (treat as required) — consistent
    // with the login path, and the short TTL absorbs brief blips.
    bool tenantRequires2fa(const std::string& user, const std::string& tenant) {
        const long now = static_cast<long>(std::time(nullptr));
        {
            std::lock_guard<std::mutex> lk(requiresMu_);
            auto it = requiresCache_.find(tenant);
            if (it != requiresCache_.end() && it->second.second > now)
                return it->second.first;
        }
        bool required = false, mustEnroll = false, tenantRequires = false;
        std::vector<std::string> methods;
        // The switch gate enforces the tenant's MANDATE (not per-user enrollment),
        // so it reads tenant_requires — a password-only (un-enrolled) session
        // entering a mandating tenant must re-login + enroll.
        const bool ok = mfaRequired(user, tenant, required, mustEnroll, methods, tenantRequires);
        const bool requires = ok ? tenantRequires : true;  // fail-closed
        {
            std::lock_guard<std::mutex> lk(requiresMu_);
            requiresCache_[tenant] = {requires, now + 30};
        }
        return requires;
    }

    // Fill an AuthIdentity from verified JWT claims, scoping roles to the active
    // tenant's entry in the {tenant:[roles]} map.
    void identityFromClaims(const Poco::JSON::Object::Ptr& claims,
                            const std::string& activeTenant, AuthIdentity& out) {
        out.user = claims->optValue<std::string>("sub", std::string());
        out.tenant = activeTenant;
        out.roles.clear();
        Poco::JSON::Object::Ptr rolesObj = claims->getObject("roles");
        if (rolesObj && !activeTenant.empty() && rolesObj->has(activeTenant)) {
            Poco::JSON::Array::Ptr arr = rolesObj->getArray(activeTenant);
            if (arr) {
                for (size_t i = 0; i < arr->size(); ++i)
                    out.roles.push_back(arr->getElement<std::string>(i));
            }
        }
        out.amr.clear();
        if (auto amrArr = claims->getArray("amr")) {
            for (size_t i = 0; i < amrArr->size(); ++i)
                out.amr.push_back(amrArr->getElement<std::string>(i));
        }
    }

    // Client IP for the audit trail: first X-Forwarded-For hop (the bridge sits
    // behind the nginx proxy), else the socket peer.
    std::string clientIp(HTTPServerRequest& req) {
        std::string peer;
        try { peer = req.clientAddress().host().toString(); } catch (...) {}
        // Trusted-proxy-aware resolution (client_ip.h). With FILEENGINE_TRUSTED_PROXIES
        // unset this keeps the dev behavior (first XFF hop); set it in production so
        // XFF can't be spoofed to forge the MFA IP binding / audit source.
        return resolveClientIp(peer, req.get("X-Forwarded-For", ""), cfg_.trusted_proxies);
    }

    void issueToken(HTTPServerRequest& req, HTTPServerResponse& resp) {
        const std::string ip = clientIp(req);
        AuthIdentity id;
        if (!authenticateBasic(req, id)) {
            // login_failure — the attempted username (from authenticateBasic) is the
            // brute-force signal; tenant is still resolvable from the request.
            const std::string attempted = id.user.empty() ? "<unknown>" : id.user;
            const std::string tenant = webdav::resolveTenant(req.get("X-Tenant", ""), req.getHost());
            audit_->emitAuth("login_failure", "denied", attempted, tenant, ip);
            return unauthorized(resp);
        }
        // Stamp a tenant the user actually belongs to. LDAP bind succeeds regardless
        // of tenant, and tenant resolution (X-Tenant / host / "default") can land on
        // a tenant the user is NOT a member of — the token would then be rejected by
        // the M3 membership check on every request (a login that "works" but 403s
        // everything). Mirror refreshToken: keep the resolved tenant if valid, else
        // fall back to a tenant the user does belong to (reject if none).
        {
            auto tenants = ldap_->getTenantsForUser(id.user);
            if (tenants.empty()) {
                audit_->emitAuth("login_failure", "denied", id.user, id.tenant, ip);
                return unauthorized(resp);
            }
            bool member = false;
            for (const auto& t : tenants) if (t == id.tenant) { member = true; break; }
            if (!member) id.tenant = tenants.front();
        }
        // Fail-closed write-ahead (§6): do not issue a session we cannot audit.
        if (!audit_->emitAuth("login_success", "ok", id.user, id.tenant, ip)) {
            return sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                            R"({"error":"audit log unavailable"})");
        }

        // Two-factor gate (PROPOSAL §4.6). When enabled, ask ldap_manager whether
        // this identity needs a second factor. Fail-closed: an unreachable identity
        // service means we cannot confirm the user is exempt, so we issue no session.
        if (cfg_.mfa_enabled) {
            bool required = false, mustEnroll = false, tenantRequires = false;
            std::vector<std::string> methods;
            if (!mfaRequired(id.user, id.tenant, required, mustEnroll, methods, tenantRequires)) {
                return sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                                R"({"error":"2FA service unavailable"})");
            }
            if (required) {
                std::string mtok = mintMfaPending(id.user, id.tenant, ip);
                audit_->emitAuth("mfa_challenge", "ok", id.user, id.tenant, ip);
                Poco::JSON::Object out;
                out.set("mfa_required", true);
                out.set("mfa_token", mtok);
                out.set("token_type", "MfaPending");
                out.set("expires_in", cfg_.mfa_challenge_ttl);
                out.set("must_enroll", mustEnroll);
                Poco::JSON::Array::Ptr marr = new Poco::JSON::Array();
                for (const auto& m : methods) marr->add(m);
                out.set("methods", marr);
                std::ostringstream os; out.stringify(os);
                return sendJson(resp, HTTPResponse::HTTP_OK, os.str());
            }
        }

        std::string jti;
        std::string token = mintJwt(id.user, id.tenant, {"pwd"}, &jti);
        recordSession(id.tenant, id.user, jti, ip);
        sendJson(resp, HTTPResponse::HTTP_OK,
                 "{\"token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" +
                 std::to_string(cfg_.token_ttl) + "}");
    }

    // POST /v1/auth/2fa — complete (or drive) a second-factor challenge.
    // Body: { "mfa_token": <the pending token from issueToken>,
    //         "action": "verify" (default) | "send" | "enroll_begin" | "enroll_complete",
    //         "method": "totp" | "email" | "recovery",
    //         "code":   <required for verify / enroll_complete> }
    // "send" emails a one-time code; "verify" checks a code and mints the full
    // session (amr=["pwd", <method>]); "enroll_begin"/"enroll_complete" drive grace
    // enrollment for a mandated-but-unenrolled user, ending in a full session.
    void verifyMfa(HTTPServerRequest& req, HTTPServerResponse& resp) {
        const std::string ip = clientIp(req);
        const std::string body = readBody(req);
        const std::string mfaToken = jsonField(body, "mfa_token");
        std::string action = jsonField(body, "action");
        if (action.empty()) action = "verify";
        std::string vmethod = jsonField(body, "method");
        if (vmethod.empty()) vmethod = "totp";
        const std::string code = jsonField(body, "code");

        // Validate the pending token: signature + exp, the mfa_pending marker, and
        // the IP binding (a stolen challenge token can't be completed elsewhere).
        Poco::JSON::Object::Ptr claims;
        std::string err;
        long now = static_cast<long>(std::time(nullptr));
        if (mfaToken.empty() ||
            !jwt::verify(mfaToken, cfg_.jwt_secret, now, claims, err) ||
            !claims->optValue<bool>("mfa_pending", false)) {
            return unauthorized(resp);
        }
        const std::string user = claims->optValue<std::string>("sub", std::string());
        const std::string tenant = claims->optValue<std::string>("tenant", std::string());
        const std::string boundIp = claims->optValue<std::string>("mip", std::string());
        if (user.empty() || boundIp != ip) {
            audit_->emitAuth("mfa_failure", "denied", user.empty() ? "<unknown>" : user,
                             tenant, ip);
            return unauthorized(resp);
        }

        if (action == "send") {
            bool sent = (vmethod == "email") && mfaEmailChallenge(user, tenant, ip);
            Poco::JSON::Object out;
            out.set("sent", sent);
            std::ostringstream os; out.stringify(os);
            return sendJson(resp, HTTPResponse::HTTP_OK, os.str());
        }

        // Grace enrollment: begin returns the TOTP setup blob (QR/secret) to show.
        if (action == "enroll_begin") {
            HttpResult r = mfaEnrollBegin(user, tenant, ip);
            if (!r.ok || r.status != 200) {
                return sendJson(resp, HTTPResponse::HTTP_BAD_GATEWAY,
                                R"({"error":"could not start enrollment"})");
            }
            return sendJson(resp, HTTPResponse::HTTP_OK, r.body);  // pass through setup blob
        }
        // Grace enrollment: verify the code, enable 2FA, and issue the session.
        if (action == "enroll_complete") {
            std::string recoveryJson;
            if (!mfaEnrollComplete(user, tenant, code, ip, recoveryJson)) {
                audit_->emitAuth("mfa_failure", "denied", user, tenant, ip);
                return sendJson(resp, HTTPResponse::HTTP_UNAUTHORIZED,
                                R"({"error":"invalid code"})");
            }
            if (!audit_->emitAuth("mfa_success", "ok", user, tenant, ip)) {
                return sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                                R"({"error":"audit log unavailable"})");
            }
            std::string jti;
            std::string token = mintJwt(user, tenant, {"pwd", "totp"}, &jti);
            recordSession(tenant, user, jti, ip);
            return sendJson(resp, HTTPResponse::HTTP_OK,
                     "{\"token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" +
                     std::to_string(cfg_.token_ttl) + ",\"recovery_codes\":" + recoveryJson + "}");
        }

        // action == verify
        if (!mfaVerify(user, tenant, vmethod, code, ip)) {
            audit_->emitAuth("mfa_failure", "denied", user, tenant, ip);
            return sendJson(resp, HTTPResponse::HTTP_UNAUTHORIZED,
                            R"({"error":"invalid or expired second factor"})");
        }
        if (!audit_->emitAuth("mfa_success", "ok", user, tenant, ip)) {
            return sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                            R"({"error":"audit log unavailable"})");
        }
        std::string jti;
        std::string token = mintJwt(user, tenant, {"pwd", vmethod}, &jti);
        recordSession(tenant, user, jti, ip);
        sendJson(resp, HTTPResponse::HTTP_OK,
                 "{\"token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" +
                 std::to_string(cfg_.token_ttl) + "}");
    }

    // Periodic re-mint: reaching here means the caller's current JWT already
    // verified. Re-resolve roles from LDAP and issue a fresh short-lived token, so
    // Renew a session token. RE-VALIDATES the user against LDAP at refresh time
    // (live), so a deactivated/removed account cannot extend its session, and the
    // new token carries fresh, non-stale security claims (roles + tenants re-read
    // from the directory, not copied from the old token). Access revoked in LDAP
    // stops the very next refresh; an un-refreshed token expires within token_ttl.
    void refreshToken(HTTPServerRequest& req, HTTPServerResponse& resp, const AuthIdentity& id) {
        const std::string ip = clientIp(req);
        // The user must still exist and belong to at least one tenant. In this
        // directory model, deactivation = removal from the tenant's groups, so an
        // empty tenant set means the account is gone/disabled.
        auto tenants = ldap_->getTenantsForUser(id.user);
        if (tenants.empty()) {
            audit_->emitAuth("token_refresh", "denied", id.user, id.tenant, ip);  // best-effort
            return unauthorized(resp);  // force re-login
        }
        // Keep the caller's active tenant if it is still valid; otherwise fall
        // back to a tenant they still belong to (never stamp a stale tenant).
        std::string activeTenant = id.tenant;
        bool stillMember = false;
        for (const auto& t : tenants) if (t == activeTenant) { stillMember = true; break; }
        if (!stillMember) activeTenant = tenants.front();
        // Fail-closed audit (B): never renew a session we cannot record (when
        // auditing is enabled).
        if (!audit_->emitAuth("token_refresh", "ok", id.user, activeTenant, ip)) {
            return sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE,
                            R"({"error":"audit log unavailable"})");
        }
        // mintJwt re-reads roles per tenant live (getRolesByTenant), so the new
        // token reflects current group/role membership, not the old claims. The
        // amr is carried over so a 2FA-completed session doesn't silently downgrade
        // to password-only on refresh (defaults to ["pwd"] for legacy tokens).
        std::vector<std::string> amr = id.amr.empty() ? std::vector<std::string>{"pwd"} : id.amr;
        std::string jti;
        std::string token = mintJwt(id.user, activeTenant, amr, &jti);
        // Re-score the session under the new jti; the previous jti ages out at its
        // score (the §14 backstop) — AuthIdentity doesn't carry it to ZREM here.
        recordSession(activeTenant, id.user, jti, ip);
        sendJson(resp, HTTPResponse::HTTP_OK,
                 "{\"token\":\"" + token + "\",\"token_type\":\"Bearer\",\"expires_in\":" +
                 std::to_string(cfg_.token_ttl) + "}");
    }

    void revokeToken(HTTPServerRequest& req, HTTPServerResponse& resp) {
        // The JWT itself stays stateless (it still expires within token_ttl), but
        // logout now actively cuts the WebDAV session-presence entry (PROPOSAL §14)
        // so external WebDAV stops working immediately — and records the logout for
        // the audit trail. Both are best-effort and never block the 204.
        std::string h = req.get("Authorization", "");
        if (h.compare(0, 7, "Bearer ") == 0) {
            Poco::JSON::Object::Ptr claims;
            std::string err;
            long now = static_cast<long>(std::time(nullptr));
            if (jwt::verify(webdav::trim(h.substr(7)), cfg_.jwt_secret, now, claims, err)) {
                const std::string sub = claims->optValue<std::string>("sub", std::string());
                const std::string tenant = claims->optValue<std::string>("tenant", std::string());
                const std::string jti = claims->optValue<std::string>("jti", std::string());
                const std::string ip = clientIp(req);
                audit_->emitAuth("logout", "ok", sub, tenant, ip);
                dropSession(tenant, sub, jti, ip);
            }
        }
        sendStatus(resp, HTTPResponse::HTTP_NO_CONTENT);
    }

    void whoami(HTTPServerResponse& resp, const AuthIdentity& id) {
        std::string body = "{\"user\":\"" + jsonEscape(id.user) +
                           "\",\"tenant\":\"" + jsonEscape(id.tenant) +
                           "\",\"roles\":" + jsonArray(id.roles) + "}";
        sendJson(resp, HTTPResponse::HTTP_OK, body);
    }

    // RFC 7662-style token introspection. The request already passed
    // authenticate(), so reaching here means the bearer token is valid; reply
    // with active=true and the resolved identity (honoring X-Tenant). Invalid
    // tokens are rejected upstream with 401. Downstream services call this to
    // accept a bridge token without re-authenticating the user themselves.
    void introspect(HTTPServerResponse& resp, const AuthIdentity& id) {
        std::string body = "{\"active\":true,\"user\":\"" + jsonEscape(id.user) +
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
        const bool coreOk = r.success();
        // A-ii: when auditing is enabled, surface its reachability so an audit
        // outage drains this instance (audit is a hard dependency for logins).
        const bool auditOk = !audit_->enabled() || audit_->healthy();
        if (coreOk && auditOk) {
            sendJson(resp, HTTPResponse::HTTP_OK, R"({"status":"ready","core":true,"audit":true})");
        } else {
            std::string body = std::string(R"({"status":"unavailable","core":)") +
                               (coreOk ? "true" : "false") + R"(,"audit":)" +
                               (auditOk ? "true" : "false") +
                               (coreOk ? "" : std::string(R"(,"error":")") + r.error() + R"(")") + "}";
            sendJson(resp, HTTPResponse::HTTP_SERVICE_UNAVAILABLE, body);
        }
    }

    Config cfg_;
    std::shared_ptr<webdav::GRPCClientWrapper> grpc_;
    std::shared_ptr<webdav::LDAPAuthenticator> ldap_;
    std::shared_ptr<TokenStore> tokens_;
    std::shared_ptr<OAuthProvider> oauth_;
    std::shared_ptr<OAuthStateStore> oauth_states_;
    std::shared_ptr<AuditPublisher> audit_;
    std::shared_ptr<SessionStore> sessions_;
    // Per-tenant WebDAV session-TTL cache (tenant -> {ttl_seconds, expiry-epoch}),
    // so the login/refresh path doesn't call ldap_manager on every request.
    inline static std::mutex sessTtlMu_;
    inline static std::map<std::string, std::pair<long, long>> sessTtlCache_;
    // Per-tenant "requires 2FA" cache (tenant -> {requires, expiry-epoch}), for the
    // tenant-switch enforcement gate. Short-lived; user-independent. `inline static`
    // so it is shared across the per-request handler instances (process-global).
    inline static std::mutex requiresMu_;
    inline static std::map<std::string, std::pair<bool, long>> requiresCache_;
};

class HandlerFactory : public HTTPRequestHandlerFactory {
public:
    HandlerFactory(Config cfg,
                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                   std::shared_ptr<webdav::LDAPAuthenticator> ldap,
                   std::shared_ptr<TokenStore> tokens,
                   std::shared_ptr<OAuthProvider> oauth,
                   std::shared_ptr<OAuthStateStore> oauth_states,
                   std::shared_ptr<AuditPublisher> audit,
                   std::shared_ptr<SessionStore> sessions)
        : cfg_(std::move(cfg)), grpc_(std::move(grpc)), ldap_(std::move(ldap)), tokens_(std::move(tokens)),
          oauth_(std::move(oauth)), oauth_states_(std::move(oauth_states)), audit_(std::move(audit)),
          sessions_(std::move(sessions)) {}

    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest&) override {
        return new RequestHandler(cfg_, grpc_, ldap_, tokens_, oauth_, oauth_states_, audit_, sessions_);
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
};

}  // namespace

HttpBridgeServer::HttpBridgeServer(const Config& cfg,
                                   std::shared_ptr<webdav::GRPCClientWrapper> grpc,
                                   std::shared_ptr<webdav::LDAPAuthenticator> ldap)
    : cfg_(cfg), grpc_(std::move(grpc)), ldap_(std::move(ldap)),
      tokens_(std::make_shared<TokenStore>(cfg.token_ttl)),
      oauth_(std::make_shared<OAuthProvider>(OAuthProvider::fromEnv(cfg.oauth_redirect_base))),
      oauth_states_(std::make_shared<OAuthStateStore>(cfg.oauth_state_ttl)),
      audit_(std::make_shared<AuditPublisher>(AuditPublisher::Options{
          cfg.audit_enabled, cfg.redis_host, cfg.redis_port, cfg.redis_password,
          cfg.redis_db, cfg.audit_stream, cfg.audit_stream_maxlen})),
      sessions_(std::make_shared<SessionStore>(SessionStore::Options{
          cfg.webdav_ip_binding_enabled, cfg.redis_host, cfg.redis_port, cfg.redis_password,
          cfg.redis_db, "webdav:session:"})) {}

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
    MonitorHandler(Poco::ThreadPool* pool, int maxQueued, std::string service,
                   std::vector<std::string> allowIps)
        : pool_(pool), maxQueued_(maxQueued), service_(std::move(service)),
          allowIps_(std::move(allowIps)) {}
    void handleRequest(HTTPServerRequest& req, HTTPServerResponse& resp) override {
        // Optional IP allowlist (L2). Enforced before serving any probe.
        if (!allowIps_.empty()) {
            std::string ip;
            try { ip = req.clientAddress().host().toString(); } catch (...) {}
            bool ok = false;
            for (const auto& a : allowIps_) if (a == ip) { ok = true; break; }
            if (!ok) return sendJson(resp, HTTPResponse::HTTP_FORBIDDEN, R"({"error":"forbidden"})");
        }
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
    std::vector<std::string> allowIps_;
};

class MonitorHandlerFactory : public HTTPRequestHandlerFactory {
public:
    MonitorHandlerFactory(Poco::ThreadPool* pool, int maxQueued, std::string service,
                          std::vector<std::string> allowIps)
        : pool_(pool), maxQueued_(maxQueued), service_(std::move(service)),
          allowIps_(std::move(allowIps)) {}
    HTTPRequestHandler* createRequestHandler(const HTTPServerRequest&) override {
        return new MonitorHandler(pool_, maxQueued_, service_, allowIps_);
    }
private:
    Poco::ThreadPool* pool_;
    int maxQueued_;
    std::string service_;
    std::vector<std::string> allowIps_;
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
        new HandlerFactory(cfg_, grpc_, ldap_, tokens_, oauth_, oauth_states_, audit_, sessions_), *pool_, socket, params);
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
        Poco::Net::SocketAddress(cfg_.monitoring_host, static_cast<Poco::UInt16>(cfg_.monitoring_port)));
    monitor_server_ = std::make_unique<Poco::Net::HTTPServer>(
        new MonitorHandlerFactory(pool_.get(), threads * 8, "http_bridge", cfg_.monitoring_allow_ips), *monitor_pool_, msocket, mparams);
    monitor_server_->start();
    webdav::infoLog("HTTP bridge monitoring (/healthz /readyz /poolz) listening on " +
                    cfg_.monitoring_host + ":" + std::to_string(cfg_.monitoring_port));
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
