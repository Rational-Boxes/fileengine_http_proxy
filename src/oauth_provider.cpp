#include "oauth_provider.h"
#include "utils.h"

#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Array.h>
#include <Poco/Dynamic/Var.h>

namespace httpbridge {

namespace {

// Per-provider env var: OAUTH_<NAME>_<KEY> (name upper-cased).
std::string providerEnv(const std::string& name, const std::string& key,
                        const std::string& def = "") {
    std::string upper = name;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return webdav::getEnvOrDefault("OAUTH_" + upper + "_" + key, def);
}

// Read a field that a provider may encode as either a JSON bool or string
// ("true"/"false") — Google sends bool, some send string.
bool boolField(const Poco::JSON::Object::Ptr& obj, const std::string& key) {
    if (!obj || !obj->has(key)) return false;
    Poco::Dynamic::Var v = obj->get(key);
    try {
        if (v.isBoolean()) return v.convert<bool>();
        if (v.isString()) {
            std::string s = v.convert<std::string>();
            return s == "true" || s == "1";
        }
        return v.convert<bool>();
    } catch (...) {
        return false;
    }
}

std::string strField(const Poco::JSON::Object::Ptr& obj, const std::string& key) {
    if (!obj || !obj->has(key) || obj->isNull(key)) return "";
    try {
        return obj->getValue<std::string>(key);
    } catch (...) {
        return "";
    }
}

}  // namespace

OAuthProvider OAuthProvider::fromEnv(const std::string& redirect_base) {
    OAuthProvider self;
    std::string list = webdav::getEnvOrDefault("OAUTH_PROVIDERS", "");
    for (const auto& raw : webdav::splitString(list, ',')) {
        std::string name = webdav::trim(raw);
        if (name.empty()) continue;

        OAuthProviderConfig cfg;
        cfg.name = name;
        std::string kind = providerEnv(name, "KIND", "oidc");
        for (char& c : kind) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        cfg.kind = (kind == "github") ? OAuthProviderConfig::GITHUB : OAuthProviderConfig::OIDC;

        cfg.client_id = providerEnv(name, "CLIENT_ID");
        cfg.client_secret = providerEnv(name, "CLIENT_SECRET");
        cfg.auth_url = providerEnv(name, "AUTH_URL");
        cfg.token_url = providerEnv(name, "TOKEN_URL");
        cfg.userinfo_url = providerEnv(name, "USERINFO_URL");
        cfg.emails_url = providerEnv(name, "EMAILS_URL");
        cfg.scopes = providerEnv(name, "SCOPES",
                                 cfg.kind == OAuthProviderConfig::GITHUB ? "read:user user:email"
                                                                         : "openid email profile");
        cfg.redirect_uri = redirect_base + "/v1/auth/oauth/" + name + "/callback";

        if (cfg.client_id.empty() || cfg.auth_url.empty() || cfg.token_url.empty()) {
            webdav::warnLog("OAuthProvider: skipping provider '" + name +
                            "' — missing CLIENT_ID/AUTH_URL/TOKEN_URL");
            continue;
        }
        webdav::infoLog("OAuthProvider: configured provider '" + name + "' (" +
                        (cfg.kind == OAuthProviderConfig::GITHUB ? "github" : "oidc") + ")");
        self.providers_[name] = std::move(cfg);
    }
    return self;
}

const OAuthProviderConfig* OAuthProvider::get(const std::string& name) const {
    auto it = providers_.find(name);
    return it == providers_.end() ? nullptr : &it->second;
}

std::string OAuthProvider::buildAuthorizeUrl(const OAuthProviderConfig& cfg,
                                             const std::string& state,
                                             const std::string& code_challenge) const {
    std::string sep = cfg.auth_url.find('?') == std::string::npos ? "?" : "&";
    return cfg.auth_url + sep +
           "response_type=code" +
           "&client_id=" + webdav::urlEncode(cfg.client_id) +
           "&redirect_uri=" + webdav::urlEncode(cfg.redirect_uri) +
           "&scope=" + webdav::urlEncode(cfg.scopes) +
           "&state=" + webdav::urlEncode(state) +
           "&code_challenge=" + webdav::urlEncode(code_challenge) +
           "&code_challenge_method=S256";
}

bool OAuthProvider::exchangeCode(const OAuthProviderConfig& cfg, const std::string& code,
                                 const std::string& code_verifier, std::string& access_token,
                                 std::string& err) const {
    std::string form =
        "grant_type=authorization_code"
        "&code=" + webdav::urlEncode(code) +
        "&redirect_uri=" + webdav::urlEncode(cfg.redirect_uri) +
        "&client_id=" + webdav::urlEncode(cfg.client_id) +
        "&client_secret=" + webdav::urlEncode(cfg.client_secret) +
        "&code_verifier=" + webdav::urlEncode(code_verifier);

    HttpResult r = http_.postForm(cfg.token_url, form, {});
    if (!r.ok) {
        err = "token endpoint unreachable: " + r.error;
        return false;
    }
    if (r.status < 200 || r.status >= 300) {
        err = "token exchange failed (HTTP " + std::to_string(r.status) + ")";
        return false;
    }

    try {
        Poco::JSON::Parser p;
        auto obj = p.parse(r.body).extract<Poco::JSON::Object::Ptr>();
        access_token = strField(obj, "access_token");
    } catch (...) {
        err = "token response was not valid JSON";
        return false;
    }
    if (access_token.empty()) {
        err = "token response had no access_token";
        return false;
    }
    return true;
}

bool OAuthProvider::fetchIdentity(const OAuthProviderConfig& cfg, const std::string& access_token,
                                  VerifiedIdentity& out, std::string& err) const {
    if (cfg.kind == OAuthProviderConfig::GITHUB) {
        return fetchIdentityGithub(cfg, access_token, out, err);
    }

    // OIDC: the userinfo response is authoritative (fetched over validated TLS).
    HttpResult r = http_.get(cfg.userinfo_url, {{"Authorization", "Bearer " + access_token}});
    if (!r.ok) {
        err = "userinfo endpoint unreachable: " + r.error;
        return false;
    }
    if (r.status < 200 || r.status >= 300) {
        err = "userinfo fetch failed (HTTP " + std::to_string(r.status) + ")";
        return false;
    }
    try {
        Poco::JSON::Parser p;
        auto obj = p.parse(r.body).extract<Poco::JSON::Object::Ptr>();
        out.email = strField(obj, "email");
        out.subject = strField(obj, "sub");
        out.email_verified = boolField(obj, "email_verified");
    } catch (...) {
        err = "userinfo response was not valid JSON";
        return false;
    }
    if (out.email.empty()) {
        err = "userinfo had no email (request the 'email' scope)";
        return false;
    }
    return true;
}

bool OAuthProvider::fetchIdentityGithub(const OAuthProviderConfig& cfg,
                                        const std::string& access_token,
                                        VerifiedIdentity& out, std::string& err) const {
    const std::map<std::string, std::string> hdrs = {
        {"Authorization", "Bearer " + access_token},
        {"User-Agent", "fileengine-http-bridge"},
        {"Accept", "application/vnd.github+json"},
    };

    // /user gives the stable numeric id (subject). The public `email` field is
    // often null, so the verified primary email comes from /user/emails.
    HttpResult u = http_.get(cfg.userinfo_url, hdrs);
    if (!u.ok || u.status < 200 || u.status >= 300) {
        err = "github /user fetch failed" + (u.ok ? " (HTTP " + std::to_string(u.status) + ")" : ": " + u.error);
        return false;
    }
    try {
        Poco::JSON::Parser p;
        auto obj = p.parse(u.body).extract<Poco::JSON::Object::Ptr>();
        if (obj->has("id") && !obj->isNull("id")) {
            out.subject = std::to_string(obj->getValue<long long>("id"));
        }
    } catch (...) {
        err = "github /user response was not valid JSON";
        return false;
    }

    std::string emails_url = cfg.emails_url.empty() ? "https://api.github.com/user/emails"
                                                    : cfg.emails_url;
    HttpResult e = http_.get(emails_url, hdrs);
    if (!e.ok || e.status < 200 || e.status >= 300) {
        err = "github /user/emails fetch failed" + (e.ok ? " (HTTP " + std::to_string(e.status) + ")" : ": " + e.error);
        return false;
    }
    try {
        Poco::JSON::Parser p;
        auto arr = p.parse(e.body).extract<Poco::JSON::Array::Ptr>();
        for (std::size_t i = 0; i < arr->size(); ++i) {
            auto obj = arr->getObject(static_cast<unsigned>(i));
            if (!obj) continue;
            if (boolField(obj, "primary") && boolField(obj, "verified")) {
                out.email = strField(obj, "email");
                out.email_verified = true;
                break;
            }
        }
    } catch (...) {
        err = "github /user/emails response was not valid JSON";
        return false;
    }
    if (out.email.empty()) {
        err = "no verified primary email on the github account";
        return false;
    }
    return true;
}

}  // namespace httpbridge
