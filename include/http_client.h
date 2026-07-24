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

#ifndef HTTP_BRIDGE_HTTP_CLIENT_H
#define HTTP_BRIDGE_HTTP_CLIENT_H

#include <map>
#include <string>

namespace httpbridge {

// Result of an outbound HTTP(S) call. `ok` is false on transport failure
// (DNS/TLS/timeout); inspect `error` for the reason. `status` is the HTTP
// status when `ok` is true.
struct HttpResult {
    bool ok = false;
    int status = 0;
    std::string body;
    std::string error;
};

// Minimal outbound HTTP client used only for server-to-server OAuth2/OIDC calls
// (token exchange, userinfo). HTTPS uses the SSL context registered by
// Poco::Net::SSLManager in main() — certificate validation MUST be enabled there
// (the bridge trusts the IdP identity on the strength of that validated TLS, in
// lieu of verifying id_token JWKS signatures). Plain http:// is accepted only so
// a local mock IdP can be used in tests; a warning is logged whenever it is used.
//
// Both calls apply a receive/connect timeout and cap the response body so a slow
// or hostile endpoint cannot hang a worker thread or exhaust memory.
class HttpClient {
public:
    explicit HttpClient(int timeout_seconds = 10,
                        long max_response_bytes = 1L * 1024 * 1024)
        : timeout_seconds_(timeout_seconds), max_response_bytes_(max_response_bytes) {}

    HttpResult get(const std::string& url,
                   const std::map<std::string, std::string>& headers) const;

    // POSTs an application/x-www-form-urlencoded body.
    HttpResult postForm(const std::string& url, const std::string& form_body,
                        const std::map<std::string, std::string>& headers) const;

    // POSTs an application/json body (server-to-server, e.g. ldap_manager's
    // internal 2FA API which parses pydantic bodies).
    HttpResult postJson(const std::string& url, const std::string& json_body,
                        const std::map<std::string, std::string>& headers) const;

private:
    HttpResult request(const std::string& method, const std::string& url,
                       const std::string& body, const std::string& content_type,
                       const std::map<std::string, std::string>& headers) const;

    int timeout_seconds_;
    long max_response_bytes_;
};

}  // namespace httpbridge

#endif  // HTTP_BRIDGE_HTTP_CLIENT_H
