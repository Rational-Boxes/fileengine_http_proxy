#include "http_client.h"
#include "utils.h"

#include <Poco/URI.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPSClientSession.h>
#include <Poco/Timespan.h>

#include <istream>
#include <memory>
#include <ostream>

namespace httpbridge {

using Poco::Net::HTTPClientSession;
using Poco::Net::HTTPSClientSession;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPResponse;

HttpResult HttpClient::get(const std::string& url,
                           const std::map<std::string, std::string>& headers) const {
    return request(HTTPRequest::HTTP_GET, url, "", "", headers);
}

HttpResult HttpClient::postForm(const std::string& url, const std::string& form_body,
                                const std::map<std::string, std::string>& headers) const {
    return request(HTTPRequest::HTTP_POST, url, form_body,
                   "application/x-www-form-urlencoded", headers);
}

HttpResult HttpClient::request(const std::string& method, const std::string& url,
                               const std::string& body, const std::string& content_type,
                               const std::map<std::string, std::string>& headers) const {
    HttpResult out;
    try {
        Poco::URI uri(url);
        const bool https = uri.getScheme() == "https";
        if (!https) {
            webdav::warnLog("HttpClient: outbound request over plain HTTP (no TLS) to " +
                            uri.getHost() + " — acceptable only for a local test IdP");
        }

        std::unique_ptr<HTTPClientSession> session;
        if (https) {
            session = std::make_unique<HTTPSClientSession>(uri.getHost(), uri.getPort());
        } else {
            session = std::make_unique<HTTPClientSession>(uri.getHost(), uri.getPort());
        }
        Poco::Timespan timeout(timeout_seconds_, 0);
        session->setTimeout(timeout);

        std::string path = uri.getPathAndQuery();
        if (path.empty()) path = "/";

        HTTPRequest req(method, path, HTTPRequest::HTTP_1_1);
        req.setHost(uri.getHost(), uri.getPort());
        req.set("Accept", "application/json");
        for (const auto& kv : headers) req.set(kv.first, kv.second);
        if (!body.empty()) {
            req.setContentType(content_type);
            req.setContentLength(static_cast<std::streamsize>(body.size()));
        }

        std::ostream& os = session->sendRequest(req);
        if (!body.empty()) os << body;

        HTTPResponse res;
        std::istream& rs = session->receiveResponse(res);

        // Bounded read: never trust the peer to stop.
        std::string data;
        char buf[16 * 1024];
        while (rs && static_cast<long>(data.size()) < max_response_bytes_) {
            rs.read(buf, sizeof(buf));
            std::streamsize n = rs.gcount();
            if (n <= 0) break;
            data.append(buf, static_cast<size_t>(n));
        }

        out.ok = true;
        out.status = static_cast<int>(res.getStatus());
        out.body = std::move(data);
        return out;
    } catch (const Poco::Exception& e) {
        out.ok = false;
        out.error = e.displayText();
        return out;
    } catch (const std::exception& e) {
        out.ok = false;
        out.error = e.what();
        return out;
    }
}

}  // namespace httpbridge
