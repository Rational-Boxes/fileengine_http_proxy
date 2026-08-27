// Every outbound ClientContext must carry the service credential.
//
// This is a source-level test, which is unusual, and it exists because the
// runtime tests could not catch what happened here. The token was attached
// inside invoke<>() with a comment claiming that was "the one place every RPC
// goes through". It was not: streamFileDownload and streamFileUpload build
// their own ClientContext, so file content moved to the core unauthenticated
// while every unary call succeeded — previews failed with HTTP 500 and nothing
// else did. An integration test would have needed a running core with auth
// required to notice, and the unit suite is deliberately hermetic.
//
// So the invariant is asserted where it is cheap: in this translation unit,
// every `grpc::ClientContext` declaration is immediately followed by an
// attach_service_token() call on it. A new call site that forgets fails here
// rather than in production, on the one path that carries file data.
#include <gtest/gtest.h>

#include <fstream>
#include <regex>
#include <sstream>
#include <string>

namespace {

std::string read_wrapper_source() {
    // Path is supplied by CMake so the test does not depend on the working
    // directory ctest happens to run from.
    std::ifstream in(GRPC_CLIENT_WRAPPER_SOURCE);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

TEST(ServiceTokenCoverage, WrapperSourceIsReadable) {
    // Guards the guard: a path that silently reads nothing would make every
    // assertion below vacuously true.
    const std::string src = read_wrapper_source();
    ASSERT_FALSE(src.empty()) << "could not read " << GRPC_CLIENT_WRAPPER_SOURCE;
    EXPECT_NE(src.find("attach_service_token"), std::string::npos)
        << "the helper is gone — the token is no longer attached anywhere";
}

TEST(ServiceTokenCoverage, EveryClientContextAttachesTheToken) {
    const std::string src = read_wrapper_source();
    ASSERT_FALSE(src.empty());

    // Each declaration, and what follows it.
    const std::regex decl(R"(grpc::ClientContext\s+(\w+)\s*;)");
    auto begin = std::sregex_iterator(src.begin(), src.end(), decl);
    auto end   = std::sregex_iterator();

    int contexts = 0;
    for (auto it = begin; it != end; ++it) {
        ++contexts;
        const std::string name = (*it)[1].str();
        // Look only at the next few lines: the attachment must happen before
        // the context is used, not somewhere later in the function.
        const std::size_t from = it->position() + it->length();
        const std::string window = src.substr(from, 200);
        EXPECT_NE(window.find("attach_service_token(" + name + ")"), std::string::npos)
            << "grpc::ClientContext '" << name << "' is created without "
            << "attach_service_token(" << name << ") immediately after it. "
            << "Calls made on it reach the core unauthenticated.";
    }

    // If the wrapper is ever restructured so no bare ClientContext remains,
    // this test would pass while checking nothing. Fail instead, so the
    // invariant gets re-expressed rather than quietly lost.
    EXPECT_GT(contexts, 0) << "no grpc::ClientContext found — if the wrapper was "
                              "restructured, update this test to match";
}
