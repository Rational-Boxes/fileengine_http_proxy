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

#include "grpc_client_wrapper.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>

namespace webdav {

GRPCClientWrapper::GRPCClientWrapper(const std::string& server_address) {
    webdav::debugLog("GRPCClientWrapper: Creating gRPC channel to: " + server_address);
    auto channel = grpc::CreateCustomChannel(server_address, grpc::InsecureChannelCredentials(), channel_args_);
    stub_ = fileengine_rpc::FileService::NewStub(channel);
    webdav::debugLog("GRPCClientWrapper: gRPC client initialized successfully");
}

GRPCClientWrapper::~GRPCClientWrapper() = default;

// Uniform unary-call helper: invokes `fn`, and on transport failure marks the
// response as a failure with the gRPC error message. `Resp` must expose
// set_success(bool) and set_error(const std::string&).
namespace {
// ── Service authentication (PROPOSAL_service_authentication.md §3.1) ────────
//
// The token rides in call metadata under a dedicated header, never in a
// protobuf field: it is a transport concern, it can be enforced in one place,
// and putting a credential inside a message that is already logged and passed
// around is how secrets end up in logs.
//
// Attached by attach_service_token() below, which every call path must use.
//
// The first version of this attached the token inside invoke<>() and claimed
// that was "the one place every RPC goes through". It was not: the streaming
// methods build their own ClientContext and never touch invoke<>, so file
// content — upload and download — went to the core unauthenticated while every
// unary call succeeded. The symptom was previews failing with HTTP 500 while
// the rest of the UI worked perfectly, which points nowhere near here.
//
// Hence a named helper rather than a line inside invoke<>: a new call site that
// forgets it is still a bug, but the thing it must call is now visible and
// greppable instead of implied by a comment.
//
// Read once at startup. FILEENGINE_SERVICE_TOKEN_FILE is the container path —
// an init writes the credential into a shared volume before the service starts,
// which is what lets tokens exist that did not exist at `compose up` time, and
// keeps the secret out of container metadata where an env var is visible to
// `docker inspect`.
const std::string& service_token() {
    static const std::string token = [] {
        if (const char* path = std::getenv("FILEENGINE_SERVICE_TOKEN_FILE")) {
            if (*path) {
                std::ifstream in(path);
                std::string from_file;
                std::getline(in, from_file);
                // Trim: a file written by a shell almost always ends in a
                // newline, and a token with a trailing newline authenticates
                // as nobody with no clue as to why.
                while (!from_file.empty() &&
                       (from_file.back() == '\n' || from_file.back() == '\r' ||
                        from_file.back() == ' ')) {
                    from_file.pop_back();
                }
                if (!from_file.empty()) return from_file;
            }
        }
        if (const char* env = std::getenv("FILEENGINE_SERVICE_TOKEN")) {
            if (*env) return std::string(env);
        }
        return std::string();
    }();
    return token;
}

// Put the service credential on one outbound call. Every ClientContext the
// bridge creates must pass through here before it is used.
void attach_service_token(grpc::ClientContext& context) {
    if (!service_token().empty()) {
        context.AddMetadata("x-fe-service-token", service_token());
    }
}

template <typename Resp, typename Fn>
Resp invoke(const char* name, Fn&& fn) {
    Resp response;
    grpc::ClientContext context;
    attach_service_token(context);
    grpc::Status status = fn(context, response);
    if (!status.ok()) {
        webdav::errorLog(std::string(name) + " failed: " + status.error_message());
        response.set_success(false);
        response.set_error(status.error_message());
    }
    return response;
}
}  // namespace

// Directory operations
fileengine_rpc::MakeDirectoryResponse GRPCClientWrapper::makeDirectory(const fileengine_rpc::MakeDirectoryRequest& request) {
    return invoke<fileengine_rpc::MakeDirectoryResponse>("MakeDirectory",
        [&](grpc::ClientContext& c, fileengine_rpc::MakeDirectoryResponse& r) { return stub_->MakeDirectory(&c, request, &r); });
}

fileengine_rpc::RemoveDirectoryResponse GRPCClientWrapper::removeDirectory(const fileengine_rpc::RemoveDirectoryRequest& request) {
    return invoke<fileengine_rpc::RemoveDirectoryResponse>("RemoveDirectory",
        [&](grpc::ClientContext& c, fileengine_rpc::RemoveDirectoryResponse& r) { return stub_->RemoveDirectory(&c, request, &r); });
}

fileengine_rpc::ListDirectoryResponse GRPCClientWrapper::listDirectory(const fileengine_rpc::ListDirectoryRequest& request) {
    return invoke<fileengine_rpc::ListDirectoryResponse>("ListDirectory",
        [&](grpc::ClientContext& c, fileengine_rpc::ListDirectoryResponse& r) { return stub_->ListDirectory(&c, request, &r); });
}

fileengine_rpc::ListDirectoryWithDeletedResponse GRPCClientWrapper::listDirectoryWithDeleted(const fileengine_rpc::ListDirectoryWithDeletedRequest& request) {
    return invoke<fileengine_rpc::ListDirectoryWithDeletedResponse>("ListDirectoryWithDeleted",
        [&](grpc::ClientContext& c, fileengine_rpc::ListDirectoryWithDeletedResponse& r) { return stub_->ListDirectoryWithDeleted(&c, request, &r); });
}

// File operations
fileengine_rpc::TouchResponse GRPCClientWrapper::touch(const fileengine_rpc::TouchRequest& request) {
    return invoke<fileengine_rpc::TouchResponse>("Touch",
        [&](grpc::ClientContext& c, fileengine_rpc::TouchResponse& r) { return stub_->Touch(&c, request, &r); });
}

fileengine_rpc::RemoveFileResponse GRPCClientWrapper::removeFile(const fileengine_rpc::RemoveFileRequest& request) {
    return invoke<fileengine_rpc::RemoveFileResponse>("RemoveFile",
        [&](grpc::ClientContext& c, fileengine_rpc::RemoveFileResponse& r) { return stub_->RemoveFile(&c, request, &r); });
}

fileengine_rpc::UndeleteFileResponse GRPCClientWrapper::undeleteFile(const fileengine_rpc::UndeleteFileRequest& request) {
    return invoke<fileengine_rpc::UndeleteFileResponse>("UndeleteFile",
        [&](grpc::ClientContext& c, fileengine_rpc::UndeleteFileResponse& r) { return stub_->UndeleteFile(&c, request, &r); });
}

fileengine_rpc::PutFileResponse GRPCClientWrapper::putFile(const fileengine_rpc::PutFileRequest& request) {
    return invoke<fileengine_rpc::PutFileResponse>("PutFile",
        [&](grpc::ClientContext& c, fileengine_rpc::PutFileResponse& r) { return stub_->PutFile(&c, request, &r); });
}

fileengine_rpc::GetFileResponse GRPCClientWrapper::getFile(const fileengine_rpc::GetFileRequest& request) {
    return invoke<fileengine_rpc::GetFileResponse>("GetFile",
        [&](grpc::ClientContext& c, fileengine_rpc::GetFileResponse& r) { return stub_->GetFile(&c, request, &r); });
}

// File information
fileengine_rpc::StatResponse GRPCClientWrapper::stat(const fileengine_rpc::StatRequest& request) {
    return invoke<fileengine_rpc::StatResponse>("Stat",
        [&](grpc::ClientContext& c, fileengine_rpc::StatResponse& r) { return stub_->Stat(&c, request, &r); });
}

fileengine_rpc::ExistsResponse GRPCClientWrapper::exists(const fileengine_rpc::ExistsRequest& request) {
    return invoke<fileengine_rpc::ExistsResponse>("Exists",
        [&](grpc::ClientContext& c, fileengine_rpc::ExistsResponse& r) { return stub_->Exists(&c, request, &r); });
}

// File manipulation operations
fileengine_rpc::RenameResponse GRPCClientWrapper::rename(const fileengine_rpc::RenameRequest& request) {
    return invoke<fileengine_rpc::RenameResponse>("Rename",
        [&](grpc::ClientContext& c, fileengine_rpc::RenameResponse& r) { return stub_->Rename(&c, request, &r); });
}

fileengine_rpc::MoveResponse GRPCClientWrapper::move(const fileengine_rpc::MoveRequest& request) {
    return invoke<fileengine_rpc::MoveResponse>("Move",
        [&](grpc::ClientContext& c, fileengine_rpc::MoveResponse& r) { return stub_->Move(&c, request, &r); });
}

fileengine_rpc::CopyResponse GRPCClientWrapper::copy(const fileengine_rpc::CopyRequest& request) {
    return invoke<fileengine_rpc::CopyResponse>("Copy",
        [&](grpc::ClientContext& c, fileengine_rpc::CopyResponse& r) { return stub_->Copy(&c, request, &r); });
}

// Version operations
fileengine_rpc::ListVersionsResponse GRPCClientWrapper::listVersions(const fileengine_rpc::ListVersionsRequest& request) {
    return invoke<fileengine_rpc::ListVersionsResponse>("ListVersions",
        [&](grpc::ClientContext& c, fileengine_rpc::ListVersionsResponse& r) { return stub_->ListVersions(&c, request, &r); });
}

fileengine_rpc::GetVersionResponse GRPCClientWrapper::getVersion(const fileengine_rpc::GetVersionRequest& request) {
    return invoke<fileengine_rpc::GetVersionResponse>("GetVersion",
        [&](grpc::ClientContext& c, fileengine_rpc::GetVersionResponse& r) { return stub_->GetVersion(&c, request, &r); });
}

fileengine_rpc::RestoreToVersionResponse GRPCClientWrapper::restoreToVersion(const fileengine_rpc::RestoreToVersionRequest& request) {
    return invoke<fileengine_rpc::RestoreToVersionResponse>("RestoreToVersion",
        [&](grpc::ClientContext& c, fileengine_rpc::RestoreToVersionResponse& r) { return stub_->RestoreToVersion(&c, request, &r); });
}

fileengine_rpc::PurgeOldVersionsResponse GRPCClientWrapper::purgeOldVersions(const fileengine_rpc::PurgeOldVersionsRequest& request) {
    return invoke<fileengine_rpc::PurgeOldVersionsResponse>("PurgeOldVersions",
        [&](grpc::ClientContext& c, fileengine_rpc::PurgeOldVersionsResponse& r) { return stub_->PurgeOldVersions(&c, request, &r); });
}

fileengine_rpc::EraseFileResponse GRPCClientWrapper::eraseFile(const fileengine_rpc::EraseFileRequest& request) {
    return invoke<fileengine_rpc::EraseFileResponse>("EraseFile",
        [&](grpc::ClientContext& c, fileengine_rpc::EraseFileResponse& r) { return stub_->EraseFile(&c, request, &r); });
}

fileengine_rpc::GetErasureStatusResponse GRPCClientWrapper::getErasureStatus(const fileengine_rpc::GetErasureStatusRequest& request) {
    return invoke<fileengine_rpc::GetErasureStatusResponse>("GetErasureStatus",
        [&](grpc::ClientContext& c, fileengine_rpc::GetErasureStatusResponse& r) { return stub_->GetErasureStatus(&c, request, &r); });
}

// Metadata operations
fileengine_rpc::SetMetadataResponse GRPCClientWrapper::setMetadata(const fileengine_rpc::SetMetadataRequest& request) {
    return invoke<fileengine_rpc::SetMetadataResponse>("SetMetadata",
        [&](grpc::ClientContext& c, fileengine_rpc::SetMetadataResponse& r) { return stub_->SetMetadata(&c, request, &r); });
}

fileengine_rpc::GetMetadataResponse GRPCClientWrapper::getMetadata(const fileengine_rpc::GetMetadataRequest& request) {
    return invoke<fileengine_rpc::GetMetadataResponse>("GetMetadata",
        [&](grpc::ClientContext& c, fileengine_rpc::GetMetadataResponse& r) { return stub_->GetMetadata(&c, request, &r); });
}

fileengine_rpc::GetAllMetadataResponse GRPCClientWrapper::getAllMetadata(const fileengine_rpc::GetAllMetadataRequest& request) {
    return invoke<fileengine_rpc::GetAllMetadataResponse>("GetAllMetadata",
        [&](grpc::ClientContext& c, fileengine_rpc::GetAllMetadataResponse& r) { return stub_->GetAllMetadata(&c, request, &r); });
}

fileengine_rpc::DeleteMetadataResponse GRPCClientWrapper::deleteMetadata(const fileengine_rpc::DeleteMetadataRequest& request) {
    return invoke<fileengine_rpc::DeleteMetadataResponse>("DeleteMetadata",
        [&](grpc::ClientContext& c, fileengine_rpc::DeleteMetadataResponse& r) { return stub_->DeleteMetadata(&c, request, &r); });
}

// ACL operations
fileengine_rpc::CheckPermissionResponse GRPCClientWrapper::checkPermission(const fileengine_rpc::CheckPermissionRequest& request) {
    return invoke<fileengine_rpc::CheckPermissionResponse>("CheckPermission",
        [&](grpc::ClientContext& c, fileengine_rpc::CheckPermissionResponse& r) { return stub_->CheckPermission(&c, request, &r); });
}

fileengine_rpc::GetResourceAclsResponse GRPCClientWrapper::getResourceAcls(const fileengine_rpc::GetResourceAclsRequest& request) {
    return invoke<fileengine_rpc::GetResourceAclsResponse>("GetResourceAcls",
        [&](grpc::ClientContext& c, fileengine_rpc::GetResourceAclsResponse& r) { return stub_->GetResourceAcls(&c, request, &r); });
}

fileengine_rpc::GrantPermissionResponse GRPCClientWrapper::grantPermission(const fileengine_rpc::GrantPermissionRequest& request) {
    return invoke<fileengine_rpc::GrantPermissionResponse>("GrantPermission",
        [&](grpc::ClientContext& c, fileengine_rpc::GrantPermissionResponse& r) { return stub_->GrantPermission(&c, request, &r); });
}

fileengine_rpc::RevokePermissionResponse GRPCClientWrapper::revokePermission(const fileengine_rpc::RevokePermissionRequest& request) {
    return invoke<fileengine_rpc::RevokePermissionResponse>("RevokePermission",
        [&](grpc::ClientContext& c, fileengine_rpc::RevokePermissionResponse& r) { return stub_->RevokePermission(&c, request, &r); });
}

// Role management operations
fileengine_rpc::CreateRoleResponse GRPCClientWrapper::createRole(const fileengine_rpc::CreateRoleRequest& request) {
    return invoke<fileengine_rpc::CreateRoleResponse>("CreateRole",
        [&](grpc::ClientContext& c, fileengine_rpc::CreateRoleResponse& r) { return stub_->CreateRole(&c, request, &r); });
}

fileengine_rpc::DeleteRoleResponse GRPCClientWrapper::deleteRole(const fileengine_rpc::DeleteRoleRequest& request) {
    return invoke<fileengine_rpc::DeleteRoleResponse>("DeleteRole",
        [&](grpc::ClientContext& c, fileengine_rpc::DeleteRoleResponse& r) { return stub_->DeleteRole(&c, request, &r); });
}

fileengine_rpc::AssignUserToRoleResponse GRPCClientWrapper::assignUserToRole(const fileengine_rpc::AssignUserToRoleRequest& request) {
    return invoke<fileengine_rpc::AssignUserToRoleResponse>("AssignUserToRole",
        [&](grpc::ClientContext& c, fileengine_rpc::AssignUserToRoleResponse& r) { return stub_->AssignUserToRole(&c, request, &r); });
}

fileengine_rpc::RemoveUserFromRoleResponse GRPCClientWrapper::removeUserFromRole(const fileengine_rpc::RemoveUserFromRoleRequest& request) {
    return invoke<fileengine_rpc::RemoveUserFromRoleResponse>("RemoveUserFromRole",
        [&](grpc::ClientContext& c, fileengine_rpc::RemoveUserFromRoleResponse& r) { return stub_->RemoveUserFromRole(&c, request, &r); });
}

fileengine_rpc::GetRolesForUserResponse GRPCClientWrapper::getRolesForUser(const fileengine_rpc::GetRolesForUserRequest& request) {
    return invoke<fileengine_rpc::GetRolesForUserResponse>("GetRolesForUser",
        [&](grpc::ClientContext& c, fileengine_rpc::GetRolesForUserResponse& r) { return stub_->GetRolesForUser(&c, request, &r); });
}

fileengine_rpc::GetUsersForRoleResponse GRPCClientWrapper::getUsersForRole(const fileengine_rpc::GetUsersForRoleRequest& request) {
    return invoke<fileengine_rpc::GetUsersForRoleResponse>("GetUsersForRole",
        [&](grpc::ClientContext& c, fileengine_rpc::GetUsersForRoleResponse& r) { return stub_->GetUsersForRole(&c, request, &r); });
}

fileengine_rpc::GetAllRolesResponse GRPCClientWrapper::getAllRoles(const fileengine_rpc::GetAllRolesRequest& request) {
    return invoke<fileengine_rpc::GetAllRolesResponse>("GetAllRoles",
        [&](grpc::ClientContext& c, fileengine_rpc::GetAllRolesResponse& r) { return stub_->GetAllRoles(&c, request, &r); });
}

fileengine_rpc::ListClaimsResponse GRPCClientWrapper::listClaims(const fileengine_rpc::ListClaimsRequest& request) {
    return invoke<fileengine_rpc::ListClaimsResponse>("ListClaims",
        [&](grpc::ClientContext& c, fileengine_rpc::ListClaimsResponse& r) { return stub_->ListClaims(&c, request, &r); });
}

// Administrative operations
fileengine_rpc::StorageUsageResponse GRPCClientWrapper::getStorageUsage(const fileengine_rpc::StorageUsageRequest& request) {
    return invoke<fileengine_rpc::StorageUsageResponse>("GetStorageUsage",
        [&](grpc::ClientContext& c, fileengine_rpc::StorageUsageResponse& r) { return stub_->GetStorageUsage(&c, request, &r); });
}

fileengine_rpc::TriggerSyncResponse GRPCClientWrapper::triggerSync(const fileengine_rpc::TriggerSyncRequest& request) {
    return invoke<fileengine_rpc::TriggerSyncResponse>("TriggerSync",
        [&](grpc::ClientContext& c, fileengine_rpc::TriggerSyncResponse& r) { return stub_->TriggerSync(&c, request, &r); });
}

// Streaming operations
GRPCClientWrapper::DownloadResult GRPCClientWrapper::streamFileDownload(
    const fileengine_rpc::GetFileRequest& request,
    const std::function<bool(const std::string&)>& onChunk) {
    grpc::ClientContext ctx;
    attach_service_token(ctx);
    auto reader = stub_->StreamFileDownload(&ctx, request);
    fileengine_rpc::GetFileResponse resp;
    std::string err;
    bool failed = false;
    while (reader->Read(&resp)) {
        if (!resp.success()) {  // an error chunk (success=false carries the error)
            failed = true;
            err = resp.error();
            break;
        }
        if (!resp.data().empty() && !onChunk(resp.data())) {
            ctx.TryCancel();  // caller asked to stop (disconnect / range satisfied)
            break;
        }
    }
    grpc::Status status = reader->Finish();
    if (failed) return {false, err};
    if (!status.ok() && status.error_code() != grpc::StatusCode::CANCELLED) {
        return {false, status.error_message()};
    }
    return {true, ""};
}

fileengine_rpc::PutFileResponse GRPCClientWrapper::streamFileUpload(
    const std::string& uid,
    const fileengine_rpc::AuthenticationContext& auth,
    const std::function<bool(std::string&)>& nextChunk) {
    grpc::ClientContext ctx;
    attach_service_token(ctx);
    fileengine_rpc::PutFileResponse response;
    auto writer = stub_->StreamFileUpload(&ctx, &response);
    bool first = true;
    std::string chunk;
    while (true) {
        chunk.clear();
        if (!nextChunk(chunk)) break;
        fileengine_rpc::PutFileRequest req;
        if (first) {
            req.set_uid(uid);
            *req.mutable_auth() = auth;
            first = false;
        }
        req.set_data(chunk);
        if (!writer->Write(req)) break;
    }
    if (first) {  // empty body: still send uid+auth so the server has the target
        fileengine_rpc::PutFileRequest req;
        req.set_uid(uid);
        *req.mutable_auth() = auth;
        writer->Write(req);
    }
    writer->WritesDone();
    grpc::Status status = writer->Finish();
    if (!status.ok()) {
        response.set_success(false);
        response.set_error(status.error_message());
    }
    return response;
}

} // namespace webdav
