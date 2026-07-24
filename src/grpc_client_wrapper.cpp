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
template <typename Resp, typename Fn>
Resp invoke(const char* name, Fn&& fn) {
    Resp response;
    grpc::ClientContext context;
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
