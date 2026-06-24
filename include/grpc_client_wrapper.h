#ifndef GRPC_CLIENT_WRAPPER_H
#define GRPC_CLIENT_WRAPPER_H

#include <grpcpp/grpcpp.h>
#include <functional>
#include <memory>
#include <string>

#include "fileservice.grpc.pb.h"
#include "utils.h"  // For logging functions

namespace webdav {

struct AuthenticationContext {
    std::string user;
    std::vector<std::string> roles;
    std::string tenant;
    std::map<std::string, std::string> claims;
};

// Thin client wrapper over the canonical FileEngine FileService gRPC interface
// (file_engine_core/proto/fileservice.proto, package `fileengine_rpc`).
//
// The server is UID-based: there is no path->UID RPC. Path resolution is done
// in the bridge (PathResolver) by walking ListDirectory from the root.
class GRPCClientWrapper {
public:
    GRPCClientWrapper(const std::string& server_address);
    ~GRPCClientWrapper();

    // Directory operations
    fileengine_rpc::MakeDirectoryResponse makeDirectory(const fileengine_rpc::MakeDirectoryRequest& request);
    fileengine_rpc::RemoveDirectoryResponse removeDirectory(const fileengine_rpc::RemoveDirectoryRequest& request);
    fileengine_rpc::ListDirectoryResponse listDirectory(const fileengine_rpc::ListDirectoryRequest& request);
    fileengine_rpc::ListDirectoryWithDeletedResponse listDirectoryWithDeleted(const fileengine_rpc::ListDirectoryWithDeletedRequest& request);

    // File operations
    fileengine_rpc::TouchResponse touch(const fileengine_rpc::TouchRequest& request);
    fileengine_rpc::RemoveFileResponse removeFile(const fileengine_rpc::RemoveFileRequest& request);
    fileengine_rpc::UndeleteFileResponse undeleteFile(const fileengine_rpc::UndeleteFileRequest& request);
    fileengine_rpc::PutFileResponse putFile(const fileengine_rpc::PutFileRequest& request);
    fileengine_rpc::GetFileResponse getFile(const fileengine_rpc::GetFileRequest& request);

    // File information
    fileengine_rpc::StatResponse stat(const fileengine_rpc::StatRequest& request);
    fileengine_rpc::ExistsResponse exists(const fileengine_rpc::ExistsRequest& request);

    // File manipulation operations
    fileengine_rpc::RenameResponse rename(const fileengine_rpc::RenameRequest& request);
    fileengine_rpc::MoveResponse move(const fileengine_rpc::MoveRequest& request);
    fileengine_rpc::CopyResponse copy(const fileengine_rpc::CopyRequest& request);

    // Version operations
    fileengine_rpc::ListVersionsResponse listVersions(const fileengine_rpc::ListVersionsRequest& request);
    fileengine_rpc::GetVersionResponse getVersion(const fileengine_rpc::GetVersionRequest& request);
    fileengine_rpc::RestoreToVersionResponse restoreToVersion(const fileengine_rpc::RestoreToVersionRequest& request);
    fileengine_rpc::PurgeOldVersionsResponse purgeOldVersions(const fileengine_rpc::PurgeOldVersionsRequest& request);

    // Metadata operations
    fileengine_rpc::SetMetadataResponse setMetadata(const fileengine_rpc::SetMetadataRequest& request);
    fileengine_rpc::GetMetadataResponse getMetadata(const fileengine_rpc::GetMetadataRequest& request);
    fileengine_rpc::GetAllMetadataResponse getAllMetadata(const fileengine_rpc::GetAllMetadataRequest& request);
    fileengine_rpc::DeleteMetadataResponse deleteMetadata(const fileengine_rpc::DeleteMetadataRequest& request);

    // ACL operations
    fileengine_rpc::CheckPermissionResponse checkPermission(const fileengine_rpc::CheckPermissionRequest& request);
    fileengine_rpc::GetResourceAclsResponse getResourceAcls(const fileengine_rpc::GetResourceAclsRequest& request);
    fileengine_rpc::GrantPermissionResponse grantPermission(const fileengine_rpc::GrantPermissionRequest& request);
    fileengine_rpc::RevokePermissionResponse revokePermission(const fileengine_rpc::RevokePermissionRequest& request);

    // Role management operations
    fileengine_rpc::CreateRoleResponse createRole(const fileengine_rpc::CreateRoleRequest& request);
    fileengine_rpc::DeleteRoleResponse deleteRole(const fileengine_rpc::DeleteRoleRequest& request);
    fileengine_rpc::AssignUserToRoleResponse assignUserToRole(const fileengine_rpc::AssignUserToRoleRequest& request);
    fileengine_rpc::RemoveUserFromRoleResponse removeUserFromRole(const fileengine_rpc::RemoveUserFromRoleRequest& request);
    fileengine_rpc::GetRolesForUserResponse getRolesForUser(const fileengine_rpc::GetRolesForUserRequest& request);
    fileengine_rpc::GetUsersForRoleResponse getUsersForRole(const fileengine_rpc::GetUsersForRoleRequest& request);
    fileengine_rpc::GetAllRolesResponse getAllRoles(const fileengine_rpc::GetAllRolesRequest& request);
    fileengine_rpc::ListClaimsResponse listClaims(const fileengine_rpc::ListClaimsRequest& request);

    // Administrative operations
    fileengine_rpc::StorageUsageResponse getStorageUsage(const fileengine_rpc::StorageUsageRequest& request);
    fileengine_rpc::TriggerSyncResponse triggerSync(const fileengine_rpc::TriggerSyncRequest& request);

    // Streaming operations (memory-efficient for large files).
    struct DownloadResult { bool success; std::string error; };
    // Server-streaming download: invokes onChunk(data) for each chunk; onChunk
    // returns false to abort early (e.g. client disconnect / range satisfied).
    DownloadResult streamFileDownload(const fileengine_rpc::GetFileRequest& request,
                                      const std::function<bool(const std::string&)>& onChunk);
    // Client-streaming upload: nextChunk(out) fills the next body chunk and
    // returns false when the body is exhausted. uid/auth are sent on the first
    // message (server reads them only from there).
    fileengine_rpc::PutFileResponse streamFileUpload(const std::string& uid,
                                      const fileengine_rpc::AuthenticationContext& auth,
                                      const std::function<bool(std::string&)>& nextChunk);

private:
    std::unique_ptr<fileengine_rpc::FileService::Stub> stub_;
    grpc::ChannelArguments channel_args_;
};

} // namespace webdav

#endif // GRPC_CLIENT_WRAPPER_H
