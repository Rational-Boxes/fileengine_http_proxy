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

} // namespace webdav
