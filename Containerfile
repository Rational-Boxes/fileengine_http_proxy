# Single-stage build on Fedora (matches the project's known-good build env, and
# grpc-devel ships the CMake config find_package(gRPC CONFIG) needs).
# Multi-stage slimming is a later refinement.
FROM fedora:43

RUN dnf -y install \
        gcc-c++ cmake make pkgconf-pkg-config git \
        grpc-devel grpc-plugins protobuf-devel protobuf-compiler \
        poco-devel openldap-devel \
    && dnf clean all

WORKDIR /src
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build --target http_bridge -j"$(nproc)" \
    && install -Dm755 build/http_bridge /usr/local/bin/http_bridge

WORKDIR /app
EXPOSE 8090
# Config is supplied via environment variables at run time.
ENTRYPOINT ["/usr/local/bin/http_bridge"]
