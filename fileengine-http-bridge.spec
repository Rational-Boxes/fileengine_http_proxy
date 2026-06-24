Name:           fileengine-http-bridge
Version:        1.0.0
Release:        1%{?dist}
Summary:        REST/HTTP bridge for the FileEngine gRPC core
License:        MIT
URL:            https://github.com/fileengine/fileengine-http-bridge
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

BuildRequires:  cmake, gcc-c++, make, pkgconfig
BuildRequires:  grpc-devel, grpc-plugins, protobuf-devel, protobuf-compiler
BuildRequires:  poco-devel
BuildRequires:  openssl-devel
BuildRequires:  openldap-devel
BuildRequires:  systemd-rpm-macros

Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
fileengine-http-bridge exposes the FileEngine gRPC core as a JSON/REST API
(default :8090): authenticated filesystem, versioning, metadata, ACL/role
management, and an ACL-editor principal type-ahead, plus LDAP Basic + bearer
token + OAuth2 login. A dedicated, correctly-sized worker pool serves concurrent
long-lived transfers, and a separate reporter listener (default :8091) exposes
/healthz, /readyz, and /poolz for load-balancer health checks.

Ships a systemd unit (runs as a transient DynamicUser) and a default
environment file at /etc/fileengine-http-bridge/bridge.env.

%prep
%setup -q -n %{name}-%{version}

%build
mkdir -p build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=%{_prefix}
make %{?_smp_mflags}

%install
rm -rf %{buildroot}

# Binary (installed under a fileengine-prefixed name to avoid a generic
# /usr/bin/http_bridge that could collide with unrelated software).
install -D -m 0755 build/http_bridge %{buildroot}%{_bindir}/fileengine-http-bridge

# OpenAPI spec (reference documentation).
install -D -m 0644 openapi.yaml %{buildroot}%{_datadir}/%{name}/openapi.yaml

# systemd unit.
install -D -m 0644 fileengine-http-bridge.service \
    %{buildroot}%{_unitdir}/fileengine-http-bridge.service

# Default environment file (config).
install -D -m 0640 http-bridge.env \
    %{buildroot}/etc/fileengine-http-bridge/bridge.env

%post
%systemd_post fileengine-http-bridge.service

%preun
%systemd_preun fileengine-http-bridge.service

%postun
%systemd_postun_with_restart fileengine-http-bridge.service

%files
%defattr(-,root,root,-)
%attr(0755,root,root) %{_bindir}/fileengine-http-bridge
%{_unitdir}/fileengine-http-bridge.service
%dir /etc/fileengine-http-bridge
%config(noreplace) %attr(0640,root,root) /etc/fileengine-http-bridge/bridge.env
%{_datadir}/%{name}/openapi.yaml

%clean
rm -rf %{buildroot}

%changelog
* Wed Jun 24 2026 FileEngine Team <maintainer@fileengine.example.com> - 1.0.0-1
- Initial RPM packaging: fileengine-http-bridge daemon, systemd unit
  (DynamicUser), and default environment file.
