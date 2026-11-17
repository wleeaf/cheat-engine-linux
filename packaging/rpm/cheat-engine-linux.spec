# RPM spec for Cheat Engine for Linux.
#
# Targets Fedora (39+) and, with the usual macro differences, openSUSE. Build
# with packaging/build-rpm.sh (it creates Source0 and downloads Source1), or
# with rpmbuild directly once the sources are in ~/rpmbuild/SOURCES.
#
# Keystone is bundled: it is not packaged under a usable name in Fedora, and its
# CMakeLists uses a CMake policy that current CMake rejects. Source1 is the
# GitHub archive of the exact commit CMakeLists.txt pins; the prep section applies
# cmake/patch_keystone.cmake to it before configuring, because FetchContent
# cannot patch a source directory that is supplied with
# FETCHCONTENT_SOURCE_DIR_KEYSTONE. See packaging/rpm/README.md.
#
# Keep Version in sync with project(cecore VERSION ...) in CMakeLists.txt; the
# CI workflow and packaging/build-rpm.sh both check this.

%global keystone_version 0.9.2
%global keystone_commit dc7932ef2b2c4a793836caec6ecab485005139d6
%global keystone_archive keystone-%{keystone_commit}
# sha256 of Source1; packaging/build-rpm.sh verifies it before building.
%global keystone_sha256 23aac537d6a596b1b9a597219fd30ee0c3a0955336b3d20df408aed432b9bcf8

Name:           cheat-engine-linux
Version:        1.1.0
Release:        1%{?dist}
Summary:        Linux-native Cheat Engine: memory scanner, debugger and injector

# The project is MIT; Lua (bundled) is MIT, TinyXML-2 (bundled) is Zlib, and the
# bundled Keystone runtime is GPL-2.0-only (see its COPYING, shipped as a
# licence file).
License:        MIT and GPL-2.0-only and Zlib
URL:            https://github.com/wleeaf/cheat-engine-linux
Source0:        %{name}-%{version}.tar.gz
Source1:        https://github.com/keystone-engine/keystone/archive/%{keystone_commit}/%{keystone_archive}.tar.gz
# Fedora bundling notation: no usable Keystone package exists, so the library
# is built from Source1 and packaged as a runtime dependency of libcecore.
Provides:       bundled(keystone) = %{keystone_version}

# ── Build dependencies ──
# GUI and build tooling.
BuildRequires:  cmake
BuildRequires:  cmake-rpm-macros
BuildRequires:  redhat-rpm-config
BuildRequires:  ninja-build
BuildRequires:  gcc-c++
BuildRequires:  python3
BuildRequires:  qt6-qtbase-devel
BuildRequires:  qt6-qttools-devel
BuildRequires:  qt6-linguist
# Backend libraries.
BuildRequires:  capstone-devel
BuildRequires:  zlib-devel
BuildRequires:  elfutils-devel
BuildRequires:  openssl-devel
# Optional features the packaged build enables.
BuildRequires:  alsa-lib-devel
BuildRequires:  soundtouch-devel
BuildRequires:  libX11-devel
BuildRequires:  libxcb-devel
# Install-time and check-time package validation.
BuildRequires:  desktop-file-utils
BuildRequires:  appstream

# The post-install script grants cap_sys_ptrace so the scanner and debugger
# processes under the default kernel.yama.ptrace_scope without root.
Requires(post): libcap

%description
Cheat Engine for Linux is a native Linux reimplementation of Cheat Engine in
C++20/23 and Qt6. It scans memory, follows pointer paths, assembles and injects
code with an auto-assembler, debugs multi-threaded programs, dissects
structures, reads and writes cheat tables, and scripts everything with Lua. The
package includes the GUI, the cescan command-line frontend and both tutorial
games.

Unlike a sandboxed package, it runs with the user's privileges (the only extra
capability is cap_sys_ptrace, granted at install), which is what memory access
to another process requires.

%package devel
Summary:        Headers, pkg-config file and linker name for libcecore
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
Development files for libcecore, the Qt-free engine behind Cheat Engine for
Linux: process access, memory scanning, the debugger, the auto-assembler, Lua
bindings and cheat-table I/O. Link with `pkg-config --libs cecore`.

%prep
%autosetup -n %{name}-%{version} -a 1

# FetchContent does not run PATCH_COMMAND for a source directory supplied with
# FETCHCONTENT_SOURCE_DIR_KEYSTONE, so apply the idempotent fix here. CMakeLists
# applies it again after FetchContent_MakeAvailable; the script is a no-op then.
# The extra source is unpacked inside the source tree, so the relative path
# works with the classic and the newer per-package build directory.
srcdir=$(pwd)
( cd keystone-%{keystone_commit} && cmake -P "$srcdir/cmake/patch_keystone.cmake" )

%build
%cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_SKIP_RPATH=ON \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DFETCHCONTENT_SOURCE_DIR_KEYSTONE="$PWD/%{keystone_archive}"
%cmake_build

%install
%cmake_install

# The bundled Keystone build installs its own development files; only the
# runtime library is part of this package. libkeystone.so is an unversioned
# development symlink, libkeystone.so.0 is the library itself.
rm -rf %{buildroot}%{_includedir}/keystone
rm -f  %{buildroot}%{_libdir}/pkgconfig/keystone.pc
rm -f  %{buildroot}%{_libdir}/libkeystone.so

# If Capstone was fetched instead of taken from the system, drop the bundled
# copy: BuildRequires guarantees the distribution's capstone-devel, and the
# runtime dependency comes from the ELF dependency generator.
rm -f %{buildroot}%{_libdir}/libcapstone.so*

# Licence text of the bundled third-party library (Fedora bundling rules).
install -d %{buildroot}%{_licensedir}/%{name}/keystone
# The install section runs inside the unpacked source tree, where the extra
# source was extracted too.
install -m 0644 %{keystone_archive}/COPYING \
    %{buildroot}%{_licensedir}/%{name}/keystone/COPYING

# Validate the desktop entry and the AppStream metadata from the staged tree.
desktop-file-validate %{buildroot}%{_datadir}/applications/cheatengine.desktop
appstreamcli validate --no-net \
    %{buildroot}%{_datadir}/metainfo/io.github.wleeaf.CheatEngineLinux.metainfo.xml

%check
# The full regression suite (cecore_test, gates, the other GUI smokes) runs in
# the upstream GitHub CI, which has the extra fixtures (Wine, QEMU, 32-bit
# toolchains, container runtimes). Here keep to checks that are portable to a
# build container: the catalogue must be complete, and the GUI theme smoke
# exercises translation loading and widget construction offscreen.
#
# CMAKE_SKIP_RPATH is set for the install tree, so the build-tree binaries need
# the engine and the bundled Keystone library on the loader path. Keystone's
# build directory is nested, so find it instead of spelling out the layout.
builddir=%{_vpath_builddir}
keystone_libdir=$(dirname "$(find "$builddir" -name 'libkeystone.so.0' -print -quit)")
export LD_LIBRARY_PATH="$PWD/$builddir:$keystone_libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python3 tools/check-translations.py
HOME=%{_builddir} QT_QPA_PLATFORM=offscreen ./%{_vpath_builddir}/gui_theme_smoke
./%{_vpath_builddir}/cheatengine --version
./%{_vpath_builddir}/cescan --version

%post
# Running as root here. libcap is a Requires(post) because of this call.
if command -v setcap >/dev/null 2>&1; then
    for bin in %{_bindir}/cheatengine %{_bindir}/cescan; do
        [ -x "$bin" ] && setcap cap_sys_ptrace+ep "$bin" \
            || echo "%{name}: could not setcap $bin (scanning other processes will need root)." >&2
    done
fi

%files
%{_bindir}/cheatengine
%{_bindir}/cescan
%{_bindir}/cetutorial
%{_bindir}/cegtutorial
%{_libdir}/libcecore.so.*
%{_libdir}/libspeedhack.so
%{_libdir}/libcecore_mono_agent.so
# The bundled Keystone runtime library (its soname).
%{_libdir}/libkeystone.so.*
%{_datadir}/applications/cheatengine.desktop
%{_datadir}/icons/hicolor/128x128/apps/cheatengine.png
%{_datadir}/metainfo/io.github.wleeaf.CheatEngineLinux.metainfo.xml
%{_datadir}/mime/packages/cheat-engine-linux.mime.xml
%doc %{_datadir}/doc/cheat-engine-linux
%license %{_datadir}/licenses/cheat-engine-linux

%files devel
%{_includedir}/cecore
%{_libdir}/libcecore.so
%{_libdir}/pkgconfig/cecore.pc

%changelog
* Mon Nov 16 2026 wleeaf <wleeaf@users.noreply.github.com> - 1.1.0-1
- Initial RPM package: GUI, cescan, the tutorial games, the bundled Keystone
  runtime, libcecore with a devel subpackage, AppStream/MIME/desktop
  integration, and cap_sys_ptrace granted at install.
