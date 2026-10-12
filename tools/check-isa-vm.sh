#!/usr/bin/env bash
# Architecture-generic process checks under a full Linux guest of another ISA.
# usage: tools/check-isa-vm.sh [riscv64|s390x|ppc64el|armhf|x32] [BUILD_DIR] [--build-only]
# Needs the ISA's cross g++, cmake, ninja, curl, python3, dpkg-deb and (unless
# --build-only) the matching qemu-system binary with its firmware.
# CECORE_ISA_FRONTEND=/path/to/cescan (a build for the guest's ISA) adds the CLI
# and Lua frontend checks; CECORE_ISA_FRONTEND_SYSROOT holds its libraries.
set -euo pipefail
cd "$(dirname "$0")/.."
isa="${1:-riscv64}"
vm_build=$(realpath -m "${2:-build/isa-vm/$isa}")
build_only=0
[ "${3:-}" = "--build-only" ] && build_only=1
mkdir -p "$vm_build"
jobs="${CECORE_CI_JOBS:-1}"

# Pinned generic kernels, each directly bootable by QEMU.
mirror=http://ports.ubuntu.com/ubuntu-ports/pool/main/l
fixture_flags="" kernel_args=""
case "$isa" in
    riscv64)
        triplet=riscv64-linux-gnu processor=riscv64 capstone_arch=RISCV qemu=qemu-system-riscv64
        expected=RISC-V64 package=linux-riscv/linux-image-6.8.0-60-generic_6.8.0-60.63.1_riscv64.deb
        package_sha256=76fed85a231f9605b75f0efc0d6ade95c9fa7cc43c17186d8434971a6ba363ca
        kernel=boot/vmlinuz-6.8.0-60-generic ;;
    s390x)   # big-endian
        triplet=s390x-linux-gnu processor=s390x capstone_arch=SYSZ qemu=qemu-system-s390x
        expected=s390x package=linux/linux-image-unsigned-6.8.0-146-generic_6.8.0-146.146_s390x.deb
        package_sha256=c9eca468bc0d7e593e004bffd8c5a317a7f6989bc6ac77a3521d7b012c925b5d
        kernel=boot/vmlinuz-6.8.0-146-generic ;;
    ppc64el)
        triplet=powerpc64le-linux-gnu processor=ppc64le capstone_arch=PPC qemu=qemu-system-ppc64
        expected=PowerPC64 package=linux/linux-image-6.8.0-146-generic_6.8.0-146.146_ppc64el.deb
        package_sha256=4fc21cd0eff980bb20ade53998217bac656b464d83fc453298ba62fbbe74827d
        kernel=boot/vmlinux-6.8.0-146-generic ;;
    armhf)   # Thumb-2 code by default
        triplet=arm-linux-gnueabihf processor=arm capstone_arch=ARM qemu=qemu-system-arm
        expected=ARM32 package=linux/linux-image-6.8.0-146-generic_6.8.0-146.146_armhf.deb
        package_sha256=bb175b37cccaac0d7aa154ab148e18a1ef11c9364a93e50d793c92cb0404532c
        kernel=boot/vmlinuz-6.8.0-146-generic ;;
    x32)     # LP64 engine, ILP32 program on an x32-enabled Debian kernel
        triplet=x86_64-linux-gnu processor=x86_64 capstone_arch=X86 qemu=qemu-system-x86_64
        expected=x86-64 mirror=https://deb.debian.org/debian/pool/main/l
        package=linux-signed-amd64/linux-image-6.1.0-50-amd64_6.1.176-1_amd64.deb
        package_sha256=7b5597492a0a65aee61985a492e6bcc3f2cde830072a0e3b3d8c7e1b90279bd3
        kernel=boot/vmlinuz-6.1.0-50-amd64 fixture_flags=-mx32 kernel_args=syscall.x32=y ;;
    *) printf 'Unsupported ISA guest: %s\n' "$isa" >&2; exit 1 ;;
esac
kernel_package="$vm_build/$(basename "$package")"
kernel_path="$vm_build/kernel/$kernel"
if [ ! -f "$kernel_path" ]; then
    if [ ! -f "$kernel_package" ]; then
        curl --fail --location --retry 3 --output "$kernel_package.tmp" "$mirror/$package"
        mv "$kernel_package.tmp" "$kernel_package"
    fi
    printf '%s  %s\n' "$package_sha256" "$kernel_package" | sha256sum --check
    dpkg-deb -x "$kernel_package" "$vm_build/kernel"
fi

# The same pinned Capstone source as the ARM64 guest checks, one ISA only.
capstone_commit=097c04d9413c59a58b00d4d1c8d5dc0ac158ffaa
capstone_sha256=51c90b47cb1b8e3f55de45563ccea16786f902175672bcbb824fb5982f44dac2
capstone_archive="${CECORE_VM_CAPSTONE_ARCHIVE:-$vm_build/capstone.tar.gz}"
if [ ! -f "$capstone_archive" ]; then
    curl --fail --location --retry 3 --output "$capstone_archive.tmp" \
        "https://codeload.github.com/capstone-engine/capstone/tar.gz/$capstone_commit"
    mv "$capstone_archive.tmp" "$capstone_archive"
fi
printf '%s  %s\n' "$capstone_sha256" "$capstone_archive" | sha256sum --check
mkdir -p "$vm_build/capstone-source"
tar -xzf "$capstone_archive" --strip-components=1 -C "$vm_build/capstone-source"
cmake -S "$vm_build/capstone-source" -B "$vm_build/capstone-build" -G Ninja \
    -DCMAKE_C_COMPILER="$triplet-gcc" -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR="$processor" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCAPSTONE_BUILD_TESTS=OFF \
    -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF "-DCAPSTONE_${capstone_arch}_SUPPORT=ON" >/dev/null
cmake --build "$vm_build/capstone-build" -j"$jobs"
cmake -S test/isa_vm -B "$vm_build/driver-build" -G Ninja \
    -DCMAKE_C_COMPILER="$triplet-gcc" -DCMAKE_CXX_COMPILER="$triplet-g++" \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR="$processor" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$vm_build" -DCECORE_ISA_FIXTURE_FLAGS="$fixture_flags" \
    -DCECORE_VM_CAPSTONE_INCLUDE="$vm_build/capstone-source/include" \
    -DCECORE_VM_CAPSTONE_LIBRARY="$vm_build/capstone-build/libcapstone.a" >/dev/null
cmake --build "$vm_build/driver-build" --target init fixture -j"$jobs"
[ "$build_only" = 1 ] && exit 0
frontend=() name="$isa-guest"
if [ -n "${CECORE_ISA_FRONTEND:-}" ]; then
    frontend=(--frontend "$CECORE_ISA_FRONTEND" --frontend-sysroot "${CECORE_ISA_FRONTEND_SYSROOT:-/}")
    name="$isa-guest-frontends"
fi
python3 test/isa_vm_gate.py "$kernel_path" "$vm_build/init" "$vm_build/fixture" \
    --qemu "$qemu" --expect-architecture "$expected" --kernel-args "$kernel_args" "${frontend[@]}" \
    --output "$vm_build/$name.log" --report "$vm_build/$name.json"
