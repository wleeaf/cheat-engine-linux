#!/usr/bin/env bash
# Architecture-generic process checks under a full RISC-V64 Linux guest.
# usage: tools/check-isa-vm.sh [BUILD_DIR] [--build-only]
# Needs: riscv64-linux-gnu-gcc/g++, cmake, ninja, curl, python3, and (unless
# --build-only) qemu-system-riscv64 with its bundled OpenSBI firmware.
set -euo pipefail
cd "$(dirname "$0")/.."
vm_build=$(realpath -m "${1:-build/isa-vm}")
build_only=0
[ "${2:-}" = "--build-only" ] && build_only=1
mkdir -p "$vm_build"
jobs="${CECORE_CI_JOBS:-1}"

# Pinned Ubuntu 24.04 generic RISC-V kernel; its vmlinuz is a raw boot Image.
kernel_package_sha256=76fed85a231f9605b75f0efc0d6ade95c9fa7cc43c17186d8434971a6ba363ca
kernel_package="$vm_build/linux-image-6.8.0-60-generic_6.8.0-60.63.1_riscv64.deb"
kernel_path="$vm_build/kernel/boot/vmlinuz-6.8.0-60-generic"
if [ ! -f "$kernel_path" ]; then
    if [ ! -f "$kernel_package" ]; then
        curl --fail --location --retry 3 --output "$kernel_package.tmp" \
            "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-riscv/$(basename "$kernel_package")"
        mv "$kernel_package.tmp" "$kernel_package"
    fi
    printf '%s  %s\n' "$kernel_package_sha256" "$kernel_package" | sha256sum --check
    dpkg-deb -x "$kernel_package" "$vm_build/kernel"
fi

# The same pinned Capstone source as the ARM64 guest checks, RISC-V only.
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
cc="${CECORE_RISCV64_CC:-riscv64-linux-gnu-gcc}"
cxx="${CECORE_RISCV64_CXX:-riscv64-linux-gnu-g++}"
cmake -S "$vm_build/capstone-source" -B "$vm_build/capstone-build" -G Ninja \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=riscv64 \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCAPSTONE_BUILD_TESTS=OFF \
    -DCAPSTONE_BUILD_CSTOOL=OFF -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_RISCV_SUPPORT=ON >/dev/null
cmake --build "$vm_build/capstone-build" -j"$jobs"
cmake -S test/isa_vm -B "$vm_build/driver-build" -G Ninja \
    -DCMAKE_C_COMPILER="$cc" -DCMAKE_CXX_COMPILER="$cxx" \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=riscv64 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$vm_build" \
    -DCECORE_VM_CAPSTONE_INCLUDE="$vm_build/capstone-source/include" \
    -DCECORE_VM_CAPSTONE_LIBRARY="$vm_build/capstone-build/libcapstone.a" >/dev/null
cmake --build "$vm_build/driver-build" --target init fixture -j"$jobs"
[ "$build_only" = 1 ] && exit 0
python3 test/isa_vm_gate.py "$kernel_path" "$vm_build/init" "$vm_build/fixture" \
    --qemu "${CECORE_RISCV64_QEMU:-qemu-system-riscv64}" --expect-architecture RISC-V64 \
    --output "$vm_build/riscv64-guest.log" --report "$vm_build/riscv64-guest.json"
