#!/usr/bin/env bash
# Small actual ARM/Thumb kernel tests; reuse builds and run guests sequentially.
set -euo pipefail
cd "$(dirname "$0")/.."
vm_build=$(realpath -m "${1:-build/arm32-vm}")
mkdir -p "$vm_build"
arm_kernel="${CECORE_ARM32_KERNEL:-$vm_build/vmlinuz-lts}"
compat_kernel="${CECORE_ARM64_KERNEL:-$vm_build/vmlinuz-virt}"
arm_hash=657d301cf57be0d1202b1d0e0c156ef5c926b7869f1208b676994d1768530649
compat_hash=06196d2cf51e9a2bac421564bb64c63a8b7146c9a22755dd22a713e337023013
fetch_kernel() {
    local kernel_path="$1" kernel_url="$2" kernel_hash="$3"
    if [ ! -f "$kernel_path" ]; then
        curl --fail --location --retry 3 --output "$kernel_path.tmp" "$kernel_url"
        mv "$kernel_path.tmp" "$kernel_path"
    fi
    printf '%s  %s\n' "$kernel_hash" "$kernel_path" | sha256sum --check
}
fetch_kernel "$arm_kernel" https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/armv7/netboot/vmlinuz-lts "$arm_hash"
fetch_kernel "$compat_kernel" https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot/vmlinuz-virt "$compat_hash"
arm_cc="${CECORE_ARM32_CC:-arm-linux-gnueabihf-gcc}"
arm_cxx="${CECORE_ARM32_CXX:-arm-linux-gnueabihf-g++}"
compat_cc="${CECORE_ARM64_CC:-aarch64-linux-gnu-gcc}"
compat_cxx="${CECORE_ARM64_CXX:-aarch64-linux-gnu-g++}"
build_suffix=""
cxx_flags=""
if [ "${CECORE_ARM32_UBSAN:-0}" = 1 ]; then
    build_suffix=-ubsan
    cxx_flags="-fsanitize=undefined -fno-sanitize-recover=all"
fi
{
    "$arm_cxx" --version
    "$compat_cxx" --version
    printf 'CXX_FLAGS=%s\nBUILD_JOBS=1\n' "$cxx_flags"
} > "$vm_build/toolchain$build_suffix.log"
cmake -S test/arm32_vm -B "$vm_build/native$build_suffix-build" -G Ninja \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=arm -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$arm_cc" -DCMAKE_CXX_COMPILER="$arm_cxx" -DCMAKE_CXX_FLAGS="$cxx_flags"
nice -n 10 cmake --build "$vm_build/native$build_suffix-build" -j1
nice -n 10 python3 test/arm32_register_gate.py "$arm_kernel" \
    "$vm_build/native$build_suffix-build/register_init" "$vm_build/native$build_suffix-build/register_fixture" \
    --profile arm32 --kernel-sha256 "$arm_hash" --qemu "${CECORE_ARM32_QEMU:-qemu-system-arm}" \
    --output "$vm_build/native$build_suffix.log" --report "$vm_build/native$build_suffix.json"
cmake -S test/arm32_vm -B "$vm_build/compat$build_suffix-build" -G Ninja \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$compat_cc" -DCMAKE_CXX_COMPILER="$compat_cxx" -DCMAKE_CXX_FLAGS="$cxx_flags"
nice -n 10 cmake --build "$vm_build/compat$build_suffix-build" -j1
nice -n 10 python3 test/arm32_register_gate.py "$compat_kernel" \
    "$vm_build/compat$build_suffix-build/register_init" "$vm_build/native$build_suffix-build/register_fixture" \
    --profile arm64-compat --kernel-sha256 "$compat_hash" --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" \
    --output "$vm_build/compat$build_suffix.log" --report "$vm_build/compat$build_suffix.json"
