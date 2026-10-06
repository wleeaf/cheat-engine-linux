#!/usr/bin/env bash
# Required memory, register and breakpoint operations under a full ARM64 Linux kernel.
set -euo pipefail
cd "$(dirname "$0")/.."
vm_build=$(realpath -m "${1:-build/arm64-vm}")
mkdir -p "$vm_build"
page_size="${CECORE_VM_PAGE_SIZE:-4096}"
profile_flags=()
report_suffix=""
case "$page_size" in
    4096)
        kernel_sha256=06196d2cf51e9a2bac421564bb64c63a8b7146c9a22755dd22a713e337023013
        kernel_url=https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot/vmlinuz-virt
        kernel_path="${CECORE_VM_KERNEL:-$vm_build/vmlinuz-virt}"
        if [ ! -f "$kernel_path" ]; then
            curl --fail --location --retry 3 --output "$kernel_path.tmp" "$kernel_url"
            mv "$kernel_path.tmp" "$kernel_path"
        fi
        ;;
    65536)
        # This additional kernel lacks SME. The gate verifies that absence and
        # lists excluded cases; the original kernel still requires SME coverage.
        kernel_sha256=d5f5150b83c59404233bde3859817d4665301e0bfab20fa47ccdac4bfbeb1ae8
        kernel_package_sha256=cdda8dffebebb6677292d17d9d9741f8c52663be680153d13f5289610ea2b9c8
        kernel_package="$vm_build/linux-image-6.8.0-146-generic-64k_6.8.0-146.146_arm64.deb"
        kernel_url=https://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-signed/linux-image-6.8.0-146-generic-64k_6.8.0-146.146_arm64.deb
        kernel_path="${CECORE_VM_KERNEL:-$vm_build/kernel-64k/boot/vmlinuz-6.8.0-146-generic-64k}"
        if [ ! -f "$kernel_path" ]; then
            if [ ! -f "$kernel_package" ]; then
                curl --fail --location --retry 3 --output "$kernel_package.tmp" "$kernel_url"
                mv "$kernel_package.tmp" "$kernel_package"
            fi
            printf '%s  %s\n' "$kernel_package_sha256" "$kernel_package" | sha256sum --check
            dpkg-deb -x "$kernel_package" "$vm_build/kernel-64k"
        fi
        profile_flags+=(--sme unavailable)
        report_suffix=-64k
        ;;
    *) printf 'Unsupported required ARM64 page-size profile: %s\n' "$page_size" >&2; exit 1 ;;
esac
printf '%s  %s\n' "$kernel_sha256" "$kernel_path" | sha256sum --check
# The session uses the same pinned decoder source as cecore. Build it for the
# guest instead of linking a host library or replacing instruction decoding.
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
cmake -S "$vm_build/capstone-source" -B "$vm_build/capstone-build" \
    -DCMAKE_C_COMPILER="${CECORE_ARM64_CC:-aarch64-linux-gnu-gcc}" \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF \
    -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_ARM64_SUPPORT=ON
cmake --build "$vm_build/capstone-build" -j"${CECORE_CI_JOBS:-1}"
cmake -S test/arm64_vm -B "$vm_build/driver-build" \
    -DCMAKE_C_COMPILER="${CECORE_ARM64_CC:-aarch64-linux-gnu-gcc}" \
    -DCMAKE_CXX_COMPILER="${CECORE_ARM64_CXX:-aarch64-linux-gnu-g++}" \
    -DCMAKE_ASM_COMPILER="${CECORE_ARM64_CC:-aarch64-linux-gnu-gcc}" \
    -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$vm_build" \
    -DCECORE_VM_CAPSTONE_INCLUDE="$vm_build/capstone-source/include" \
    -DCECORE_VM_CAPSTONE_LIBRARY="$vm_build/capstone-build/libcapstone.a"
cmake --build "$vm_build/driver-build" --target init fixture native_call_fixture native_call_library native_call_image_init native_call_exec_init native_call_image_fixture relocation_init code_write_init memory_image_init shared_mm_fixture -j"${CECORE_CI_JOBS:-1}"
arm64_cc="${CECORE_ARM64_CC:-aarch64-linux-gnu-gcc}"
guest_libc=$("$arm64_cc" -print-file-name=libc.so.6)
guest_loader=$("$arm64_cc" -print-file-name=ld-linux-aarch64.so.1)
guest_libgcc=$("$arm64_cc" -print-file-name=libgcc_s.so.1)
python3 test/fullsystem_vm.py "$kernel_path" "$vm_build/init" "$vm_build/fixture" \
    --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" --kernel-sha256 "$kernel_sha256" \
    --native-call-fixture "$vm_build/native_call_fixture" --native-call-library "$vm_build/libnative_call_library.so" \
    --native-call-libc "$guest_libc" --native-call-loader "$guest_loader" --native-call-libgcc "$guest_libgcc" \
    --expected-page-size "$page_size" "${profile_flags[@]}" \
    --output "$vm_build/guest$report_suffix.log" --report "$vm_build/arm64-syscalls$report_suffix.json"
python3 test/aarch64_relocation_gate.py "$kernel_path" "$vm_build/relocation_init" \
    --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" --kernel-sha256 "$kernel_sha256" \
    --page-size "$page_size" --output "$vm_build/relocation$report_suffix.log" \
    --report "$vm_build/arm64-relocation$report_suffix.json"
python3 test/code_write_gate.py "$vm_build/code_write_init" --kernel "$kernel_path" \
    --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" --kernel-sha256 "$kernel_sha256" \
    --page-size "$page_size" --output "$vm_build/code-write$report_suffix.log" \
    --report "$vm_build/arm64-code-write$report_suffix.json"
python3 test/memory_image_gate.py "$vm_build/memory_image_init" --fixture "$vm_build/shared_mm_fixture" --kernel "$kernel_path" \
    --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" --kernel-sha256 "$kernel_sha256" \
    --page-size "$page_size" --output "$vm_build/memory-image$report_suffix.log" \
    --report "$vm_build/arm64-memory-image$report_suffix.json"
python3 test/native_call_image_gate.py "$vm_build/native_call_image_init" \
    --fixture "$vm_build/native_call_image_fixture" --kernel "$kernel_path" --kernel-sha256 "$kernel_sha256" \
    --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" \
    --loader "$guest_loader" --libc "$guest_libc" --libgcc "$guest_libgcc" \
    --page-size "$page_size" --output "$vm_build/native-call-image$report_suffix.log" \
    --report "$vm_build/arm64-native-call-image$report_suffix.json"

python3 test/native_call_exec_gate.py "$vm_build/native_call_exec_init" \
    --fixture "$vm_build/native_call_image_fixture" --kernel "$kernel_path" --kernel-sha256 "$kernel_sha256" \
    --qemu "${CECORE_ARM64_QEMU:-qemu-system-aarch64}" \
    --loader "$guest_loader" --libc "$guest_libc" --libgcc "$guest_libgcc" \
    --page-size "$page_size" --output "$vm_build/native-call-exec$report_suffix.log" \
    --report "$vm_build/arm64-native-call-exec$report_suffix.json"
