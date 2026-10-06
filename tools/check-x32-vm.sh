#!/usr/bin/env bash
# Use a prebuilt x32-enabled kernel; never rebuild a kernel or boot the host.
set -euo pipefail
cd "$(dirname "$0")/.."
vm_build=$(realpath -m "${1:-build/x32-vm}")
mkdir -p "$vm_build/tmp"
export TMPDIR="$vm_build/tmp"
python3 tools/generate-thread-entry.py --architecture x32
kernel_package="$vm_build/linux-image-6.1.0-50-amd64_6.1.176-1_amd64.deb"
kernel_url=https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/linux-image-6.1.0-50-amd64_6.1.176-1_amd64.deb
kernel_package_sha256=7b5597492a0a65aee61985a492e6bcc3f2cde830072a0e3b3d8c7e1b90279bd3
kernel_sha256=d8808aa4ca188560da1e6d749dcb930c87a5fd8b11ebff1f3fa6d728af35203d
if [ ! -f "$kernel_package" ]; then
    curl --fail --location --retry 3 --output "$kernel_package.tmp" "$kernel_url"
    mv "$kernel_package.tmp" "$kernel_package"
fi
printf '%s  %s\n' "$kernel_package_sha256" "$kernel_package" | sha256sum --check
mkdir -p "$vm_build/kernel"
# Extract only boot files instead of unpacking hundreds of MiB of unused modules.
dpkg-deb --fsys-tarfile "$kernel_package" | tar -x -C "$vm_build/kernel" ./boot
kernel="$vm_build/kernel/boot/vmlinuz-6.1.0-50-amd64"
printf '%s  %s\n' "$kernel_sha256" "$kernel" | sha256sum --check
grep -qx 'CONFIG_X86_X32_ABI=y' "$vm_build/kernel/boot/config-6.1.0-50-amd64"

capstone_commit=097c04d9413c59a58b00d4d1c8d5dc0ac158ffaa
capstone_sha256=51c90b47cb1b8e3f55de45563ccea16786f902175672bcbb824fb5982f44dac2
archive="$vm_build/capstone.tar.gz"
if [ ! -f "$archive" ]; then
    curl --fail --location --retry 3 --output "$archive.tmp" \
        "https://codeload.github.com/capstone-engine/capstone/tar.gz/$capstone_commit"
    mv "$archive.tmp" "$archive"
fi
printf '%s  %s\n' "$capstone_sha256" "$archive" | sha256sum --check
mkdir -p "$vm_build/capstone-source"
tar -xzf "$archive" --strip-components=1 -C "$vm_build/capstone-source"
cmake -S "$vm_build/capstone-source" -B "$vm_build/capstone-build" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DCAPSTONE_BUILD_TESTS=OFF -DCAPSTONE_BUILD_CSTOOL=OFF \
    -DCAPSTONE_ARCHITECTURE_DEFAULT=OFF -DCAPSTONE_X86_SUPPORT=ON
nice -n 10 cmake --build "$vm_build/capstone-build" -j1
cmake -S test/arm64_vm -B "$vm_build/driver-build" \
    -DCMAKE_BUILD_TYPE=Release -DCECORE_VM_X32_TESTS=ON \
    -DCMAKE_RUNTIME_OUTPUT_DIRECTORY="$vm_build" \
    -DCECORE_VM_CAPSTONE_INCLUDE="$vm_build/capstone-source/include" \
    -DCECORE_VM_CAPSTONE_LIBRARY="$vm_build/capstone-build/libcapstone.a"
nice -n 10 cmake --build "$vm_build/driver-build" \
    --target x32_call_init native_call_image_init native_call_exec_init x32_debug_init -j1
# Only target fixtures use -mx32. The engine remains a normal LP64 program.
for fixture in native_call_fixture native_call_image_fixture; do
    nice -n 10 gcc -mx32 -O2 -fno-pie -no-pie -rdynamic \
        "test/$fixture.c" -pthread -o "$vm_build/$fixture"
done
nice -n 10 gcc -mx32 -O2 -ffreestanding -fno-builtin -fno-pie -fno-stack-protector \
    -fomit-frame-pointer -I/usr/include/x86_64-linux-gnu -nostdlib -static -no-pie \
    test/compatibility_fixture.c -o "$vm_build/compatibility_fixturex32"
nice -n 10 gcc -mx32 -O2 -fPIC -shared test/native_call_library.c \
    -ldl -o "$vm_build/libnative_call_library.so"
x32_loader=$(gcc -mx32 -print-file-name=ld-linux-x32.so.2)
x32_libc=$(gcc -mx32 -print-file-name=libc.so.6)
x32_libgcc=$(gcc -mx32 -print-file-name=libgcc_s.so.1)
nice -n 10 python3 test/x32_vm_gate.py "$vm_build" --kernel "$kernel" \
    --kernel-sha256 "$kernel_sha256" --loader "$x32_loader" --libc "$x32_libc" --libgcc "$x32_libgcc" \
    --accel "${CECORE_X32_ACCEL:-tcg}" --qemu "${CECORE_X32_QEMU:-qemu-system-x86_64}" \
    --output-dir "$vm_build/evidence" --report "$vm_build/evidence/x32.json"
