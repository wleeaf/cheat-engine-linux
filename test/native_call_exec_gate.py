#!/usr/bin/env python3
"""Require native callee exec retirement and failed-detach recovery."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from fullsystem_vm import write_initramfs


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build_or_init", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--loader", type=Path)
    parser.add_argument("--libc", type=Path)
    parser.add_argument("--libgcc", type=Path)
    parser.add_argument("--kernel-sha256")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--page-size", type=int, choices=(4096, 16384, 65536))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.kernel and (not args.fixture or not args.kernel_sha256 or not args.page_size or
                        not args.loader or not args.libc or not args.libgcc):
        parser.error("guest checks require the fixture, pinned kernel hash, page size and native libc runtime")
    driver = (args.build_or_init if args.kernel else args.build_or_init / "native_call_exec_integration").resolve()
    fixture = (args.fixture or args.build_or_init / "native_call_image_fixture").resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"suite": "native-callee-exec-retirement", "passed": False,
              "utc": datetime.now(timezone.utc).isoformat(),
              "sourceRevision": os.environ.get("GITHUB_SHA"), "sourceRef": os.environ.get("GITHUB_REF")}
    output = b""
    try:
        report.update(driverSha256=sha(driver), fixtureSha256=sha(fixture))
        if args.kernel:
            report["kernelSha256"] = sha(args.kernel)
            if report["kernelSha256"] != args.kernel_sha256.lower():
                raise RuntimeError("required kernel hash does not match")
            native_files = (("lib/ld-linux-aarch64.so.1", args.loader),
                            ("lib/libc.so.6", args.libc), ("lib/libgcc_s.so.1", args.libgcc))
            report["runtimeSha256"] = {name: sha(path) for name, path in native_files}
            for binary in (driver, fixture, *(path for _, path in native_files)):
                with binary.open("rb") as source:
                    header = source.read(20)
                if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
                    raise RuntimeError("guest inputs must be actual little-endian ELF64 AArch64 binaries")
            ramfs = args.output.with_suffix(".initramfs.gz")
            write_initramfs(ramfs, (("init", driver), ("native_call_image_fixture", fixture), *native_files))
            command = [args.qemu, "-machine", "virt", "-cpu", "max", "-smp", "1", "-m", "128M",
                       "-nographic", "-nic", "none", "-monitor", "none", "-no-reboot",
                       "-kernel", str(args.kernel), "-initrd", str(ramfs),
                       "-append", "console=ttyAMA0 rdinit=/init panic=1"]
            report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=10).splitlines()[0]
        else:
            command = [str(driver), str(fixture)]
            report["coreSha256"] = sha(args.build_or_init / "libcecore.so")
        report["command"] = command
        result = subprocess.run(command, capture_output=True, timeout=70)
        output = result.stdout + result.stderr
        decoded = output.decode(errors="replace").replace("\r", "")
        success = re.search(r"NATIVE_CALL_EXEC_RESULT=PASSED width=([48]) checks=(\d+) failures=0", decoded)
        page = re.search(r"CALL_EXEC_PAGE_SIZE=(\d+)", decoded)
        if result.returncode or not success or int(success[2]) != 475 or "FAILED:" in decoded or not page:
            raise RuntimeError("required native callee exec matrix did not complete")
        if args.kernel and (int(success[1]) != 8 or "machine=aarch64\n" not in decoded):
            raise RuntimeError("required guest is not an actual AArch64 kernel process")
        if args.page_size and int(page[1]) != args.page_size:
            raise RuntimeError("actual kernel page size does not match required profile")
        report.update(passed=True, width=int(success[1]), checks=int(success[2]), pageSize=int(page[1]), exitCode=result.returncode)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            output = (error.stdout or b"") + (error.stderr or b"")
    args.output.write_bytes(output)
    report["outputSha256"] = sha(args.output)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(output.decode(errors="replace"), end="", flush=True)
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
