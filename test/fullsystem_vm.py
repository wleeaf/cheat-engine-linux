#!/usr/bin/env python3
"""Boot an architecture-native test driver under a real Linux guest kernel."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess


def write_initramfs(destination: pathlib.Path, files):
    """Stream newc into gzip; large Qt runtimes need no second in-memory copy."""
    offset = 0
    entries = [("dev", 0o040755, None, 0, 0), ("proc", 0o040755, None, 0, 0),
               ("tmp", 0o041777, None, 0, 0), ("dev/console", 0o020600, None, 5, 1),
               ("dev/null", 0o020666, None, 1, 3), ("dev/urandom", 0o020666, None, 1, 9)]
    directories = {"dev", "proc", "tmp"}
    names = set(directories) | {"dev/console", "dev/null", "dev/urandom"}
    for name, path in files:
        relative = pathlib.PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or name in names:
            raise ValueError(f"invalid or duplicate initramfs entry: {name}")
        names.add(name)
        for directory in reversed(relative.parents):
            if str(directory) != "." and str(directory) not in directories:
                entries.append((str(directory), 0o040755, None, 0, 0))
                directories.add(str(directory))
        entries.append((name, 0o100755, path, 0, 0))
    entries.append(("TRAILER!!!", 0, None, 0, 0))
    with destination.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as archive:
        for inode, (name, mode, path, major, minor) in enumerate(entries, 1):
            encoded = name.encode() + b"\0"
            size = path.stat().st_size if path else 0
            fields = (inode, mode, 0, 0, 1, 0, size, 0, 0, major, minor, len(encoded), 0)
            header = b"070701" + b"".join(f"{field:08x}".encode() for field in fields) + encoded
            archive.write(header); offset += len(header)
            padding = -offset % 4
            archive.write(b"\0" * padding); offset += padding
            if path:
                with path.open("rb") as source:
                    shutil.copyfileobj(source, archive, length=65536)
                offset += size
            padding = -offset % 4
            archive.write(b"\0" * padding); offset += padding


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=pathlib.Path)
    parser.add_argument("init", type=pathlib.Path)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--cpus", type=int, choices=(1, 2), default=2)
    parser.add_argument("--ram-mib", type=int, choices=(128, 256, 512), default=512)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--expected-page-size", type=int, choices=(4096, 16384, 65536))
    parser.add_argument("--sme", choices=("required", "unavailable"), default="required")
    parser.add_argument("--native-call-fixture", type=pathlib.Path, required=True)
    parser.add_argument("--native-call-library", type=pathlib.Path, required=True)
    parser.add_argument("--native-call-loader", type=pathlib.Path, required=True)
    parser.add_argument("--native-call-libc", type=pathlib.Path, required=True)
    parser.add_argument("--native-call-libgcc", type=pathlib.Path, required=True)
    args = parser.parse_args()
    native_files = (("native_call_fixture", args.native_call_fixture),
                    ("libnative_call_library.so", args.native_call_library),
                    ("lib/ld-linux-aarch64.so.1", args.native_call_loader),
                    ("lib/libc.so.6", args.native_call_libc),
                    ("lib/libgcc_s.so.1", args.native_call_libgcc))
    for path in (args.kernel, args.init, args.fixture, *(path for _, path in native_files)):
        if not path.is_file():
            parser.error(f"missing required VM input: {path}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "suite": "arm64-memory-syscalls-debugger-trace-codefinder-and-recovery",
        "platform": platform.platform(),
        "sourceRevision": os.environ.get("GITHUB_SHA"),
        "sourceRef": os.environ.get("GITHUB_REF"),
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "failed",
        "expectedPageSize": args.expected_page_size,
        "smeProfile": args.sme,
        "guestCpus": args.cpus, "guestRamMiB": args.ram_mib,
        "kernelSha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
        "initSha256": hashlib.sha256(args.init.read_bytes()).hexdigest(),
        "fixtureSha256": hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
        "nativeCallFiles": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in native_files},
    }
    output = b""
    try:
        if report["kernelSha256"] != args.kernel_sha256.lower():
            raise RuntimeError("required guest kernel hash does not match")
        for binary in (args.init, args.fixture, *(path for _, path in native_files)):
            header = binary.read_bytes()[:20]
            if len(header) < 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
                raise RuntimeError(f"VM binary is not a real little-endian ELF64 AArch64 program: {binary}")
        report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=15).splitlines()[0]
        ramfs = args.output.with_suffix(".initramfs.gz")
        write_initramfs(ramfs, (("init", args.init), ("fixture", args.fixture), *native_files))
        command = [args.qemu, "-machine", "virt", "-cpu", "max", "-smp", str(args.cpus), "-m", f"{args.ram_mib}M",
                   "-nographic", "-nic", "none", "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel),
                   "-initrd", str(ramfs), "-append", "console=ttyAMA0 rdinit=/init panic=1"]
        if args.sme == "unavailable":
            command[-1] += " ce_vm_sme=unavailable"
        result = subprocess.run(command, capture_output=True, timeout=90)
        output = result.stdout + result.stderr
        report["exitCode"] = result.returncode
        decoded = output.decode(errors="replace").replace("\r", "")
        guest = re.search(r"^SYSCALL_KERNEL release=(\S+) machine=(\S+)$", decoded, re.MULTILINE)
        if guest:
            report["guestKernel"], report["guestMachine"] = guest.groups()
        page = re.search(r"^SYSCALL_TARGET architecture=ARM64 abi=Linux AArch64 width=8 pageSize=(\d+)$", decoded, re.MULTILINE)
        if page:
            report["guestPageSize"] = int(page.group(1))
        if not page or (args.expected_page_size is not None and report["guestPageSize"] != args.expected_page_size):
            raise RuntimeError("required guest page size does not match")
        vector_cases = (
            "CODEFINDER_BACKEND_RESULT", "CODEFINDER_TEARDOWN_RESULT", "STOPPED_SYSCALL_RESULT", "SOFTWARE_CODEFINDER_RESULT", "CODEFINDER_SIGNAL_RESULT",
            "SHARED_SYSCALL_RESULT", "SYSCALL_POLICY_RESULT", "PREFLIGHT_RECOVERY_RESULT", "SVE_SYSCALL_RESULT", "SME_SYSCALL_RESULT",
            "MAXIMUM_SVE_SYSCALL_RESULT", "MAXIMUM_SME_SYSCALL_RESULT",
            "STOPPED_FUNCTION_RESULT", "NATIVE_CALL_OWNER_RESULT", "SVE_FUNCTION_RESULT", "SME_FUNCTION_RESULT",
            "MAXIMUM_SVE_FUNCTION_RESULT", "MAXIMUM_SME_FUNCTION_RESULT",
            "DEFERRED_SVE_CONTROL_RESULT", "DEFERRED_SME_CONTROL_RESULT",
            "DEFERRED_SVE_SYSCALL_RESULT", "DEFERRED_SME_SYSCALL_RESULT",
            "DEFERRED_SVE_PRIVATE_RESULT", "DEFERRED_SME_PRIVATE_RESULT",
            "DEFERRED_SVE_QUIESCED_RESULT", "DEFERRED_SME_QUIESCED_RESULT",
            "DEFERRED_SVE_FUNCTION_RESULT", "DEFERRED_SME_FUNCTION_RESULT",
            "SVE_SECCOMP_GUARD_RESULT", "SME_SECCOMP_GUARD_RESULT",
            "SVE_ALTSTACK_GUARD_RESULT", "SME_ALTSTACK_GUARD_RESULT")
        excluded = [name for name in vector_cases if args.sme == "unavailable" and
                    "SME" in name]
        report["excludedCases"] = excluded
        if args.sme == "unavailable" and "VECTOR_PROFILE_RESULT=PASSED sve=available sme=unavailable\n" not in decoded:
            raise RuntimeError("required non-SME guest capability verification failed")
        if (result.returncode or "CE_VM_RESULT=PASSED\n" not in decoded or "FAILED:" in decoded or
                not guest or guest.group(2) != "aarch64" or
                "SYSCALL_TARGET architecture=ARM64 abi=Linux AArch64 width=8" not in decoded or
                "DEBUG_BACKEND_RESULT=PASSED architecture=ARM64\n" not in decoded or
                "DEBUG_SESSION_RESULT=PASSED architecture=ARM64\n" not in decoded or
                "TRACE_BACKEND_RESULT=PASSED architecture=ARM64\n" not in decoded or
                "NATIVE_INJECTOR_RESULT=PASSED width=8\n" not in decoded or
                "PARKED_NATIVE_CALL_RESULT=PASSED width=8\n" not in decoded or
                "NATIVE_THREAD_LIFETIME_RESULT=PASSED width=8\n" not in decoded or
                "LEADER_NATIVE_CALL_RESULT=PASSED width=8\n" not in decoded or
                "LEADER_EXIT_RESULT=PASSED\n" not in decoded or
                "SESSION_THREAD_EXIT_RESULT=PASSED\n" not in decoded or
                any(f"{name}=PASSED architecture=ARM64\n" not in decoded for name in vector_cases if name not in excluded) or
                "DEBUG_RECOVERY_RESULT=PASSED\n" not in decoded):
            raise RuntimeError("required full-system guest integration failed")
        report["status"] = "passed"
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + (error.stderr or b"")
        report["error"] = "required full-system guest timed out"
        raise SystemExit(report["error"]) from error
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
        raise SystemExit(str(error)) from error
    finally:
        args.output.write_bytes(output)
        decoded = output.decode(errors="replace").replace("\r", "")
        report["checks"] = [line for line in decoded.splitlines() if line.startswith(("OK:", "FAILED:"))]
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(decoded, end="", flush=True)


if __name__ == "__main__":
    main()
