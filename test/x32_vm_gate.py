#!/usr/bin/env python3
"""Run LP64 engine drivers against real x32 programs in an isolated Linux VM."""
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


def require_elf(path, elf_class):
    with path.open("rb") as source:
        header = source.read(20)
    if (len(header) != 20 or header[:6] != b"\x7fELF" + bytes((elf_class, 1)) or
            header[18:20] != b"\x3e\x00"):
        raise RuntimeError(f"required ELF{elf_class * 32} x86-64 input is invalid: {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--libgcc", type=Path, required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--accel", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument("--suite", choices=("calls", "image", "exec", "debug", "all"), default="all")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"suite": "linux-x32-native-calls-image-recovery-and-debugger", "passed": False,
              "utc": datetime.now(timezone.utc).isoformat(),
              "sourceRevision": os.environ.get("GITHUB_SHA"), "sourceRef": os.environ.get("GITHUB_REF"),
              "guestRamMiB": 128, "profiles": []}
    suites = {"calls": ("x32_call_init", "native_call_fixture"),
              "image": ("native_call_image_init", "native_call_image_fixture"),
              "exec": ("native_call_exec_init", "native_call_image_fixture"),
              "debug": ("x32_debug_init", "compatibility_fixturex32")}
    try:
        report["kernelSha256"] = sha(args.kernel)
        if report["kernelSha256"] != args.kernel_sha256.lower():
            raise RuntimeError("required guest kernel hash does not match")
        runtime = (("libx32/ld-linux-x32.so.2", args.loader), ("libx32/libc.so.6", args.libc),
                   ("libx32/libgcc_s.so.1", args.libgcc))
        for _, path in runtime:
            require_elf(path, 1)
        report["runtimeSha256"] = {name: sha(path) for name, path in runtime}
        report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=10).splitlines()[0]
        for suite, (driver_name, fixture_name) in suites.items():
            if args.suite not in (suite, "all"):
                continue
            driver, fixture = args.build / driver_name, args.build / fixture_name
            require_elf(driver, 2)
            require_elf(fixture, 1)
            files = (("init", driver), ("fixture" if suite == "debug" else fixture_name, fixture), *runtime)
            if suite == "calls":
                library = args.build / "libnative_call_library.so"
                require_elf(library, 1)
                files += (("libnative_call_library.so", library),)
            output = args.output_dir / f"x32-{suite}.log"
            ramfs = args.output_dir / f"x32-{suite}.initramfs.gz"
            cpus = 2 if suite == "debug" else 1
            profile = {"suite": suite, "passed": False, "guestCpus": cpus, "guestRamMiB": 128,
                       "inputsSha256": {name: sha(path) for name, path in files}}
            report["profiles"].append(profile)
            write_initramfs(ramfs, files)
            command = [args.qemu, "-machine", "pc", "-accel", args.accel,
                       "-cpu", "host" if args.accel == "kvm" else "max", "-smp", str(cpus), "-m", "128M",
                       "-nographic", "-nic", "none", "-monitor", "none", "-no-reboot",
                       "-kernel", str(args.kernel), "-initrd", str(ramfs),
                       "-append", "console=ttyS0 rdinit=/init panic=1 syscall.x32=y"]
            if suite == "debug":
                command[-1] += " ce_vm_dispatch=legacy"
            profile["command"] = command
            data = b""
            try:
                result = subprocess.run(command, capture_output=True, timeout=70)
                data = result.stdout + result.stderr
                profile["exitCode"] = result.returncode
            except subprocess.TimeoutExpired as error:
                data = (error.stdout or b"") + (error.stderr or b"")
                profile["error"] = "required x32 guest timed out"
                raise RuntimeError(profile["error"]) from error
            finally:
                output.write_bytes(data)
                profile["outputSha256"] = sha(output)
                print(data.decode(errors="replace"), end="", flush=True)
            decoded = data.decode(errors="replace").replace("\r", "")
            profile["checks"] = sum(line.startswith("OK:") for line in decoded.splitlines())
            prefix = {"calls": "X32_CALL", "image": "CALL_IMAGE", "exec": "CALL_EXEC", "debug": "SYSCALL"}[suite]
            kernel = re.search(rf"^{prefix}_KERNEL release=(\S+) machine=x86_64$", decoded, re.MULTILINE)
            page_marker = ("SYSCALL_TARGET architecture=x86-64 abi=Linux x32 width=4 pageSize=4096\n"
                           if suite == "debug" else f"{prefix}_PAGE_SIZE=4096\n")
            if result.returncode or "FAILED:" in decoded or not kernel or page_marker not in decoded:
                raise RuntimeError(f"required {suite} guest profile failed")
            profile["guestKernel"] = kernel[1]
            if suite == "debug":
                expected = "CE_VM_RESULT=PASSED\n"
                boundary = re.findall(r'^RETURN_BOUNDARY_CHECK (OK|FAILED):', decoded, re.MULTILINE)
                if (re.findall(r'^RETURN_BOUNDARY_RESULT=.*$', decoded, re.MULTILINE) != ['RETURN_BOUNDARY_RESULT=PASSED architecture=x86-64 checks=26'] or
                        len(boundary) != 26 or any(value != 'OK' for value in boundary)):
                    raise RuntimeError("required x32 return-instruction boundary checks did not complete")
                profile["returnBoundaryChecks"] = 26
                profile["checks"] += 26
                restart = re.findall(r'^RESTART_BOUNDARY_CHECK (OK|FAILED):', decoded, re.MULTILINE)
                if (re.findall(r'^RESTART_BOUNDARY_RESULT=.*$', decoded, re.MULTILINE) != ['RESTART_BOUNDARY_RESULT=PASSED architecture=x86-64 checks=50'] or
                        len(restart) != 50 or any(value != 'OK' for value in restart)):
                    raise RuntimeError("required x32 syscall-restart boundary checks did not complete")
                profile["restartBoundaryChecks"] = 50
                profile["checks"] += 50
                for marker in ("SESSION_THREAD_EXIT", "DEBUG_BACKEND", "DEBUG_SESSION", "DEBUG_RECOVERY",
                               "TRACE_BACKEND", "CODEFINDER_BACKEND", "STOPPED_SYSCALL", "SOFTWARE_CODEFINDER",
                               "CODEFINDER_SIGNAL", "CODEFINDER_TEARDOWN", "LEADER_EXIT", "PREFLIGHT_RECOVERY",
                               "STOPPED_FUNCTION", "NATIVE_CALL_OWNER", "SHARED_SYSCALL", "SYSCALL_POLICY",
                               "SYSCALL_DISPATCH_LEGACY"):
                    if not re.search(rf"^{marker}_RESULT=PASSED(?: architecture=x86-64)?$", decoded, re.MULTILINE):
                        raise RuntimeError(f"required x32 {marker} checks did not complete")
            elif suite == "exec":
                expected = "NATIVE_CALL_EXEC_RESULT=PASSED width=4 checks=475 failures=0\n"
            elif suite == "image":
                expected = "NATIVE_CALL_IMAGE_RESULT=PASSED width=4\nNATIVE_CALL_IMAGE_CHECKS=83 failures=0\n"
            else:
                expected = "X32_CALL_RESULT=PASSED\n"
                for marker in ("NATIVE_INJECTOR", "NATIVE_THREAD_LIFETIME", "LEADER_NATIVE_CALL", "PARKED_NATIVE_CALL", "X32_WIDE_CALL"):
                    if f"{marker}_RESULT=PASSED width=4\n" not in decoded:
                        raise RuntimeError(f"required x32 {marker} checks did not complete")
            if expected not in decoded:
                raise RuntimeError(f"required x32 {suite} matrix did not complete")
            if profile["checks"] != {"calls": 40, "image": 83, "exec": 475, "debug": 627}[suite]:
                raise RuntimeError(f"required x32 {suite} checks are incomplete")
            profile["passed"] = True
        report["passed"] = True
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
