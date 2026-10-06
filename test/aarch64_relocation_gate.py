#!/usr/bin/env python3
"""Execute the real relocator under a pinned ARM64 Linux kernel with one vCPU."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from fullsystem_vm import write_initramfs


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=Path)
    parser.add_argument("init", type=Path)
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--page-size", type=int, choices=(4096, 65536), required=True)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"schemaVersion": 1, "createdUTC": datetime.now(timezone.utc).isoformat(),
              "scope": "Actual ARM64 Linux execution of GNU-assembled original and relocated code; W^X mapping/cache synchronization, live literal data, branches/calls, flags and restoration. Does not establish native hook installation or external-process code-cache synchronization.",
              "initSha256": sha(args.init), "kernelSha256": sha(args.kernel),
              "resources": {"cpus": 1, "memoryMiB": 128, "nice": 10},
              "sourceState": "uncommitted worktree snapshot"}
    output = b""
    try:
        if report["kernelSha256"] != args.kernel_sha256:
            raise RuntimeError("required kernel hash mismatch")
        header = args.init.read_bytes()[:20]
        if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
            raise RuntimeError("required driver must be a real LE ELF64 AArch64 program")
        ramfs = args.output.with_suffix(".initramfs.gz")
        write_initramfs(ramfs, (("init", args.init),))
        command = [args.qemu, "-machine", "virt", "-cpu", "max", "-smp", "1", "-m", "128M",
                   "-nographic", "-nic", "none", "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel),
                   "-initrd", str(ramfs), "-append", "console=ttyAMA0 rdinit=/init panic=1"]
        report["command"] = command
        report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=10).splitlines()[0]
        result = subprocess.run(command, capture_output=True, timeout=60)
        output = result.stdout + result.stderr
        report["exitCode"] = result.returncode
        decoded = output.decode(errors="replace").replace("\r", "")
        kernel = re.search(r"AARCH64_RELOCATION_KERNEL=(\S+) pageSize=(\d+)", decoded)
        success = re.search(r"AARCH64_RELOCATION_RESULT=PASSED checks=(\d+) executions=(\d+) failures=0", decoded)
        if result.returncode or not kernel or int(kernel[2]) != args.page_size or not success or int(success[1]) != 21 or int(success[2]) != 1119 or "FAILED:" in decoded:
            raise RuntimeError("required relocation execution/restoration matrix did not complete")
        report.update(passed=True, guestKernel=kernel[1], pageSize=int(kernel[2]), checks=int(success[1]), executions=int(success[2]))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(passed=False, error=str(error))
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
