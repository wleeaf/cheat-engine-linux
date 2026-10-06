#!/usr/bin/env python3
"""Require live executable-code edits and recovery, locally or under ARM64 Linux."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import re
import selectors
import subprocess
import tempfile
from fullsystem_vm import write_initramfs


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def line(process):
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ)
        if not ready.select(10):
            raise RuntimeError("owned executable fixture response timed out")
        answer = process.stdout.readline()
        if not answer:
            raise RuntimeError("owned executable fixture exited without its response")
        return answer.decode().strip()


def cli_checks(build, directory, output):
    fixture = subprocess.Popen([str(build / "code_write_integration"), "--fixture"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def expect_value(value):
        fixture.stdin.write(b"E"); fixture.stdin.flush()
        return line(fixture) == f"CE_CODE_VALUE={value}"
    def run_cli(*arguments):
        result = subprocess.run([str(build / "cescan"), *map(str, arguments)], capture_output=True, timeout=30)
        output.extend(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError("production CLI code workflow failed")
    try:
        header = line(fixture)
        output.extend((header + "\n").encode())
        info = re.fullmatch(r"CE_CODE_READY pid=(\d+) address=([0-9a-f]+) value=42", header)
        if not info or not expect_value(42):
            raise RuntimeError("production CLI fixture did not warm original code")
        pid, address = int(info[1]), int(info[2], 16)
        instruction = "mov w0, #0x2b" if platform.machine() == "aarch64" else "mov eax, 0x2b"
        script = directory / "patch.aa"
        script.write_text(f"[ENABLE]\n0x{address:x}:\n{instruction}\n")
        run_cli("autoasm", pid, script)
        if not expect_value(43):
            raise RuntimeError("CLI patch did not change actual fixture execution")
        original = "mov w0, #0x2a" if platform.machine() == "aarch64" else "mov eax, 0x2a"
        script.write_text(f"[ENABLE]\n0x{address:x}:\n{original}\n")
        run_cli("autoasm", pid, script)
        if not expect_value(42):
            raise RuntimeError("CLI restoration did not restore original execution")
        run_cli("lua", "-e", f"assert(openProcess({pid})); local a=0x{address:x}; local b=nopInstruction(a); assert(b); writeBytes(a,b); local r=readBytes(a,#b,true); for i,v in ipairs(b) do assert(r[i]==v) end")
        if not expect_value(42):
            raise RuntimeError("CLI Lua NOP/undo did not restore execution")
        fixture.stdin.write(b"Q"); fixture.stdin.flush()
        if fixture.wait(timeout=10):
            raise RuntimeError("CLI fixture did not finish normally")
        return 5
    finally:
        if fixture.poll() is None:
            fixture.kill(); fixture.wait(timeout=10)
        fixture.stdin.close(); fixture.stdout.close(); fixture.stderr.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build_or_init", type=Path)
    parser.add_argument("--kernel", type=Path)
    parser.add_argument("--kernel-sha256")
    parser.add_argument("--page-size", type=int, choices=(4096, 65536))
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.kernel and (not args.kernel_sha256 or not args.page_size):
        parser.error("guest checks require a pinned kernel hash and page size")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    driver = args.build_or_init if args.kernel else args.build_or_init / "code_write_integration"
    output = bytearray()
    report = {"schemaVersion": 1, "createdUTC": datetime.now(timezone.utc).isoformat(),
              "scope": "Actual executable RX-page writes, NOP/undo, debugger ownership, short/dropped/post-mutation writes, retained restoration, reentrant ownership, same-file exec and self-code edits. Guest excludes AutoAssembler and Lua; host additionally requires production CLI/Lua. Does not establish atomic live hooks, hardware caches, other ISAs or all kernel proc-mem policies.",
              "resources": {"cpus": 1, "guestMemoryMiB": 128, "nice": 10},
              "sourceState": "uncommitted worktree snapshot"}
    try:
        report["driverSha256"] = sha(driver)
        if args.kernel:
            report["kernelSha256"] = sha(args.kernel)
            if report["kernelSha256"] != args.kernel_sha256:
                raise RuntimeError("required kernel hash mismatch")
            with driver.open("rb") as source:
                header = source.read(20)
            if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
                raise RuntimeError("required driver must be a real LE ELF64 AArch64 program")
            ramfs = args.output.with_suffix(".initramfs.gz")
            write_initramfs(ramfs, (("init", driver),))
            command = [args.qemu, "-machine", "virt", "-cpu", "max", "-smp", "1", "-m", "128M",
                       "-nographic", "-nic", "none", "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel),
                       "-initrd", str(ramfs), "-append", "console=ttyAMA0 rdinit=/init panic=1"]
            report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=10).splitlines()[0]
        else:
            command = [str(driver)]
            report["cliSha256"] = sha(args.build_or_init / "cescan")
            report["coreSha256"] = sha(args.build_or_init / "libcecore.so")
        report["command"] = command
        result = subprocess.run(command, capture_output=True, timeout=60)
        output.extend(result.stdout + result.stderr)
        report["exitCode"] = result.returncode
        decoded = output.decode(errors="replace").replace("\r", "")
        kernel = re.search(r"CODE_WRITE_KERNEL=(\S+) pageSize=(\d+)", decoded)
        success = re.search(r"CODE_WRITE_RESULT=PASSED checks=(\d+) failures=0", decoded)
        if result.returncode or not kernel or not success or int(success[1]) != (27 if args.kernel else 40) or "FAILED:" in decoded:
            raise RuntimeError("required executable code/recovery matrix did not complete")
        if args.page_size and int(kernel[2]) != args.page_size:
            raise RuntimeError("actual guest page size does not match required profile")
        cli_count = 0
        if not args.kernel:
            with tempfile.TemporaryDirectory(prefix="code-write-", dir=args.report.parent) as directory:
                cli_count = cli_checks(args.build_or_init.resolve(), Path(directory), output)
        report.update(passed=True, kernel=kernel[1], pageSize=int(kernel[2]), checks=int(success[1]), cliChecks=cli_count)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(passed=False, error=str(error))
        if isinstance(error, subprocess.TimeoutExpired):
            output.extend((error.stdout or b"") + (error.stderr or b""))
    args.output.write_bytes(output)
    report["outputSha256"] = sha(args.output)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(output.decode(errors="replace"), end="", flush=True)
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
