#!/usr/bin/env python3
"""Boot the ISA guest driver (test/isa_vm_integration.cpp) and require its checks.

usage: isa_vm_gate.py KERNEL INIT FIXTURE --qemu QEMU --expect-architecture NAME
           [--frontend CESCAN [--frontend-sysroot DIR]] --output LOG --report JSON

The guest is a real full-system Linux kernel of the target instruction set;
the static driver runs as /init with the static libc fixture next to it.
With --frontend, a dynamically linked `cescan` for the guest and the shared
libraries it needs (found under the sysroot, `/` by default) are added, and
the driver also drives the fixture through the CLI and Lua frontends.
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from fullsystem_vm import write_initramfs  # noqa: E402

# Machine type and kernel console for each full-system emulator.
MACHINES = {"qemu-system-riscv64": ("virt", "ttyS0"),
            "qemu-system-s390x": ("s390-ccw-virtio", "ttysclp0"),
            "qemu-system-ppc64": ("pseries", "hvc0"),
            "qemu-system-arm": ("virt", "ttyAMA0"),
            "qemu-system-x86_64": ("pc", "ttyS0")}
# Extra arguments: pseries otherwise wants a VGA BIOS the headless run lacks.
EXTRA = {"qemu-system-ppc64": ["-vga", "none"]}


def shared_libraries(binary, sysroot):
    """The ELF interpreter and every DT_NEEDED library, resolved under sysroot
    (or the binary's RUNPATH, kept at the same absolute path in the guest)."""
    def readelf(*options, path):
        return subprocess.check_output(["readelf", "-W", *options, str(path)], text=True, timeout=30)

    def kind(path):
        header = readelf("-h", path=path)
        return re.findall(r"^\s*(?:Class|Data|Machine):\s*(.+)$", header, re.M)

    wanted = kind(binary)
    interpreter = re.search(r"Requesting program interpreter: (\S+)\]", readelf("-l", path=binary))
    found, pending = {}, [binary.resolve()]
    if interpreter:
        # Cross sysroots (/usr/<triplet>) keep every loader in lib/.
        loader = sysroot / interpreter.group(1).lstrip("/")
        if not loader.exists():
            loader = sysroot / "lib" / pathlib.PurePosixPath(interpreter.group(1)).name
        found[interpreter.group(1)] = loader.resolve()
    system = sorted({"/lib", "/usr/lib", "/lib64", "/usr/lib64"} |
                    {"/" + str(d.relative_to(sysroot)) for pattern in
                     ("lib/*-linux-gnu*", "usr/lib/*-linux-gnu*", "libx32", "usr/libx32") for d in sysroot.glob(pattern)})
    while pending:
        current = pending.pop()
        dynamic = readelf("-d", path=current)
        runpath = [entry.replace("$ORIGIN", str(current.parent)) for match in
                   re.findall(r"\((?:RUNPATH|RPATH)\)\s+Library r(?:un)?path: \[(.+?)\]", dynamic)
                   for entry in match.split(":")]
        for name in re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", dynamic):
            if any(pathlib.PurePosixPath(guest).name == name for guest in found):
                continue
            candidates = [(f"{d}/{name}", pathlib.Path(d) / name) for d in runpath] + \
                         [(f"{d}/{name}", sysroot / d.lstrip("/") / name) for d in system]
            for guest, candidate in candidates:
                if candidate.exists() and kind(candidate.resolve()) == wanted:
                    found[guest] = candidate.resolve()
                    pending.append(candidate.resolve())
                    break
            else:
                raise RuntimeError(f"shared library {name} for {current} not found under {sysroot}")
    return [(guest.lstrip("/"), path) for guest, path in found.items()]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=pathlib.Path)
    parser.add_argument("init", type=pathlib.Path)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--expect-architecture", required=True)
    parser.add_argument("--kernel-args", default="", help="extra kernel parameters (x32: syscall.x32=y)")
    parser.add_argument("--frontend", type=pathlib.Path, help="a dynamically linked cescan for the guest")
    parser.add_argument("--frontend-sysroot", type=pathlib.Path, default=pathlib.Path("/"))
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = {"status": "failed", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "kernelSha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
              "initSha256": hashlib.sha256(args.init.read_bytes()).hexdigest()}
    try:
        report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=15).splitlines()[0]
        ramfs = args.output.with_suffix(".initramfs.gz")
        files = [("init", args.init), ("fixture", args.fixture)]
        if args.frontend:
            files += [("cescan", args.frontend), *shared_libraries(args.frontend, args.frontend_sysroot)]
            report["frontendFiles"] = [name for name, _ in files[2:]]
        write_initramfs(ramfs, files)
        machine, console = MACHINES[pathlib.Path(args.qemu).name]
        command = [args.qemu, "-machine", machine, "-smp", "1", "-m", "512M", "-nographic", "-nic", "none",
                   "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel), "-initrd", str(ramfs),
                   "-append", f"console={console} rdinit=/init panic=1 {args.kernel_args}".strip(),
                   *EXTRA.get(pathlib.Path(args.qemu).name, [])]
        # Emulated full-system boots are slow on hosted runners; bound generously.
        result = subprocess.run(command, capture_output=True, timeout=900)
        output = (result.stdout + result.stderr).decode(errors="replace").replace("\r", "")
        args.output.write_text(output)
        report["exitCode"] = result.returncode
        kernel = re.search(r"^ISA_VM_KERNEL release=(\S+) machine=(\S+)$", output, re.M)
        if kernel:
            report["guestKernel"], report["guestMachine"] = kernel.groups()
        report["checks"] = re.findall(r"^ISA_VM_CHECK (OK|FAILED): (.+)$", output, re.M)
        print("\n".join(line for line in output.splitlines() if line.startswith("ISA_VM")), flush=True)
        expected = f"ISA_VM_RESULT=PASSED architecture={args.expect_architecture} checks={len(report['checks'])}"
        frontends = sum(1 for _, name in report["checks"] if "cescan" in name)
        if args.frontend and frontends < 4:
            raise RuntimeError("the guest did not run the CLI and Lua frontend checks")
        if expected not in output or "ISA_VM_CHECK FAILED" in output or len(report["checks"]) < 9:
            raise RuntimeError(f"required {args.expect_architecture} guest checks failed")
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
