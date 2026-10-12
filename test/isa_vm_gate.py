#!/usr/bin/env python3
"""Boot the ISA guest driver (test/isa_vm_integration.cpp) and require its checks.

usage: isa_vm_gate.py KERNEL INIT FIXTURE --qemu QEMU --expect-architecture NAME
           --output LOG --report JSON

The guest is a real full-system Linux kernel of the target instruction set;
the static driver runs as /init with the static libc fixture next to it.
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
            "qemu-system-ppc64": ("pseries", "hvc0")}
# Extra arguments: pseries otherwise wants a VGA BIOS the headless run lacks.
EXTRA = {"qemu-system-ppc64": ["-vga", "none"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=pathlib.Path)
    parser.add_argument("init", type=pathlib.Path)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--expect-architecture", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = {"status": "failed", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "kernelSha256": hashlib.sha256(args.kernel.read_bytes()).hexdigest(),
              "initSha256": hashlib.sha256(args.init.read_bytes()).hexdigest()}
    try:
        report["qemu"] = subprocess.check_output([args.qemu, "--version"], text=True, timeout=15).splitlines()[0]
        ramfs = args.output.with_suffix(".initramfs.gz")
        write_initramfs(ramfs, (("init", args.init), ("fixture", args.fixture)))
        machine, console = MACHINES[pathlib.Path(args.qemu).name]
        command = [args.qemu, "-machine", machine, "-smp", "1", "-m", "512M", "-nographic", "-nic", "none",
                   "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel), "-initrd", str(ramfs),
                   "-append", f"console={console} rdinit=/init panic=1", *EXTRA.get(pathlib.Path(args.qemu).name, [])]
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
