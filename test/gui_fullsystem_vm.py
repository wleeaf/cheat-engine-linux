#!/usr/bin/env python3
"""Run the actual ARM64 Qt debugger against real guest-kernel ptrace."""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import threading
from fullsystem_vm import write_initramfs


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def run_guest(command, timeout):
    # Surface timing markers during the run without printing screenshot payloads.
    chunks = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as guest:
        def read_output():
            for line in guest.stdout:
                chunks.append(line)
                if line.startswith(b"GUI_STAGE "):
                    print(line.decode(errors="replace").strip(), flush=True)
        reader = threading.Thread(target=read_output)
        reader.start()
        try:
            code = guest.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            guest.kill()
            guest.wait()
            reader.join()
            raise subprocess.TimeoutExpired(command, timeout, output=b"".join(chunks))
        reader.join()
        return subprocess.CompletedProcess(command, code, stdout=b"".join(chunks), stderr=b"")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=pathlib.Path)
    parser.add_argument("gui", type=pathlib.Path)
    parser.add_argument("--application", type=pathlib.Path, required=True)
    parser.add_argument("--cli", type=pathlib.Path, required=True)
    parser.add_argument("--library-dir", type=pathlib.Path, action="append", required=True)
    parser.add_argument("--plugin", type=pathlib.Path, required=True)
    parser.add_argument("--font", type=pathlib.Path, required=True)
    parser.add_argument("--readelf", default="aarch64-linux-gnu-readelf")
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    parser.add_argument("--timeout", type=int, default=480,
                        help="Guest deadline in seconds, including all standalone windows and app startup")
    parser.add_argument("--kernel-sha256", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--leader-exit", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = {"suite": "arm64-live-qt-debugger-registers", "status": "failed",
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "sourceRevision": os.environ.get("GITHUB_SHA"), "sourceRef": os.environ.get("GITHUB_REF"),
              "leaderExit": args.leader_exit}
    output = b""
    try:
        if sha256(args.kernel) != args.kernel_sha256:
            raise RuntimeError("guest kernel hash mismatch")
        files = {"init": args.gui, "cheatengine": args.application, "cescan": args.cli,
                 "qt/plugins/platforms/libqoffscreen.so": args.plugin,
                 "usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf": args.font}
        fonts = pathlib.Path("/etc/fonts/fonts.conf")
        if fonts.is_file(): files["etc/fonts/fonts.conf"] = fonts
        queue = [args.gui, args.plugin, args.application, args.cli]
        dependencies = {}
        while queue:
            binary = queue.pop()
            with binary.open("rb") as source:
                header = source.read(20)
            if header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\xb7\x00":
                raise RuntimeError(f"runtime dependency is not little-endian AArch64: {binary}")
            dynamic = subprocess.check_output([args.readelf, "-d", str(binary)], text=True, timeout=15)
            needed = re.findall(r"\(NEEDED\).*\[([^]]+)\]", dynamic)
            needed.append("ld-linux-aarch64.so.1")
            for name in needed:
                if name in dependencies:
                    continue
                candidate = next((directory / name for directory in args.library_dir if (directory / name).is_file()), None)
                if candidate is None:
                    raise RuntimeError(f"missing actual guest library: {name}, needed by {binary}")
                dependencies[name] = candidate
                files["lib/" + name] = candidate
                queue.append(candidate)
        report.update(kernelSha256=sha256(args.kernel), guiSha256=sha256(args.gui),
                      runtimeFiles={name: sha256(path) for name, path in files.items()},
                      qemu=subprocess.check_output([args.qemu, "--version"], text=True, timeout=15).splitlines()[0])
        ramfs = args.output.with_suffix(".initramfs.gz")
        write_initramfs(ramfs, files.items())
        command = [args.qemu, "-machine", "virt", "-cpu", "max", "-smp", "1", "-m", "512M",
                   "-nographic", "-nic", "none", "-monitor", "none", "-no-reboot", "-kernel", str(args.kernel),
                   "-initrd", str(ramfs), "-append", "console=ttyAMA0 rdinit=/init panic=1"]
        if args.leader_exit: command[-1]+=" CECORE_GUI_LEADER_EXIT=1"
        if args.timeout <= 0: raise RuntimeError("guest timeout must be positive")
        report["timeoutSeconds"] = args.timeout
        result = run_guest(command, args.timeout)
        output = result.stdout + result.stderr
        decoded = output.decode(errors="replace").replace("\r", "")
        report["stages"] = [{"name": name, "elapsedMs": int(elapsed)} for name, elapsed in
                            re.findall(r"^GUI_STAGE name=(\S+) elapsedMs=(\d+)$", decoded, re.MULTILINE)]
        report["exitCode"] = result.returncode
        report["checks"] = [line for line in decoded.splitlines() if line.startswith(("OK:", "FAILED:"))]
        guest = re.search(r"^GUI_KERNEL release=(\S+) machine=(\S+)$", decoded, re.MULTILINE)
        if guest: report["guestKernel"], report["guestMachine"] = guest.groups()
        screenshot = re.search(r"^CE_GUI_SCREENSHOT_PNG=([A-Za-z0-9+/=]+)$", decoded, re.MULTILINE)
        if screenshot:
            png = base64.b64decode(screenshot.group(1), validate=True)
            if not png.startswith(b"\x89PNG\r\n\x1a\n"):
                raise RuntimeError("guest screenshot is not PNG")
            image = args.output.with_suffix(".png"); image.write_bytes(png)
            report["screenshotSha256"] = sha256(image)
        application_shot = re.search(r"^CE_APPLICATION_SCREENSHOT_PNG=([A-Za-z0-9+/=]+)$", decoded, re.MULTILINE)
        if application_shot:
            png = base64.b64decode(application_shot.group(1), validate=True)
            if not png.startswith(b"\x89PNG\r\n\x1a\n"): raise RuntimeError("application screenshot is not PNG")
            image = args.output.with_suffix(".application.png"); image.write_bytes(png)
            report["applicationScreenshotSha256"] = sha256(image)
        for name in ("REGISTER_EDITOR", "STACK"):
            shot = re.search(rf"^CE_{name}_SCREENSHOT_PNG=([A-Za-z0-9+/=]+)$", decoded, re.MULTILINE)
            if not shot: raise RuntimeError(f"missing standalone {name} screenshot")
            png = base64.b64decode(shot.group(1), validate=True)
            if not png.startswith(b"\x89PNG\r\n\x1a\n"): raise RuntimeError("standalone screenshot is not PNG")
            image = args.output.with_suffix(f".{name.lower()}.png"); image.write_bytes(png)
            report[name.lower() + "ScreenshotSha256"] = sha256(image)
        if (result.returncode or "GUI_REGISTER_RESULT=PASSED architecture=ARM64\n" not in decoded or
                "FAILED:" in decoded or not screenshot or not application_shot or not guest or guest.group(2) != "aarch64"):
            raise RuntimeError("required live ARM64 Qt debugger checks failed")
        if args.leader_exit and "GUI_LEADER_EXIT_RESULT=PASSED\n" not in decoded:
            raise RuntimeError("required live ARM64 Qt leader-exit fixture failed")
        report["status"] = "passed"
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + (error.stderr or b"")
        report["error"] = "required ARM64 GUI guest timed out"
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
    finally:
        # Keep image bytes in the PNG artifact, rather than inflating text logs.
        output = re.sub(rb"CE_(GUI|APPLICATION|REGISTER_EDITOR|STACK)_SCREENSHOT_PNG=[A-Za-z0-9+/=]+\r?\n", rb"CE_\1_SCREENSHOT_PNG=[saved as PNG artifact]\n", output)
        args.output.write_bytes(output)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(output.decode(errors="replace"), end="", flush=True)
        if report["status"] != "passed":
            raise SystemExit(report.get("error", "ARM64 Qt debugger failed"))


if __name__ == "__main__":
    main()
