#!/usr/bin/env python3
"""Run real libc/pthread injection, retaining hashes and complete failure output."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--require-i386", action="store_true")
    parser.add_argument("--fixture32", type=pathlib.Path)
    parser.add_argument("--library32", type=pathlib.Path)
    args = parser.parse_args()
    report = {
        "suite": "native-libc-library-and-pthread-injection", "status": "failed",
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(), "requireI386": args.require_i386,
        "sourceRevision": os.environ.get("GITHUB_SHA"), "sourceRef": os.environ.get("GITHUB_REF"),
        "targets": [],
    }
    try:
        build = args.build.resolve()
        driver = build / "native_call_integration"
        image_driver = build / "native_call_image_integration"
        exec_driver = build / "native_call_exec_integration"
        core = build / "libcecore.so"
        report["driverSha256"] = hashlib.sha256(driver.read_bytes()).hexdigest()
        report["coreSha256"] = hashlib.sha256(core.read_bytes()).hexdigest()
        report["imageDriverSha256"] = hashlib.sha256(image_driver.read_bytes()).hexdigest()
        report["execDriverSha256"] = hashlib.sha256(exec_driver.read_bytes()).hexdigest()
        targets = [(build / "native_call_fixture", build / "libnative_call_library.so")]
        fixture32 = (args.fixture32 or build / "native_call_fixture32").resolve()
        library32 = (args.library32 or build / "libnative_call_library32.so").resolve()
        if args.require_i386 or args.fixture32 or args.library32 or fixture32.exists():
            targets.append((fixture32, library32))
        for fixture, library in targets:
            header = fixture.read_bytes()[:20]
            width = {1: 4, 2: 8}.get(header[4]) if len(header) == 20 and header[:4] == b"\x7fELF" else None
            if width is None or (fixture == fixture32 and width != 4):
                raise RuntimeError(f"invalid native fixture ABI: {fixture}")
            target = {"status": "failed", "width": width,
                      "fixtureSha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                      "librarySha256": hashlib.sha256(library.read_bytes()).hexdigest()}
            report["targets"].append(target)
            result = subprocess.run([str(driver), str(fixture), str(library)],
                                    capture_output=True, text=True, timeout=40)
            target.update(exitCode=result.returncode, output=result.stdout, stderr=result.stderr,
                          checks=result.stdout.count("OK:"))
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", flush=True)
            if (result.returncode or f"NATIVE_INJECTOR_RESULT=PASSED width={width}\n" not in result.stdout or
                    f"PARKED_NATIVE_CALL_RESULT=PASSED width={width}\n" not in result.stdout or "FAILED:" in result.stdout):
                raise RuntimeError(f"required native {width * 8}-bit injection failed")
            if any(f"{marker}=PASSED width={width}\n" not in result.stdout for marker in
                   ("NATIVE_THREAD_LIFETIME_RESULT", "AUTOASM_THREAD_LIFETIME_RESULT", "LEADER_NATIVE_CALL_RESULT")):
                raise RuntimeError(f"required native {width * 8}-bit thread lifetime checks failed")
            image_fixture = (fixture.parent / "native_call_image_fixture32" if width == 4 else
                             build / "native_call_image_fixture")
            image_header = image_fixture.read_bytes()[:20]
            if (len(image_header) != 20 or image_header[:4] != b"\x7fELF" or
                    {1: 4, 2: 8}.get(image_header[4]) != width):
                raise RuntimeError(f"invalid native worker-image fixture ABI: {image_fixture}")
            image_result = subprocess.run([str(image_driver), str(image_fixture)],
                                          capture_output=True, text=True, timeout=40)
            target["workerImage"] = {
                "fixtureSha256": hashlib.sha256(image_fixture.read_bytes()).hexdigest(),
                "exitCode": image_result.returncode, "output": image_result.stdout,
                "stderr": image_result.stderr, "checks": image_result.stdout.count("OK:"),
            }
            print(image_result.stdout, end="", flush=True)
            print(image_result.stderr, end="", flush=True)
            if (image_result.returncode or "FAILED:" in image_result.stdout or
                    f"NATIVE_CALL_IMAGE_RESULT=PASSED width={width}\n" not in image_result.stdout):
                raise RuntimeError(f"required native {width * 8}-bit worker image recovery failed")
            exec_result = subprocess.run([str(exec_driver), str(image_fixture)],
                                         capture_output=True, text=True, timeout=40)
            target["calleeExec"] = {
                "exitCode": exec_result.returncode, "output": exec_result.stdout,
                "stderr": exec_result.stderr, "checks": exec_result.stdout.count("OK:"),
            }
            print(exec_result.stdout, end="", flush=True)
            print(exec_result.stderr, end="", flush=True)
            if (exec_result.returncode or "FAILED:" in exec_result.stdout or
                    f"NATIVE_CALL_EXEC_RESULT=PASSED width={width} checks=475 failures=0\n" not in exec_result.stdout):
                raise RuntimeError(f"required native {width * 8}-bit callee exec retirement failed")
            target["status"] = "passed"
        report["status"] = "passed"
    except subprocess.TimeoutExpired as error:
        report["error"] = "required native injection timed out"
        report["output"] = (error.stdout or b"").decode(errors="replace")
        report["stderr"] = (error.stderr or b"").decode(errors="replace")
        raise SystemExit(report["error"]) from error
    except (OSError, RuntimeError) as error:
        report["error"] = str(error)
        raise SystemExit(str(error)) from error
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
