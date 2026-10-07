#!/usr/bin/env python3
"""Require both native x86 syscall ABIs and publish operation evidence."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = {
        "suite": "native-x86-memory-syscalls-debugger-trace-codefinder-and-recovery", "status": "failed",
        "platform": platform.platform(),
        "sourceRevision": os.environ.get("GITHUB_SHA"),
        "sourceRef": os.environ.get("GITHUB_REF"),
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targets": [],
    }
    try:
        driver = (args.build / "target_syscall_integration").resolve()
        report["driverSha256"] = hashlib.sha256(driver.read_bytes()).hexdigest()
        for bits in (64, 32):
            fixture = (args.build / f"compatibility_fixture{bits}").resolve()
            target = {"bits": bits, "status": "failed", "fixtureSha256": hashlib.sha256(fixture.read_bytes()).hexdigest()}
            report["targets"].append(target)
            try:
                result = subprocess.run([str(driver), str(fixture)], capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired as error:
                target["output"] = (error.stdout or b"").decode(errors="replace")
                target["stderr"] = (error.stderr or b"").decode(errors="replace")
                raise RuntimeError(f"required native {bits}-bit syscall integration timed out") from error
            target.update(exitCode=result.returncode, output=result.stdout, stderr=result.stderr)
            print(result.stdout, end="", flush=True)
            if result.stderr:
                print(result.stderr, end="", flush=True)
            expected = ("SYSCALL_TARGET architecture=x86-64 abi=Linux x86-64 width=8" if bits == 64 else
                        "SYSCALL_TARGET architecture=x86-32 abi=Linux i386 width=4")
            debug_marker = "DEBUG_BACKEND_RESULT=PASSED architecture=" + ("x86-64" if bits == 64 else "x86-32")
            session_marker = "DEBUG_SESSION_RESULT=PASSED architecture=" + ("x86-64" if bits == 64 else "x86-32")
            trace_marker = "TRACE_BACKEND_RESULT=PASSED architecture=" + ("x86-64" if bits == 64 else "x86-32")
            architecture = "x86-64" if bits == 64 else "x86-32"
            finder_markers = [f"{name}=PASSED architecture={architecture}\n" for name in (
                "CODEFINDER_BACKEND_RESULT", "CODEFINDER_TEARDOWN_RESULT", "STOPPED_SYSCALL_RESULT", "SOFTWARE_CODEFINDER_RESULT", "CODEFINDER_SIGNAL_RESULT",
                "SHARED_SYSCALL_RESULT", "SYSCALL_POLICY_RESULT", "PREFLIGHT_RECOVERY_RESULT", "STOPPED_FUNCTION_RESULT", "NATIVE_CALL_OWNER_RESULT")]
            boundary = re.findall(r'^RETURN_BOUNDARY_RESULT=.*$', result.stdout, re.M)
            boundary_checks = re.findall(r'^RETURN_BOUNDARY_CHECK (OK|FAILED):', result.stdout, re.M)
            restart = re.findall(r'^RESTART_BOUNDARY_RESULT=.*$', result.stdout, re.M)
            restart_checks = re.findall(r'^RESTART_BOUNDARY_CHECK (OK|FAILED):', result.stdout, re.M)
            mixed = re.findall(r'^MIXED_ABI_RESTART_RESULT=.*$', result.stdout, re.M)
            mixed_checks = re.findall(r'^MIXED_ABI_RESTART_CHECK (OK|FAILED):', result.stdout, re.M)
            mixed_count = 298 if bits == 64 else 24
            preentry = re.findall(r'^RESTART_PREENTRY_STOP actualStop=19 queuedCode=-1 leftWait=1$', result.stderr, re.M)
            target["checks"] = result.stdout.count("OK:")
            if (result.returncode or expected not in result.stdout or debug_marker not in result.stdout or
                    session_marker not in result.stdout or trace_marker not in result.stdout or
                    any(marker not in result.stdout for marker in finder_markers) or
                    boundary != [f'RETURN_BOUNDARY_RESULT=PASSED architecture={architecture} checks=26'] or
                    len(boundary_checks) != 26 or any(value != 'OK' for value in boundary_checks) or
                    restart != [f'RESTART_BOUNDARY_RESULT=PASSED architecture={architecture} checks=50'] or
                    len(restart_checks) != 50 or any(value != 'OK' for value in restart_checks) or
                    mixed != [f'MIXED_ABI_RESTART_RESULT=PASSED architecture={architecture} checks={mixed_count}'] or
                    len(mixed_checks) != mixed_count or any(value != 'OK' for value in mixed_checks) or
                    len(preentry) != (4 if bits == 64 else 0) or
                    "SYSCALL_DISPATCH_RESULT=PASSED\n" not in result.stdout or
                    "LEADER_EXIT_RESULT=PASSED\n" not in result.stdout or
                    "SESSION_THREAD_EXIT_RESULT=PASSED\n" not in result.stdout or
                    "DEBUG_RECOVERY_RESULT=PASSED\n" not in result.stdout or "FAILED:" in result.stdout or
                    "0 failed target syscall checks\n" not in result.stdout):
                raise RuntimeError(f"required native {bits}-bit syscall integration failed")
            thread_death = {"status": "failed"}
            target["serviceThreadDeath"] = thread_death
            try:
                observed = subprocess.run([str(driver), "--service-thread-death-only", str(fixture)],
                                          capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired as error:
                thread_death["output"] = (error.stdout or b"").decode(errors="replace")
                thread_death["stderr"] = (error.stderr or b"").decode(errors="replace")
                raise RuntimeError(f"required native {bits}-bit service thread-death integration timed out") from error
            thread_death.update(exitCode=observed.returncode, output=observed.stdout, stderr=observed.stderr)
            print(observed.stdout, end="", flush=True)
            if observed.stderr:
                print(observed.stderr, end="", flush=True)
            results = re.findall(r'^SERVICE_THREAD_DEATH_RESULT=.*$', observed.stdout, re.M)
            assertions = re.findall(r'^SERVICE_THREAD_DEATH_CHECK (OK|FAILED):', observed.stdout, re.M)
            events = re.findall(r'^SERVICE_REAL_EXIT tid=\d+ owner=\d+ context=1 flag=1 allocation=[0-9a-f]+ mapped=1 terminal=1 leftWait=1$', observed.stderr, re.M)
            phases = re.findall(r'^SERVICE_THREAD_DEATH_OBSERVATION architecture=\S+ phase=(\S+) allocation=[0-9a-f]+ absent=1 context=1$', observed.stdout, re.M)
            thread_death["checks"] = len(assertions)
            if (observed.returncode or results != [f'SERVICE_THREAD_DEATH_RESULT=PASSED architecture={architecture} checks=38'] or
                    len(assertions) != 38 or any(value != 'OK' for value in assertions) or 'FAILED:' in observed.stdout or
                    len(events) != 3 or phases != ['after-record', 'before-record', 'shutdown']):
                raise RuntimeError(f"required native {bits}-bit service thread-death integration failed")
            thread_death["status"] = "passed"
            if bits == 64:
                lifecycle = {"status": "failed"}
                target["mixedAbiLifecycle"] = lifecycle
                try:
                    observed = subprocess.run([str(driver), "--mixed-abi-lifecycle-only", str(fixture)],
                                              capture_output=True, text=True, timeout=60)
                except subprocess.TimeoutExpired as error:
                    lifecycle["output"] = (error.stdout or b"").decode(errors="replace")
                    lifecycle["stderr"] = (error.stderr or b"").decode(errors="replace")
                    raise RuntimeError("required mixed-ABI lifecycle integration timed out") from error
                lifecycle.update(exitCode=observed.returncode, output=observed.stdout, stderr=observed.stderr)
                print(observed.stdout, end="", flush=True)
                if observed.stderr:
                    print(observed.stderr, end="", flush=True)
                results = re.findall(r'^MIXED_ABI_LIFECYCLE_RESULT=.*$', observed.stdout, re.M)
                assertions = re.findall(r'^MIXED_ABI_LIFECYCLE_CHECK (OK|FAILED):', observed.stdout, re.M)
                lifecycle["checks"] = len(assertions)
                if (observed.returncode or results != [
                        'MIXED_ABI_LIFECYCLE_RESULT=PASSED architecture=x86-64 action=death checks=218',
                        'MIXED_ABI_LIFECYCLE_RESULT=PASSED architecture=x86-64 action=exec checks=182'] or
                        len(assertions) != 400 or any(value != 'OK' for value in assertions) or 'FAILED:' in observed.stdout or
                        len(re.findall(r'^RESTART_PREENTRY_STOP actualStop=19 queuedCode=-1 leftWait=1$', observed.stderr, re.M)) != 3):
                    raise RuntimeError("required mixed-ABI lifecycle integration failed")
                lifecycle["status"] = "passed"
                shared_fixture = (args.build / "shared_mm_fixture").resolve()
                shared = {"status": "failed", "fixtureSha256": hashlib.sha256(shared_fixture.read_bytes()).hexdigest()}
                target["mixedAbiSharedExec"] = shared
                try:
                    observed = subprocess.run([str(driver), "--mixed-abi-shared-exec-only", str(shared_fixture)],
                                              capture_output=True, text=True, timeout=60)
                except subprocess.TimeoutExpired as error:
                    shared["output"] = (error.stdout or b"").decode(errors="replace")
                    shared["stderr"] = (error.stderr or b"").decode(errors="replace")
                    raise RuntimeError("required mixed-ABI shared-mm exec integration timed out") from error
                shared.update(exitCode=observed.returncode, output=observed.stdout, stderr=observed.stderr)
                print(observed.stdout, end="", flush=True)
                if observed.stderr:
                    print(observed.stderr, end="", flush=True)
                results = re.findall(r'^MIXED_ABI_LIFECYCLE_RESULT=.*$', observed.stdout, re.M)
                assertions = re.findall(r'^MIXED_ABI_LIFECYCLE_CHECK (OK|FAILED):', observed.stdout, re.M)
                shared["checks"] = len(assertions)
                if (observed.returncode or results != [
                        'MIXED_ABI_LIFECYCLE_RESULT=PASSED architecture=x86-64 action=shared-exec checks=252',
                        'MIXED_ABI_LIFECYCLE_RESULT=PASSED architecture=x86-64 action=identical-shared-exec checks=36'] or
                        len(assertions) != 288 or any(value != 'OK' for value in assertions) or 'FAILED:' in observed.stdout):
                    raise RuntimeError("required mixed-ABI shared-mm exec integration failed")
                shared["status"] = "passed"
                shared_death = {"status": "failed"}
                target["mixedAbiSharedDeath"] = shared_death
                try:
                    observed = subprocess.run([str(driver), "--mixed-abi-shared-death-only", str(shared_fixture)],
                                              capture_output=True, text=True, timeout=60)
                except subprocess.TimeoutExpired as error:
                    shared_death["output"] = (error.stdout or b"").decode(errors="replace")
                    shared_death["stderr"] = (error.stderr or b"").decode(errors="replace")
                    raise RuntimeError("required mixed-ABI shared-mm death integration timed out") from error
                shared_death.update(exitCode=observed.returncode, output=observed.stdout, stderr=observed.stderr)
                print(observed.stdout, end="", flush=True)
                if observed.stderr:
                    print(observed.stderr, end="", flush=True)
                results = re.findall(r'^MIXED_ABI_LIFECYCLE_RESULT=.*$', observed.stdout, re.M)
                assertions = re.findall(r'^MIXED_ABI_LIFECYCLE_CHECK (OK|FAILED):', observed.stdout, re.M)
                shared_death["checks"] = len(assertions)
                if (observed.returncode or results != [
                        'MIXED_ABI_LIFECYCLE_RESULT=PASSED architecture=x86-64 action=shared-death checks=322',
                        'MIXED_ABI_LIFECYCLE_RESULT=PASSED architecture=x86-64 action=shared-death-probe checks=47'] or
                        len(assertions) != 369 or any(value != 'OK' for value in assertions) or 'FAILED:' in observed.stdout or
                        len(re.findall(r'^RESTART_PREENTRY_STOP actualStop=19 queuedCode=-1 leftWait=1$', observed.stderr, re.M)) != 3):
                    raise RuntimeError("required mixed-ABI shared-mm death integration failed")
                shared_death["status"] = "passed"
                guard = {"status": "failed"}
                target["completedImageGuard"] = guard
                try:
                    observed = subprocess.run([str(driver), "--completed-image-guard-only", str(shared_fixture)],
                                              capture_output=True, text=True, timeout=60)
                except subprocess.TimeoutExpired as error:
                    guard["output"] = (error.stdout or b"").decode(errors="replace")
                    guard["stderr"] = (error.stderr or b"").decode(errors="replace")
                    raise RuntimeError("required completed-image guard integration timed out") from error
                guard.update(exitCode=observed.returncode, output=observed.stdout, stderr=observed.stderr)
                print(observed.stdout, end="", flush=True)
                if observed.stderr:
                    print(observed.stderr, end="", flush=True)
                results = re.findall(r'^COMPLETED_IMAGE_GUARD_RESULT=.*$', observed.stdout, re.M)
                assertions = re.findall(r'^COMPLETED_IMAGE_GUARD_CHECK (OK|FAILED):', observed.stdout, re.M)
                guard["checks"] = len(assertions)
                if (observed.returncode or results != ['COMPLETED_IMAGE_GUARD_RESULT=PASSED architecture=x86-64 checks=57'] or
                        len(assertions) != 57 or any(value != 'OK' for value in assertions) or 'FAILED:' in observed.stdout):
                    raise RuntimeError("required completed-image guard integration failed")
                guard["status"] = "passed"
            target["status"] = "passed"
        report["status"] = "passed"
    except (OSError, RuntimeError) as error:
        report["error"] = str(error)
        raise SystemExit(str(error)) from error
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
