#!/usr/bin/env python3
"""Verify host-side pthread ownership for a fixture in an existing PID namespace."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import select
import shlex
import signal
import subprocess
import time


def line(stream):
    deadline = time.monotonic() + 5
    data = bytearray()
    while len(data) < 4096:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise RuntimeError("namespace fixture handshake timed out")
        byte = os.read(stream.fileno(), 1)
        if byte == b"\n":
            return data.decode()
        if not byte:
            raise RuntimeError("namespace fixture exited before its handshake")
        data.extend(byte)
    raise RuntimeError("invalid namespace fixture handshake")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--container", required=True)
    parser.add_argument("--fixture", required=True, help="native fixture path inside the existing container")
    parser.add_argument("--collision-library", type=pathlib.Path,
                        help="absolute path with different libraries on host and in target namespace")
    parser.add_argument("--remove-target-library", action="store_true",
                        help="unlink the generated target fixture library after its execution checks")
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.collision_library and not args.collision_library.is_absolute():
        parser.error("the colliding library path must be absolute")
    if args.remove_target_library and not args.collision_library:
        parser.error("--remove-target-library requires --collision-library")
    report = {"suite": "host-owner-native-pthread-pid-namespace", "status": "failed",
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "container": args.container, "sourceRevision": os.environ.get("GITHUB_SHA"),
              "sourceRef": os.environ.get("GITHUB_REF")}
    fixture = None
    pidfd = None
    deleted_shadow = None
    try:
        init_pid = int(subprocess.check_output(
            ["podman", "inspect", "--format", "{{.State.Pid}}", args.container], text=True, timeout=10))
        namespace = os.readlink(f"/proc/{init_pid}/ns/pid")
        preload = ""
        if args.collision_library:
            preload = "LD_PRELOAD=" + shlex.quote(str(args.collision_library)) + " "
        fixture = subprocess.Popen(
            ["podman", "exec", "-i", args.container, "sh", "-c",
             "echo CE_NAMESPACE_PID $$; exec env " + preload + shlex.quote(args.fixture)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        published = line(fixture.stdout).split()
        if len(published) != 2 or published[0] != "CE_NAMESPACE_PID":
            raise RuntimeError(f"invalid namespace PID handshake: {published}")
        inner_pid = int(published[1])
        ready = line(fixture.stdout).split()
        if len(ready) < 8 or ready[0] != "CE_NATIVE_CALL":
            raise RuntimeError(f"invalid namespace fixture handshake: {ready}")
        target = None
        for candidate in pathlib.Path("/proc").iterdir():
            if not candidate.name.isdecimal():
                continue
            try:
                if os.readlink(candidate / "ns/pid") != namespace:
                    continue
                status = (candidate / "status").read_text(errors="replace")
                chain = next([int(value) for value in row.split()[1:]]
                             for row in status.splitlines() if row.startswith("NSpid:"))
                if chain[-1] == inner_pid:
                    target = int(candidate.name)
                    report["namespacePidChain"] = chain
                    break
            except (OSError, StopIteration):
                continue
        if target is None or len(report["namespacePidChain"]) < 2 or target == inner_pid:
            raise RuntimeError("fixture is not in a distinct, visible PID namespace")
        pidfd = os.pidfd_open(target)
        build = args.build.resolve()
        report.update(targetPid=target, targetWidth=int(ready[1]),
                      fixtureSha256=hashlib.sha256(pathlib.Path(f"/proc/{target}/exe").read_bytes()).hexdigest(),
                      driverSha256=hashlib.sha256((build / "native_call_integration").read_bytes()).hexdigest(),
                      coreSha256=hashlib.sha256((build / "libcecore.so").read_bytes()).hexdigest())
        result = subprocess.run([str(build / "native_call_integration"), "--namespace-probe",
                                 str(target), str(int(ready[7], 16))],
                                capture_output=True, text=True, timeout=10)
        report.update(exitCode=result.returncode, output=result.stdout, stderr=result.stderr)
        print(result.stdout, end="", flush=True)
        if result.returncode or f"NATIVE_THREAD_NAMESPACE_RESULT=PASSED pid={target} " not in result.stdout:
            raise RuntimeError("required host-owner namespaced pthread execution failed")
        if args.collision_library:
            actual = pathlib.Path(f"/proc/{target}/root") / str(args.collision_library).lstrip("/")
            report["collision"] = {"path": str(args.collision_library),
                "hostSha256": hashlib.sha256(args.collision_library.read_bytes()).hexdigest(),
                "targetSha256": hashlib.sha256(actual.read_bytes()).hexdigest()}
            result = subprocess.run([str(build / "native_call_integration"), "--namespace-symbol-probe",
                                     str(target), str(args.collision_library)],
                                    capture_output=True, text=True, timeout=10)
            report["collision"].update(exitCode=result.returncode, output=result.stdout, stderr=result.stderr)
            print(result.stdout, end="", flush=True)
            if result.returncode or f"NATIVE_MODULE_NAMESPACE_RESULT=PASSED pid={target}\n" not in result.stdout:
                raise RuntimeError("required target-module collision checks failed")
            if args.remove_target_library:
                marker = int(next(row.split("=", 1)[1] for row in result.stdout.splitlines()
                                  if row.startswith("NATIVE_NAMESPACE_MARKER=")))
                shadow = pathlib.Path(str(args.collision_library) + " (deleted)")
                if shadow.exists():
                    raise RuntimeError(f"refusing to replace an existing deleted-name shadow: {shadow}")
                # This host-only ELF has the exact name emitted for the unlinked mapping.
                with shadow.open("xb") as output:
                    output.write(args.collision_library.read_bytes())
                deleted_shadow = shadow
                subprocess.run(["podman", "exec", args.container, "rm", "--", str(args.collision_library)],
                               check=True, timeout=5)
                result = subprocess.run([str(build / "native_call_integration"), "--namespace-deleted-probe",
                                         str(target), str(shadow), str(marker)],
                                        capture_output=True, text=True, timeout=10)
                report["deletedModule"] = {"exitCode": result.returncode, "output": result.stdout,
                                           "stderr": result.stderr}
                print(result.stdout, end="", flush=True)
                if result.returncode or f"DELETED_MODULE_NAMESPACE_RESULT=PASSED pid={target}\n" not in result.stdout:
                    raise RuntimeError("required deleted-module namespace checks failed")
        fixture.stdin.write(b"x")
        fixture.stdin.flush()
        finished = line(fixture.stdout)
        exit_code = fixture.wait(timeout=5)
        report.update(fixtureCompletion=finished, fixtureExitCode=exit_code)
        if finished != "CE_NATIVE_CALL_DONE" or exit_code:
            raise RuntimeError("namespaced application did not resume normal console work")
        report["status"] = "passed"
    except (OSError, ValueError, StopIteration, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        raise SystemExit(str(error)) from error
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        if fixture is not None and fixture.poll() is None:
            try:
                fixture.stdin.write(b"x")
                fixture.stdin.flush()
                fixture.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                fixture.terminate()
                try:
                    fixture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    fixture.kill()
                    fixture.wait(timeout=5)
        if pidfd is not None:
            os.close(pidfd)
        if deleted_shadow is not None:
            deleted_shadow.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
