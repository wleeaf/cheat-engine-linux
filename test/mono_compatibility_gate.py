#!/usr/bin/env python3
"""Require real Mono metadata, JIT, refresh, GC and application-exit evidence."""
import argparse
import errno
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import socket
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def stage_installed_file(source, target):
    # CMake's library name is a symlink. Linking that symlink itself creates a
    # dangling installed entry, which exists() misses on the next invocation.
    source = source.resolve(strict=True)
    target.unlink(missing_ok=True)
    try:
        os.link(source, target)
    except OSError as error:
        if error.errno != errno.EXDEV:
            raise
        shutil.copy2(source, target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    parser.add_argument("--mono", default=shutil.which("mono"))
    parser.add_argument("--compiler", default=shutil.which("mcs"))
    parser.add_argument("--embedded", action="store_true",
                        help="Require the private-loader embedding profile and locate its installed runtime")
    parser.add_argument("--embedded-library", type=Path,
                        help="Run a real privately dlopened Mono runtime instead of mono-sgen")
    parser.add_argument("--embedded-runtime-prefix", type=Path, default=Path("/"))
    parser.add_argument("--container")
    parser.add_argument("--container-runtime", help="Extracted runtime prefix inside an existing container")
    parser.add_argument("--container-source", default="/src")
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    work = (args.work_dir or build / ".mono-compat").resolve()
    work.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {"suite": "real-mono-runtime-and-lifecycle", "passed": False,
              "utc": datetime.now(timezone.utc).isoformat(), "sourceRevision": os.environ.get("GITHUB_SHA"),
              "sourceRef": os.environ.get("GITHUB_REF"), "container": args.container, "phases": [],
              "execution": "embedded-local" if args.embedded or args.embedded_library else "standalone"}
    fixture = None
    namespace_pid = 0
    error_log = work / "fixture-stderr.log"
    try:
        if not args.mono or not args.compiler:
            raise RuntimeError("Mono and its C# compiler are required; this gate cannot skip")
        if args.embedded and not args.embedded_library:
            prefix = args.embedded_runtime_prefix.resolve()
            directories = [prefix / "usr/lib", prefix / "usr/lib64", prefix / "lib", prefix / "lib64"]
            directories += sorted((prefix / "usr/lib").glob("*-linux-gnu"))
            with Path("/proc/self/exe").open("rb") as executable:
                native = executable.read(20)
            for directory in directories:
                for candidate in sorted(directory.glob("libmonosgen-2.0.so.*")):
                    if not candidate.is_file():
                        continue
                    with candidate.open("rb") as library:
                        header = library.read(20)
                    if len(header) == 20 and header[:6] == native[:6] and header[18:20] == native[18:20]:
                        args.embedded_library = candidate
                        break
                if args.embedded_library:
                    break
            if not args.embedded_library:
                raise RuntimeError("the embedded gate requires a native Mono shared runtime; use --embedded-library")
        for name in ("mono_integration", "libmono_fixture_control.so", "libcecore_mono_agent.so",
                     "libmono_limit_agent.so", "cescan"):
            report.setdefault("binariesSha256", {})[name] = sha(build / name)
        report["binariesSha256"]["libcecore.so"] = sha(build / "libcecore.so")
        if args.embedded_library:
            report["binariesSha256"]["mono_embed_fixture"] = sha(build / "mono_embed_fixture")
            report["embeddedLibrarySha256"] = sha(args.embedded_library)
        installed = work / "installed"
        installed_bin = installed / "bin"
        installed_lib = installed / "engine-libraries"
        installed_bin.mkdir(parents=True, exist_ok=True)
        installed_lib.mkdir(parents=True, exist_ok=True)
        # Stage the CLI away from the build tree and ordinary ../lib paths.
        # Hard links keep the low-memory gate from duplicating large binaries.
        for source, target in ((build / "cescan", installed_bin / "cescan"),
                               (build / "libcecore.so", installed_lib / "libcecore.so.0"),
                               (build / "libcecore_mono_agent.so", installed_lib / "libcecore_mono_agent.so")):
            stage_installed_file(source, target)
        report["mono"] = subprocess.check_output([args.mono, "--version"], text=True, timeout=10).strip()
        report["monoSha256"] = sha(Path(args.mono))
        compiler = [args.mono, args.compiler] if args.compiler.endswith(".exe") else [args.compiler]
        for source, output, extra in (("mono_fixture.cs", "fixture.exe", []),
                                      ("mono_late_fixture.cs", "late.dll", ["-target:library"])):
            subprocess.run([*compiler, *extra, f"-out:{work / output}", str(ROOT / "test" / source)],
                           check=True, capture_output=True, timeout=20)
            report.setdefault("fixturesSha256", {})[output] = sha(work / output)

        def inside(path):
            return args.container_source.rstrip("/") + "/" + str(path.relative_to(ROOT))

        env = dict(os.environ, LD_LIBRARY_PATH=str(build) + ":" + os.environ.get("LD_LIBRARY_PATH", ""))
        if args.container:
            if not args.container_runtime:
                raise RuntimeError("the container's extracted Mono runtime prefix is required")
            runtime = args.container_runtime.rstrip("/")
            target = ([inside(build / "mono_embed_fixture"), f"{runtime}/usr/lib/libmonosgen-2.0.so.1.0.0",
                       inside(work / "fixture.exe"), inside(work / "late.dll"),
                       f"{runtime}/usr/lib", f"{runtime}/etc"] if args.embedded_library else
                      [f"{runtime}/usr/bin/mono-sgen", inside(work / "fixture.exe"), inside(work / "late.dll")])
            command = ["podman", "exec", "-i", args.container, "env", f"MONO_PATH={runtime}/usr/lib/mono/4.5",
                       f"MONO_CFG_DIR={runtime}/etc", f"LD_LIBRARY_PATH={inside(build)}", "nice", "-n", "10",
                       *target]
        elif args.embedded_library:
            prefix = args.embedded_runtime_prefix.resolve()
            command = [str(build / "mono_embed_fixture"), str(args.embedded_library.resolve()),
                       str(work / "fixture.exe"), str(work / "late.dll"), str(prefix / "usr/lib"), str(prefix / "etc")]
        else:
            command = [args.mono, str(work / "fixture.exe"), str(work / "late.dll")]
        report["fixtureCommand"] = command
        with error_log.open("w") as errors:
            fixture = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=errors, text=True, env=env)
        output_buffer = bytearray()

        def line():
            with selectors.DefaultSelector() as selector:
                selector.register(fixture.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 8
                # TextIOWrapper.readline may prefetch the next marker. Polling
                # the FD again would then wait despite a complete buffered line.
                while b"\n" not in output_buffer:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(timeout=remaining):
                        raise RuntimeError("the actual Mono application stopped making progress")
                    packet = os.read(fixture.stdout.fileno(), 4096)
                    if not packet:
                        raise RuntimeError("the Mono fixture exited before completing its protocol")
                    output_buffer.extend(packet)
                    if len(output_buffer) > 65536:
                        raise RuntimeError("the Mono fixture marker exceeded its protocol bound")
                end = output_buffer.index(b"\n")
                value = output_buffer[:end].decode("utf-8", errors="replace").strip()
                del output_buffer[:end + 1]
                if not value:
                    raise RuntimeError("the Mono fixture exited before completing its protocol")
                return value

        def fixture_pid(inner_pid):
            if not args.container:
                if fixture.pid != inner_pid:
                    raise RuntimeError("the native fixture reported the wrong PID")
                return fixture.pid
            top = subprocess.check_output(["podman", "top", args.container, "hpid", "pid", "args"],
                                          text=True, timeout=10)
            matches = [row.split(None, 2) for row in top.splitlines()[1:]
                       if len(row.split(None, 2)) == 3 and row.split(None, 2)[1] == str(inner_pid)]
            if len(matches) != 1:
                raise RuntimeError("cannot identify the actual namespace fixture host PID")
            pid = int(matches[0][0])
            if pid == inner_pid:
                raise RuntimeError("the declared PID namespace did not change the fixture PID")
            return pid

        def after_cleanup(agent, label):
            for marker, phase, key in (("MONO_CLEANED_READY", "shutdown_mapped", label + "Mapped"),
                                       ("MONO_SHUTDOWN_READY", "shutdown", label)):
                ready = line()
                parts = ready.split()
                if len(parts) != 3 or parts[0] != marker or int(parts[1]) != namespace_pid:
                    raise RuntimeError(f"the embedded fixture did not finish actual Mono cleanup: {ready}")
                driver_command = [str(build / "mono_integration"), str(fixture_pid(namespace_pid)),
                                  str(agent), phase, parts[2], "0", "0", "0", "0", "release"]
                result = subprocess.run(driver_command, capture_output=True, text=True, timeout=20)
                print(result.stdout, end="", flush=True)
                report[key] = {"ready": ready, "command": driver_command,
                               "exitCode": result.returncode, "output": result.stdout, "stderr": result.stderr}
                if (result.returncode or "FAILED:" in result.stdout or
                        f"MONO_INTEGRATION_RESULT=PASSED phase={phase} checks=9 failures=0" not in result.stdout):
                    raise RuntimeError("post-cleanup runtime requests did not preserve the native application")
                report[key]["checks"] = 9
            if line() != "MONO_EMBED_EXIT":
                raise RuntimeError("the original native application did not finish normally after Mono cleanup")

        for phase, next_command in (("initial", "collect"), ("collected", "load"), ("loaded", "exit")):
            ready = line()
            print(ready, flush=True)
            parts = ready.split()
            if len(parts) != 10 or parts[0] != "MONO_READY" or parts[2] != "8" or parts[6] != "37":
                raise RuntimeError(f"invalid real Mono ready marker: {ready}")
            inner_pid = int(parts[1])
            namespace_pid = inner_pid
            pid = fixture_pid(inner_pid)
            if phase == "collected":
                if int(parts[5]) <= report["phases"][0]["collections"]:
                    raise RuntimeError("the target did not perform actual managed garbage collection")
                if parts[4] != report["phases"][0]["pinnedData"]:
                    raise RuntimeError("the runtime's pinned object changed address during collection")
            if phase == "initial":
                script = work / "cli.lua"
                script.write_text(f"assert(openProcess({pid}))\nlocal d=monoDissect(3000)\n"
                                  "assert(d and d.ready and d.error=='', d and d.error or 'Mono dissection unavailable')\n"
                                  "assert(monoDissect(3000).ready)\n"
                                  f"assert(findMonoFunction('Compatibility','Player','Compute',1)=={int(parts[7],16)})\n"
                                  "print('MONO_CLI_LUA_RESULT=PASSED')\n")
                cli_env = dict(os.environ, LD_LIBRARY_PATH=str(installed_lib))
                cli = subprocess.run([str(installed_bin / "cescan"), "lua", str(script)],
                                     capture_output=True, text=True, timeout=15, env=cli_env)
                report["cli"] = {"exitCode": cli.returncode, "output": cli.stdout, "stderr": cli.stderr,
                                 "stagedExecutable": str(installed_bin / "cescan"),
                                 "engineLibraryDirectory": str(installed_lib)}
                if cli.returncode or "MONO_CLI_LUA_RESULT=PASSED" not in cli.stdout:
                    raise RuntimeError("production CLI/Lua Mono operations failed")
                endpoint = f"/proc/{pid}/root/tmp/cecore_mono_{inner_pid}/agent.sock"
                with socket.socket(socket.AF_UNIX) as peer:
                    peer.settimeout(2)
                    peer.connect(endpoint)
                    peer.sendall(b"C")  # Disconnect in the middle of a header.
                rejected = []
                for name, header in (("magic", (0, 1, 0, 0, 0, 0)),
                                     ("command", (0x43454D31, 99, 0, 0, 0, 0)),
                                     ("length", (0x43454D31, 2, 1048577, 0, 0, 0)),
                                     ("negativeParameterCount", (0x43454D31, 2, 0, 0, 0, 0xFFFFFFFE))):
                    with socket.socket(socket.AF_UNIX) as peer:
                        peer.settimeout(2)
                        peer.connect(endpoint)
                        peer.sendall(struct.pack("!6I", *header))
                        received = b""
                        while len(received) < 32:
                            packet = peer.recv(32 - len(received))
                            if not packet:
                                raise RuntimeError("the agent dropped its invalid-request reply")
                            received += packet
                        magic, status, length = struct.unpack("!3I", received[:12])
                        if (magic, status, length) != (0x43454D31, 1, 20) or received[12:] != b"Invalid Mono request":
                            raise RuntimeError(f"the agent did not reject its malformed {name}")
                    rejected.append(name)
                report["rejectedHeaders"] = rejected
                report["partialDisconnectAndMalformedHeader"] = "passed"
            fixture.stdin.write(next_command + "\n")
            fixture.stdin.flush()
            driver_command = [str(build / "mono_integration"), str(pid), str(build / "libcecore_mono_agent.so"),
                              phase, *parts[3:5], *parts[7:10], "release"]
            result = subprocess.run(driver_command, capture_output=True, text=True, timeout=20)
            print(result.stdout, end="", flush=True)
            profile = {"phase": phase, "ready": ready, "collections": int(parts[5]), "pinnedData": parts[4],
                       "hostPid": pid, "namespacePid": inner_pid, "command": driver_command,
                       "exitCode": result.returncode, "output": result.stdout, "stderr": result.stderr}
            report["phases"].append(profile)
            marker = re.search(r"^MONO_INTEGRATION_RESULT=PASSED phase=(\w+) checks=(\d+) failures=0$",
                               result.stdout, re.MULTILINE)
            expected = 21 if phase == "loaded" else 20
            if result.returncode or "FAILED:" in result.stdout or not marker or marker[1] != phase or int(marker[2]) != expected:
                raise RuntimeError(f"required Mono {phase} integration checks failed")
            profile["checks"] = expected
        final = line()
        if final != "MONO_EXIT 123":
            raise RuntimeError("the managed application did not restore its object and finish normally")
        if args.embedded_library:
            after_cleanup(build / "libcecore_mono_agent.so", "afterCleanup")
        fixture.wait(timeout=5)
        report["fixtureExitCode"] = fixture.returncode
        if fixture.returncode:
            raise RuntimeError("the target did not exit normally with the agent resident")
        report["normalExit"] = final
        report["checks"] = sum(p["checks"] for p in report["phases"])

        # Use the same real runtime with a 1 KiB test-only response cap to
        # verify overflow/recovery without generating a large assembly.
        namespace_pid = 0
        output_buffer.clear()
        bounded_log = work / "bounded-fixture-stderr.log"
        with bounded_log.open("w") as errors:
            fixture = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=errors, text=True, env=env)
        ready = line()
        parts = ready.split()
        if len(parts) != 10 or parts[0] != "MONO_READY" or parts[2] != "8" or parts[6] != "37":
            raise RuntimeError(f"invalid real Mono overflow ready marker: {ready}")
        namespace_pid = int(parts[1])
        pid = fixture_pid(namespace_pid)
        fixture.stdin.write("exit\n")
        fixture.stdin.flush()
        driver_command = [str(build / "mono_integration"), str(pid), str(build / "libmono_limit_agent.so"),
                          "limited", *parts[3:5], *parts[7:10], "release"]
        result = subprocess.run(driver_command, capture_output=True, text=True, timeout=20)
        print(result.stdout, end="", flush=True)
        report["boundedMetadata"] = {"ready": ready, "hostPid": pid, "namespacePid": namespace_pid,
                                     "responseLimit": 1024, "command": driver_command,
                                     "exitCode": result.returncode, "output": result.stdout, "stderr": result.stderr}
        if (result.returncode or "FAILED:" in result.stdout or
                "MONO_INTEGRATION_RESULT=PASSED phase=limited checks=9 failures=0" not in result.stdout):
            raise RuntimeError("required real Mono metadata overflow/recovery checks failed")
        if line() != "MONO_EXIT 123":
            raise RuntimeError("the overflow fixture did not restore its object and finish normally")
        if args.embedded_library:
            after_cleanup(build / "libmono_limit_agent.so", "boundedAfterCleanup")
        fixture.wait(timeout=5)
        if fixture.returncode:
            raise RuntimeError("the overflow fixture did not exit normally")
        report["boundedMetadata"].update(checks=9, fixtureExitCode=fixture.returncode,
                                          fixtureStderr=bounded_log.read_text())
        if args.embedded_library:
            for log in (error_log, bounded_log):
                text = log.read_text()
                for marker in ("MONO_EMBED_LOCAL_EXPORTS=hidden", "MONO_EMBED_LOCAL_EXPORTS_AFTER_REQUESTS=hidden",
                               "MONO_EMBED_AFTER_CLEANUP_SHUTTING_DOWN=1", "MONO_EMBED_RUNTIME_AFTER_OWNER_CLOSE=unloaded"):
                    if marker not in text.splitlines():
                        raise RuntimeError(f"the real embedded runtime did not prove its scope/cleanup marker: {marker}")
        report["totalChecks"] = report["checks"] + 9 + (36 if args.embedded_library else 0)
        report["passed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(str(error), flush=True)
    finally:
        if fixture and fixture.poll() is None:
            if args.container and namespace_pid:
                subprocess.run(["podman", "exec", args.container, "kill", "-KILL",
                                str(namespace_pid)], timeout=10, capture_output=True)
            fixture.kill()
            fixture.wait(timeout=5)
        if error_log.exists():
            report["fixtureStderr"] = error_log.read_text()
        bounded_log = work / "bounded-fixture-stderr.log"
        if bounded_log.exists():
            report["boundedFixtureStderr"] = bounded_log.read_text()
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
