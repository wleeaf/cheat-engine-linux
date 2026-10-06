#!/usr/bin/env python3
"""Required real CEServer TCP memory/lifetime gate for x86-64 and i386 targets."""
import argparse
import datetime
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    report = {"suite": "real-ceserver-tcp-memory-and-lifetime", "passed": False,
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "hostArchitecture": platform.machine(), "execution": "loopback TCP",
              "scope": "Production server/client, ProcessHandle and debugger against actual x86-64/i386 Linux targets; ABI-changing exec; independent malformed-reply peers; command deadlines/cancellation; simultaneous isolated client/debug sessions; concurrent start/stop and descriptor-pressure recovery."}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    active = report
    phase = "actual targets"
    try:
        if platform.machine().lower() not in ("x86_64", "amd64"):
            raise RuntimeError("this required profile needs an x86-64 Linux host with i386 execution")
        binaries = ["ceserver_integration", "libcecore.so", "compatibility_fixture64", "compatibility_fixture32", "ceserver_connection_integration", "ceserver_multiclient_integration"]
        report["binariesSha256"] = {name: digest(build / name) for name in binaries}
        command = [str(build / name) for name in ("ceserver_integration", "compatibility_fixture64", "compatibility_fixture32")]
        report["command"] = command
        result = subprocess.run(command, capture_output=True, text=True, timeout=150)
        print(result.stdout, end="", flush=True)
        if result.stderr:
            print(result.stderr, end="", flush=True)
        report.update(exitCode=result.returncode, output=result.stdout, stderr=result.stderr)
        summary = re.search(r"CESERVER_INTEGRATION_RESULT=PASSED checks=(\d+) failures=0", result.stdout)
        if result.returncode or "FAILED:" in result.stdout or not summary:
            raise RuntimeError("required real CEServer checks failed")
        report["checks"] = int(summary.group(1))
        if report["checks"] != 143 or result.stdout.count("CESERVER_PROFILE width=8") != 1 or result.stdout.count("CESERVER_PROFILE width=4") != 1:
            raise RuntimeError("required 32/64-bit CEServer profiles were not both exercised")
        if set(re.findall(r"CESERVER_MALFORMED mode=(\d+)", result.stdout)) != {str(i) for i in range(9)}:
            raise RuntimeError("required independent malformed-reply profiles were not all exercised")
        if result.stdout.count("CESERVER_EXEC x86-64-to-i386") != 1:
            raise RuntimeError("required real remote exec transition was not exercised")
        connection_command = [str(build / "ceserver_connection_integration")]
        report["connection"] = {"command": connection_command}
        active = report["connection"]
        phase = "connection transactions"
        connection = subprocess.run(connection_command, capture_output=True, text=True, timeout=40)
        print(connection.stdout, end="", flush=True)
        if connection.stderr:
            print(connection.stderr, end="", flush=True)
        report["connection"].update(exitCode=connection.returncode, output=connection.stdout, stderr=connection.stderr)
        summary = re.search(r"CESERVER_CONNECTION_RESULT=PASSED checks=(\d+) failures=0", connection.stdout)
        if connection.returncode or "FAILED:" in connection.stdout or not summary or int(summary.group(1)) != 30:
            raise RuntimeError("required CEServer connection transaction checks failed")
        if set(re.findall(r"CESERVER_DEADLINE mode=(\d+)", connection.stdout)) != {str(i) for i in range(5)}:
            raise RuntimeError("required whole-message transport deadline profiles were not all exercised")
        report["connection"]["checks"] = 30
        multiclient_command = [str(build / name) for name in ("ceserver_multiclient_integration", "compatibility_fixture64", "compatibility_fixture32")]
        report["multiclient"] = {"command": multiclient_command}
        active = report["multiclient"]
        phase = "multi-client isolation"
        multiclient = subprocess.run(multiclient_command, capture_output=True, text=True, timeout=50)
        print(multiclient.stdout, end="", flush=True)
        if multiclient.stderr:
            print(multiclient.stderr, end="", flush=True)
        report["multiclient"].update(exitCode=multiclient.returncode, output=multiclient.stdout, stderr=multiclient.stderr)
        summary = re.search(r"CESERVER_MULTICLIENT_RESULT=PASSED checks=(\d+) failures=0", multiclient.stdout)
        if multiclient.returncode or "FAILED:" in multiclient.stdout or not summary or int(summary.group(1)) != 31:
            raise RuntimeError("required CEServer multi-client isolation checks failed")
        if set(re.findall(r"CESERVER_MULTICLIENT_BLOCKED mode=(\d+)", multiclient.stdout)) != {"0", "1"}:
            raise RuntimeError("required idle and partial-command client profiles were not both exercised")
        for marker in ("CESERVER_MULTICLIENT_LIVE x86-64+i386", "CESERVER_MULTICLIENT_LIFECYCLE", "CESERVER_MULTICLIENT_DESCRIPTOR_PRESSURE"):
            if multiclient.stdout.count(marker) != 1:
                raise RuntimeError("required CEServer multi-client runtime profile was not exercised: " + marker)
        report["multiclient"]["checks"] = 31
        report["totalChecks"] = report["checks"] + report["connection"]["checks"] + report["multiclient"]["checks"]
        report["passed"] = True
    except subprocess.TimeoutExpired as error:
        report["failedProfile"] = phase
        report["error"] = "required CEServer " + phase + " checks exceeded their timeout"
        active.update(timedOut=True, timeoutSeconds=error.timeout)
        for field, value in (("output", error.stdout), ("stderr", error.stderr)):
            if value:
                active[field] = value.decode(errors="replace") if isinstance(value, bytes) else value
        print(report["error"], flush=True)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        report["failedProfile"] = phase
        report["error"] = str(error)
        print(str(error), flush=True)
    finally:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
