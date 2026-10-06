#!/usr/bin/env python3
"""Require GUI injection cleanup against live x86-64 and i386 processes."""
import argparse
import datetime
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    report = {"suite": "gui-live-injection-lifecycle", "passed": False,
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "platform": platform.platform(), "output": "", "runs": []}
    try:
        binaries = [build / name for name in
                    ("gui_lifecycle_smoke", "compatibility_fixture64", "compatibility_fixture32")]
        report["binarySha256"] = {}
        for binary in [*binaries, build / "libcecore.so"]:
            with binary.open("rb") as source:
                report["binarySha256"][binary.name] = hashlib.file_digest(source, "sha256").hexdigest()
        for mode, prefix, count in (("--injection-lifecycle-only", "GUI_INJECTION", 78),
                                    ("--editor-injection-only", "GUI_EDITOR_INJECTION", 77)):
            command = [str(binaries[0]), mode, *map(str, binaries[1:])]
            run = {"command": command, "profile": prefix}
            report["runs"].append(run)
            result = subprocess.run(command, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=50)
            run.update(exitCode=result.returncode, output=result.stdout)
            report["output"] += result.stdout
            profiles = re.findall(rf"^{prefix}_RESULT width=(\d+) checks=(\d+) failures=(\d+)$", result.stdout, re.M)
            if result.returncode or profiles != [("8", str(count), "0"), ("4", str(count), "0")]:
                raise RuntimeError("Required " + prefix + " profiles failed or are incomplete")
            for width in (8, 4):
                checks = re.findall(rf"^{prefix} {width} (OK|FAILED):", result.stdout, re.M)
                if len(checks) != count or any(check != "OK" for check in checks):
                    raise RuntimeError("Incomplete or failed target assertions in " + prefix)
            run["checks"] = count * 2
        report.update(passed=True, targetWidths=[8, 4], checks=310)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        if report["runs"]:
            report["runs"][-1].update(output=output, timedOut=True)
        report["output"] += output
        report.update(timedOut=True, failure="Required live GUI injection checks exceeded their deadline")
    except (OSError, RuntimeError) as error:
        report["failure"] = str(error)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print("GUI_INJECTION_GATE=" + ("PASSED" if report["passed"] else "FAILED"))
    if not report["passed"]:
        print(report.get("failure", "Unknown failure"))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
