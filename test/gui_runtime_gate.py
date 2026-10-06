#!/usr/bin/env python3
"""Require live Qt debugger, application startup and CLI/Lua frontend checks."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path, required=True)
    parser.add_argument("--leader-exit", action="store_true")
    args = parser.parse_args()
    build = args.build.resolve()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    screenshot = args.report.with_suffix(".png").resolve()
    report = {"suite": "native-live-qt-debugger-cli-lua", "status": "failed",
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "platform": platform.platform(),
              "sourceRevision": os.environ.get("GITHUB_SHA"), "sourceRef": os.environ.get("GITHUB_REF"),
              "leaderExit": args.leader_exit}
    output = ""
    try:
        binaries = {name: build / name for name in ("gui_register_smoke", "cheatengine", "cescan", "libcecore.so")}
        hashes = {}
        for name, binary in binaries.items():
            with binary.open("rb") as source:
                hashes[name] = hashlib.file_digest(source, "sha256").hexdigest()
        report["binarySha256"] = hashes
        environment = dict(os.environ, QT_QPA_PLATFORM="offscreen", CECORE_GUI_SCREENSHOT=str(screenshot),
                           CECORE_GUI_APPLICATION=str(binaries["cheatengine"]), CECORE_GUI_CLI=str(binaries["cescan"]),
                           CECORE_GUI_LEADER_EXIT="1" if args.leader_exit else "0")
        result = subprocess.run([str(binaries["gui_register_smoke"])], env=environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=100)
        output = result.stdout
        report["exitCode"] = result.returncode
        report["checks"] = [line for line in output.splitlines() if line.startswith(("OK:", "FAILED:"))]
        if result.returncode or "GUI_REGISTER_RESULT=PASSED architecture=" not in output or "FAILED:" in output:
            raise RuntimeError("required live frontend checks failed")
        if args.leader_exit and "GUI_LEADER_EXIT_RESULT=PASSED\n" not in output:
            raise RuntimeError("required live frontend leader-exit fixture failed")
        application_shot = pathlib.Path(str(binaries["cheatengine"]) + ".smoke.png")
        if not screenshot.is_file() or not application_shot.is_file():
            raise RuntimeError("required frontend screenshots are missing")
        shutil.copyfile(application_shot, args.report.with_suffix(".application.png"))
        for name in ("register-editor", "stack"):
            shot = pathlib.Path(str(screenshot) + f".{name}.png")
            if not shot.is_file(): raise RuntimeError(f"missing standalone {name} screenshot")
            shutil.copyfile(shot, args.report.with_suffix(f".{name}.png"))
        report["status"] = "passed"
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"").decode(errors="replace") if isinstance(error.stdout, bytes) else error.stdout or ""
        report["error"] = "required live frontend checks timed out"
    except (OSError, RuntimeError) as error:
        report["error"] = str(error)
    finally:
        args.report.with_suffix(".log").write_text(output)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(output, end="", flush=True)
        if report["status"] != "passed":
            raise SystemExit(report.get("error", "required frontend checks failed"))


if __name__ == "__main__":
    main()
