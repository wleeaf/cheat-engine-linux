#!/usr/bin/env python3
"""The AI Assistant's keyring client (gui/secret_store.cpp) on a private D-Bus
session, never the user's: first with no keyring (the key lasts for the run),
then against test/secret_service_mock.py, a keyring that starts locked and
unlocks through a prompt.

Usage: test/secret_store_gate.py <build-dir> [--report file.json]
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

BUS_CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=@DIR@</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build")
    parser.add_argument("--report")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside:
        # A fresh session bus for this test alone, with no service activation:
        # the default configuration could start the real keyring daemon, which
        # would open the user's own keyring.
        with tempfile.TemporaryDirectory(prefix="ce-bus-") as work:
            config = pathlib.Path(work) / "session.conf"
            config.write_text(BUS_CONFIG.replace("@DIR@", work))
            command = ["dbus-run-session", f"--config-file={config}", "--", sys.executable, __file__, args.build, "--inside"]
            if args.report:
                command += ["--report", args.report]
            return subprocess.run(command).returncode

    if "ce-bus-" not in os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""):
        print("refusing to run outside the private test bus")
        return 2
    build = pathlib.Path(args.build).resolve()
    here = pathlib.Path(__file__).resolve().parent
    results = []

    def check(name, ok, detail=""):
        results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})
        print(f"SECRET_STORE_CHECK {'OK' if ok else 'FAILED'}: {name}" + ("" if ok else f" ({detail})"), flush=True)

    def run(*arguments):
        return subprocess.run([str(build / "secret_store_test"), *arguments], capture_output=True, text=True,
                              timeout=60).stdout.strip()

    out = run("available")
    check("no keyring on a fresh bus", out == "AVAILABLE 0", out)
    out = run("memory", "sk-run-only")
    check("without a keyring the key lasts for the run", out == "FOUND sk-run-only persisted=0", out)

    with tempfile.TemporaryDirectory(prefix="ce-secrets-") as work:
        state_file = pathlib.Path(work) / "state.json"
        mock = subprocess.Popen([sys.executable, str(here / "secret_service_mock.py"), str(state_file)])
        try:
            deadline = time.time() + 20
            while run("available") != "AVAILABLE 1" and time.time() < deadline:
                time.sleep(0.2)
            check("the mock keyring answers", run("available") == "AVAILABLE 1")
            state = lambda: json.loads(state_file.read_text())
            out = run("store", "sk-first")
            check("store unlocks the keyring through its prompt and saves",
                  out.startswith("STORED ok=1 persisted=1") and state()["prompts"] == 1 and len(state()["items"]) == 1, (out, state()))
            item = state()["items"][0]
            check("the item is labelled and tagged for Cheat Engine",
                  item["attributes"] == {"application": "cheat-engine-linux", "account": "test-account"} and "Cheat Engine" in item["label"], item)
            out = run("lookup")
            check("a new run reads the key back from the keyring", out == "FOUND sk-first", out)
            out = run("store", "sk-second")
            check("storing again replaces the key", out.startswith("STORED ok=1") and len(state()["items"]) == 1
                  and state()["items"][0]["secret"] == "sk-second", state())
            out = run("lookup")
            check("the replaced key is read back", out == "FOUND sk-second", out)
            out = run("remove")
            check("remove deletes it", out.startswith("REMOVED ok=1") and not state()["items"], (out, state()))
            out = run("lookup")
            check("nothing is found after remove", out.startswith("NONE"), out)
        finally:
            mock.terminate()
            mock.wait(timeout=10)

    failed = [r for r in results if not r["ok"]]
    print(f"SECRET_STORE_RESULT={'FAILED' if failed else 'PASSED'} checks={len(results)} failed={len(failed)}")
    if args.report:
        pathlib.Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.report).write_text(json.dumps({"checks": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
