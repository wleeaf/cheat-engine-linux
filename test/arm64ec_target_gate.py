#!/usr/bin/env python3
"""Drive a live ARM64EC program under Wine (Hangover) on an ARM64 host.

usage: arm64ec_target_gate.py BUILD FIXTURE.exe [--wine WINE] [--report JSON]

FIXTURE is test/arm64ec_fixture.c built with arm64ec-w64-mingw32-clang. The
CLI and Lua frontends must identify the program as Wine-hosted ARM64EC, write
and read its value, scan and rescan it, and resolve a static pointer path.
Code features (disassembly, injection, native calls, find-what-writes, the
debugger) must each either work or refuse with an explicit reason, and the
program must keep answering afterwards. The report records which, per
capability, for the compatibility matrix.
"""
import argparse
import json
import os
import pathlib
import re
import select
import shutil
import subprocess
import sys
import time


class Program:
    def __init__(self, wine, exe):
        env = dict(os.environ, WINEDEBUG="-all")
        self.process = subprocess.Popen([wine, str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=env)
        header = self.line(timeout=300).split()   # the first run creates the Wine prefix
        if len(header) != 4 or header[0] != "CE_ARM64EC":
            raise RuntimeError(f"unexpected fixture header {header}")
        self.value, self.pointer, self.writer = (int(field, 16) for field in header[1:])
        self.pid = self.find(exe.name)

    def find(self, name):
        # Wine runs the program in its own process; pick the one mapping the exe.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            for entry in pathlib.Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    if name in (entry / "maps").read_text(errors="replace"):
                        return int(entry.name)
                except OSError:
                    pass
            time.sleep(0.5)
        raise RuntimeError("the Wine process mapping the fixture was not found")

    def line(self, timeout=30):
        if not select.select([self.process.stdout], [], [], timeout)[0]:
            raise TimeoutError("the fixture did not answer")
        return self.process.stdout.readline().decode().strip()

    def command(self, letter):
        self.process.stdin.write(letter.encode())
        self.process.stdin.flush()
        return int(self.line())

    def stop(self):
        self.process.kill()
        self.process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("fixture", type=pathlib.Path)
    parser.add_argument("--wine", default=shutil.which("wine") or "wine")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    cescan = str((args.build / "cescan").resolve())
    report = {"target": "ARM64EC under Wine", "checks": {}, "capabilities": {}, "status": "failed"}
    failures = 0

    def check(name, ok, detail=""):
        nonlocal failures
        report["checks"][name] = bool(ok)
        print(f"ARM64EC_TARGET_CHECK {'OK' if ok else 'FAILED'}: {name}", flush=True)
        if not ok:
            failures += 1
            if detail:
                print(detail[-3000:], flush=True)

    def run(*argv, timeout=120):
        result = subprocess.run([cescan, *map(str, argv)], capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr

    def lua(code, timeout=120):
        result = subprocess.run([cescan, "lua", "-e", code], capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout + result.stderr

    def outcome(capability, worked, output, refusal):
        # Either a working operation or an explicit refusal (a line matching the
        # frontend's refusal format); anything else is a silent failure.
        reason = re.search(refusal, output, re.M)
        message = reason.group(0) if reason else output.strip()[-300:]
        state = "worked" if worked else ("refused" if reason else "silent")
        report["capabilities"][capability] = {"state": state, "message": message[:300]}
        print(f"ARM64EC_CAPABILITY {capability} {state}: {message[:300]}", flush=True)
        return state != "silent"

    program = None
    try:
        program = Program(args.wine, args.fixture.resolve())
        pid = program.pid
        code, info = run("info", pid)
        check("info identifies a Wine-hosted ARM64EC program", "ARM64EC" in info and re.search(r"wine:\s+yes", info), info)

        run("write", pid, hex(program.value), 13579, "--type", "i32")
        code, read = run("read", pid, hex(program.value), "--type", "i32")
        check("a typed write reaches the program and reads back", program.command("r") == 13579 and
              read.strip().endswith("13579"), read)

        run("write", pid, hex(program.value), 24681357, "--type", "i32")
        code, first = run("scan", pid, "--type", "i32", "--value", 24681357)
        snapshot = re.search(r"^Results: (.+)$", first, re.M)
        called = program.command("b")
        code, nxt = run("scan", pid, "--type", "i32", "--value", called, "--previous", snapshot.group(1)) if snapshot else (1, first)
        check("a first scan and a next scan after the program's own change isolate the value",
              f"{program.value:#x}" in first.lower() and f"{program.value:#x}" in nxt.lower() and called == 24681358, nxt[-1500:])

        code, pointers = lua(f"""
assert(openProcess({pid}))
local found = 0
for _, path in ipairs(pointerScan({program.value}, 1, 4096) or {{}}) do
  local address = path.moduleBase + path.baseOffset
  for _, offset in ipairs(path.offsets) do
    local next = address and readPointer(address)
    address = next and next + offset
  end
  if address == {program.value} then found = found + 1 end
end
assert(found > 0, 'no resolving static pointer path')
print('POINTER_PATHS ' .. found)
""", timeout=300)
        check("a static pointer scan resolves through the ARM64EC module", code == 0 and "POINTER_PATHS" in pointers, pointers)

        # Code features: each works or refuses explicitly.
        code, listing = run("disasm", pid, hex(program.writer), 3)
        check("disassembly works or refuses explicitly",
              outcome("C5", code == 0 and "instructions" in listing and "ARM64EC" not in listing, listing,
                      r"^.*ARM64EC code mixes .*$"))

        code, inject = lua(f"""
assert(openProcess({pid}))
local script, err = generateCodeInjectionScript({program.writer})
if not script then error(tostring(err)) end
local ok, info = autoAssemble(script)
if not ok then error(tostring(info)) end
assert(autoAssemble(script, info))
print('INJECTED_AND_RESTORED')
""")
        check("code injection works or refuses explicitly",
              outcome("C6", code == 0 and "INJECTED_AND_RESTORED" in inject, inject, r"^lua: .*injection template / hook: .+$"))

        code, calls = lua(f"""
assert(openProcess({pid}))
local result, err = executeCode({program.writer})
if not result then error(tostring(err)) end
print('NATIVE_CALL ' .. tostring(result))
""")
        check("a native call works or refuses explicitly",
              outcome("C7", code == 0 and "NATIVE_CALL" in calls, calls, r"^lua: .*create remote thread: .+$"))

        watch = subprocess.Popen([cescan, "watch", str(pid), hex(program.value), "--duration", "4"],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(2)
        program.command("b")
        output = watch.communicate(timeout=60)[0]
        writers = re.findall(r"^\s*\d+ x\s+(0x[0-9a-f]+)", output, re.M)
        check("find what writes works or refuses explicitly",
              outcome("C8", bool(writers), output, r"^watch: could not arm the watchpoint: .+$"))

        # The breakpoint session needs the program to call the writer while armed.
        debugger = subprocess.Popen([cescan, "lua", "-e", f"""
assert(openProcess({pid}))
local hit = nil
function debugger_onBreakpoint() hit = true; return 1 end
-- The second result explains why no real breakpoint could be planted.
local id, err = debug_setBreakpoint({program.writer})
if err then error('breakpoint refused: ' .. tostring(err)) end
print('SESSION_READY'); io.flush()
for i = 1, 50 do debug_pumpEvents(100); if hit then break end end
debug_removeBreakpoint({program.writer})
assert(hit, 'the writer was not hit')
print('SESSION_HIT')
"""], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        first = debugger.stdout.readline() if select.select([debugger.stdout], [], [], 60)[0] else ""
        if first.startswith("SESSION_READY"):
            program.process.stdin.write(b"b")
            program.process.stdin.flush()
        output = first + debugger.communicate(timeout=60)[0]
        if first.startswith("SESSION_READY"):
            program.line()
        check("the debugger works or refuses explicitly",
              outcome("C9", "SESSION_HIT" in output, output, r"^lua: .*breakpoint refused: .+$"))

        before = program.command("r")
        check("the program keeps running after every frontend detached", program.command("b") == before + 1)
    except Exception as error:
        check("the workflow completes", False, repr(error))
    finally:
        if program:
            program.stop()
    report["status"] = "failed" if failures else "passed"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"ARM64EC_TARGET_RESULT={report['status'].upper()} checks={len(report['checks'])} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
