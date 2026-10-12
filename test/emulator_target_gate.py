#!/usr/bin/env python3
"""Drive a real console emulator (mGBA) running a generated homebrew ROM.

usage: emulator_target_gate.py BUILD [--mgba MGBA] [--report JSON]

The ROM is assembled here from a dozen ARM7 instructions (no game data): it
stores a marker word at the start of emulated work RAM (EWRAM, 0x02000000),
runs a counter at +4, and keeps copying the word at +0 to +8. From the host,
as a user would, the gate identifies the emulator, finds EWRAM through a value
scan for the marker, writes a new value and requires the guest program's copy
at +8 to follow it, repeats the scan as a next scan, and finds a pointer path
to the EWRAM buffer. Run under a display (xvfb-run) with dummy audio.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

MARKER = 0x5A5A1234
CODE = bytes.fromhex(
    "020 4a0e3 5a14a0e3 5a1881e3 121c81e3 341081e3 001080e5"   # mov r0,#EWRAM; build marker; str
    " 0020a0e3 012082e2 042080e5 003090e5 083080e5 faffffea"    # loop: count, copy +0 to +8, b loop
    .replace(" ", ""))


def build_rom(path):
    rom = bytearray(0x200)
    rom[0:4] = bytes.fromhex("2e0000ea")          # b 0x080000c0
    rom[0xA0:0xAC] = b"CECOVERAGE  "               # title
    rom[0xAC:0xB0] = b"CECV"                       # game code
    rom[0xB2] = 0x96                               # fixed value
    rom[0xBD] = (-(sum(rom[0xA0:0xBD]) + 0x19)) & 0xFF   # header complement check
    rom[0xC0:0xC0 + len(CODE)] = CODE
    path.write_bytes(bytes(rom))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--mgba", default=shutil.which("mgba") or shutil.which("mgba-sdl") or "/usr/games/mgba")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    cescan = str((args.build / "cescan").resolve())
    report = {"emulator": "mGBA", "checks": {}, "status": "failed"}
    failures = 0

    def check(name, ok, detail=""):
        nonlocal failures
        report["checks"][name] = bool(ok)
        print(f"EMULATOR_TARGET_CHECK {'OK' if ok else 'FAILED'}: {name}", flush=True)
        if not ok:
            failures += 1
            if detail:
                print(detail[-3000:], flush=True)

    def run(*argv, timeout=120):
        result = subprocess.run([cescan, *map(str, argv)], capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr

    def read_i32(pid, address):
        match = re.search(r"(-?\d+)\s*$", run("read", pid, hex(address), "--type", "i32").strip())
        return int(match.group(1)) if match else None

    directory = pathlib.Path(tempfile.mkdtemp(prefix="ce-emulator-"))
    rom = directory / "coverage.gba"
    build_rom(rom)
    # mGBA logs heavily; an undrained pipe would block it before the ROM runs.
    log = open(directory / "mgba.log", "w+")
    emulator = subprocess.Popen([args.mgba, str(rom)], cwd=directory, stdout=log, stderr=subprocess.STDOUT,
                                env=dict(os.environ, SDL_AUDIODRIVER="dummy"))
    try:
        time.sleep(4)   # let the emulator boot the ROM
        if emulator.poll() is not None:
            log.seek(0)
            raise RuntimeError(f"mGBA exited: {log.read()[-2000:]}")
        pid = emulator.pid
        info = run("info", pid)
        check("info identifies the mGBA emulator", re.search(r"^emulator:\s*mGBA", info, re.M) is not None, info)

        first = run("scan", pid, "--type", "i32", "--value", MARKER)
        snapshot = re.search(r"^Results: (.+)$", first, re.M)
        candidates = [int(a, 16) for a in re.findall(r"^\s*(0x[0-9a-f]+) = ", first, re.M)]
        ewram = next((a for a in candidates if read_i32(pid, a + 8) == MARKER), None)
        check("a host value scan finds the guest's marker in emulated work RAM", ewram is not None, first[-2000:])
        if ewram is None:
            raise RuntimeError("EWRAM not found")
        print(f"EWRAM backing at {ewram:#x}", flush=True)

        counter = read_i32(pid, ewram + 4)
        time.sleep(0.5)
        check("the guest program is running (its counter advances)", read_i32(pid, ewram + 4) != counter)

        run("write", pid, hex(ewram), 305419896, "--type", "i32")
        time.sleep(0.5)
        check("a host write to guest RAM is observed by the guest program", read_i32(pid, ewram + 8) == 305419896)

        nxt = run("scan", pid, "--type", "i32", "--value", 305419896, "--previous", snapshot.group(1)) if snapshot else ""
        check("a next scan follows the changed guest value", f"{ewram:#x}" in nxt.lower(), nxt[-2000:])

        pointers = subprocess.run([cescan, "lua", "-e", f"""
assert(openProcess({pid}))
local found = 0
for _, path in ipairs(pointerScan({ewram}, 1, 4096, {{staticOnly=false}}) or {{}}) do
  local address = path.moduleBase + path.baseOffset
  for _, offset in ipairs(path.offsets) do
    local next = address and readPointer(address)
    address = next and next + offset
  end
  if address == {ewram} then found = found + 1 end
end
assert(found > 0, 'no resolving pointer path to guest RAM')
print('POINTER_PATHS ' .. found)
"""], capture_output=True, text=True, timeout=300)
        check("a pointer scan finds a host path to the guest RAM buffer",
              pointers.returncode == 0 and "POINTER_PATHS" in pointers.stdout, pointers.stdout + pointers.stderr)
    except Exception as error:
        log.seek(0)
        check("the workflow completes", False, repr(error) + "\nmGBA log tail:\n" + log.read()[-2000:])
    finally:
        emulator.kill()
        emulator.wait()
        log.close()
        shutil.rmtree(directory, ignore_errors=True)
    report["status"] = "failed" if failures else "passed"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"EMULATOR_TARGET_RESULT={report['status'].upper()} checks={len(report['checks'])} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
