#!/usr/bin/env python3
"""Drive a real console emulator (mGBA) running a generated homebrew ROM.

usage: emulator_target_gate.py BUILD [--mgba MGBA] [--gui] [--report JSON]

The ROM is assembled here from a dozen ARM7 instructions (no game data): it
stores a marker word at the start of emulated work RAM (EWRAM, 0x02000000),
runs a counter at +4, and keeps copying the word at +0 to +8. From the host,
as a user would, the gate identifies the emulator, finds EWRAM through a value
scan for the marker, writes a new value and requires the guest program's copy
at +8 to follow it, repeats the scan as a next scan, and finds a pointer path
to the EWRAM buffer. It then disassembles the guest's ARM code where the
emulator holds the ROM, finds the host instruction that stores the guest's
counter, stops there with a breakpoint and, with --gui, drives the Qt windows.
Run under a display (xvfb-run) with dummy audio, as root under Yama scope 1.
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
    parser.add_argument("--gui", action="store_true", help="also drive the Qt main and debugger windows")
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
    # stdbuf keeps mGBA's stdio line-buffered so the log tail is current on failure.
    stdbuf = ["stdbuf", "-oL", "-eL"] if shutil.which("stdbuf") else []
    emulator = subprocess.Popen([*stdbuf, args.mgba, str(rom)], cwd=directory, stdout=log, stderr=subprocess.STDOUT,
                                env=dict(os.environ, SDL_AUDIODRIVER="dummy"))
    try:
        time.sleep(4)   # let the emulator boot the ROM
        if emulator.poll() is not None:
            log.seek(0)
            raise RuntimeError(f"mGBA exited: {log.read()[-2000:]}")
        pid = emulator.pid
        info = run("info", pid)
        check("info identifies the mGBA emulator", re.search(r"^emulator:\s*mGBA", info, re.M) is not None, info)

        # A slow runner (software GL) can still be booting the ROM after the fixed
        # wait, so look for the guest's marker until it appears or 30 s pass.
        ewram = None
        deadline = time.monotonic() + 30
        while True:
            first = run("scan", pid, "--type", "i32", "--value", MARKER)
            snapshot = re.search(r"^Results: (.+)$", first, re.M)
            candidates = [int(a, 16) for a in re.findall(r"^\s*(0x[0-9a-f]+) = ", first, re.M)]
            # mGBA's rewind buffer holds many snapshots of guest RAM, refreshed as the
            # game runs. The live copy is the one the guest program itself copies
            # from: a host write at +0 shows up at +8 only there.
            copies = [a for a in candidates if read_i32(pid, a + 8) == MARKER]
            for index, address in enumerate(copies):
                probe = MARKER + 1 + index
                run("write", pid, hex(address), probe, "--type", "i32")
                time.sleep(0.3)
                if read_i32(pid, address + 8) == probe:
                    ewram = address
                    break
                run("write", pid, hex(address), MARKER, "--type", "i32")
            if ewram is not None or time.monotonic() > deadline or emulator.poll() is not None:
                break
            time.sleep(1)
        check("a host value scan finds the guest's marker in emulated work RAM", ewram is not None, first[-2000:])
        if ewram is None:
            # Tell "ROM not loaded" from "loaded but not running" from "RAM not scanned".
            title = run("scan", pid, "--type", "string", "--value", "CECOVERAGE", "--align", 1)
            threads = []
            for task in sorted(pathlib.Path(f"/proc/{pid}/task").iterdir()):
                try:
                    stat = (task / "stat").read_text()
                    comm = stat[stat.index("(") + 1:stat.rindex(")")]
                    state = stat[stat.rindex(")") + 2]
                    wchan = (task / "wchan").read_text().strip()
                    threads.append(f"{task.name} {comm} {state} {wchan}")
                except (OSError, ValueError):
                    pass
            print(f"marker candidates: {[hex(a) for a in candidates]} copies: {[hex(a) for a in copies]}\nROM title scan:\n{title[-1500:]}\n"
                  f"info:\n{info[-1500:]}\nthreads:\n" + "\n".join(threads), flush=True)
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

        # Guest code: the ROM image is host memory; disassemble it as the guest ISA.
        pattern = " ".join(f"{b:02x}" for b in CODE[:12])
        code = run("scan", pid, "--type", "aob", "--value", pattern, "--align", 1)
        sites = [int(a, 16) for a in re.findall(r"^\s*(0x[0-9a-f]+)", code, re.M)]
        listing = run("disasm", pid, hex(sites[0]), 3, "--arch", "arm32") if sites else code
        assembled = run("asm", "mov r0, #0x2000000", "--arch", "arm32")
        check("the guest's ARM code disassembles from the emulator's ROM image and reassembles",
              bool(sites) and re.search(r"mov\s+r0, #0x2000000", listing) is not None and "02 04 a0 e3" in assembled,
              code[-1000:] + listing + assembled)

        # The guest's counter store runs through the emulator's own store code:
        # find what writes reports that host instruction.
        watch = run("watch", pid, hex(ewram + 4), "--duration", 3, "--mode", "hw", timeout=60)
        writer = re.search(r"^\s*\d+ x\s+(0x[0-9a-f]+)\s", watch, re.M)
        check("find what writes reports the emulator's host store for a guest write", writer is not None, watch)
        writer = int(writer.group(1), 16) if writer else None

        if writer:
            script = (f"assert(openProcess({pid}))\nlocal hit = nil\n"
                      "function debugger_onBreakpoint() hit = RIP; return 1 end\n"
                      f"assert(debug_setBreakpoint({writer}))\n"
                      "for i = 1, 100 do debug_pumpEvents(100); if hit then break end end\n"
                      f"debug_removeBreakpoint({writer})\n"
                      "assert(hit, 'the store was not hit')\nprint('SESSION_HIT ' .. hit)\n")
            session = subprocess.run([cescan, "lua", "-e", script], capture_output=True, text=True, timeout=120)
            hit = re.search(r"SESSION_HIT (\d+)", session.stdout)
            counter = read_i32(pid, ewram + 4)
            time.sleep(0.5)
            check("a Lua breakpoint stops at that store and the emulator keeps running after detach",
                  hit is not None and int(hit.group(1)) == writer and read_i32(pid, ewram + 4) != counter,
                  session.stdout + session.stderr)

        if args.gui and writer:
            # The guest only reads +0, so the GUI scan/edit stages own that word;
            # the store breakpoint is hit by the running guest on its own.
            run("write", pid, hex(ewram), 24681357, "--type", "i32")
            smoke = subprocess.Popen([str((args.build / "gui_lifecycle_smoke").resolve()), "--target", str(pid),
                                      hex(ewram), hex(writer)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
            output = smoke.communicate(timeout=120)[0]
            counter = read_i32(pid, ewram + 4)
            time.sleep(0.5)
            check("the GUI scans, edits and debugs the emulator (6 window checks)",
                  smoke.returncode == 0 and "GUI_TARGET_RESULT=PASSED checks=6" in output, output)
            check("the emulator keeps running after the GUI detached", read_i32(pid, ewram + 4) != counter)
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
