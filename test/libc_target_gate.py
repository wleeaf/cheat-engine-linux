#!/usr/bin/env python3
"""Drive real libc programs through the CLI and Lua frontends.

usage: libc_target_gate.py BUILD FIXTURE [FIXTURE...] [--report JSON]

Each FIXTURE is test/static_fixture.c built as an ordinary C program: glibc or
musl, static or dynamic, x86-64 or i386. Unlike the freestanding fixtures,
these carry a real C library (inside the executable when static). Every check
goes through `cescan` exactly as a user would: info/symbols, typed write and
read, first/next scans, pointer scan, an Auto Assembler hook with disable,
find-what-writes, and a Lua debugger breakpoint session.
"""
import argparse
import json
import os
import pathlib
import re
import select
import subprocess
import sys
import tempfile
import time


class Fixture:
    def __init__(self, path):
        self.process = subprocess.Popen([str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, bufsize=1)
        header = self.line().split()
        if len(header) != 5 or header[0] != "CE_STATIC" or int(header[1]) != self.process.pid:
            raise RuntimeError(f"unexpected fixture header {header}")
        self.pid = self.process.pid
        with open(path, "rb") as elf:
            self.bits = 32 if elf.read(5)[4] == 1 else 64
        self.value, self.pointer, self.writer = (int(field, 16) for field in header[2:])

    def line(self, timeout=10):
        if not select.select([self.process.stdout], [], [], timeout)[0]:
            raise RuntimeError("fixture did not answer")
        return self.process.stdout.readline().strip()

    def command(self, letter):
        self.process.stdin.write(letter)
        self.process.stdin.flush()
        return int(self.line())

    def close(self):
        self.process.kill()
        self.process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("fixtures", type=pathlib.Path, nargs="+")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    cescan = str((args.build / "cescan").resolve())
    report = {"targets": [], "status": "failed"}
    failures = 0

    def run(*argv, timeout=60, expect=0):
        result = subprocess.run([cescan, *map(str, argv)], capture_output=True, text=True, timeout=timeout)
        if expect is not None and result.returncode != expect:
            raise RuntimeError(f"cescan {argv[0]} exited {result.returncode}: {result.stdout}{result.stderr}")
        return result.stdout + result.stderr

    for path in args.fixtures:
        path = path.resolve()
        entry = {"fixture": path.name, "checks": {}}
        report["targets"].append(entry)
        fixture = Fixture(path)

        def check(name, ok, detail=""):
            nonlocal failures
            entry["checks"][name] = bool(ok)
            print(f"LIBC_TARGET_CHECK {'OK' if ok else 'FAILED'}: {path.name}: {name}", flush=True)
            if not ok:
                failures += 1
                if detail:
                    print(detail[-3000:], flush=True)

        try:
            pid = fixture.pid
            info = run("info", pid)
            arch, abi = ("x86-32", "Linux i386") if fixture.bits == 32 else ("x86-64", "Linux x86-64")
            check(f"info identifies an {arch} Linux program", arch in info and abi in info, info)
            symbols = run("symbols", pid)
            check("the static symbol table names the writer", "ce_writer" in symbols and "ce_value" in symbols, symbols[:2000])
            modules = run("modules", pid)
            check("the executable is its own module", path.name in modules, modules)

            run("write", pid, hex(fixture.value), 7654321, "--type", "i32")
            read = run("read", pid, hex(fixture.value), "--type", "i32")
            check("typed write reaches the program and reads back", fixture.command("r") == 7654321 and "7654321" in read, read)

            first = run("scan", pid, "--type", "i32", "--value", 7654321)
            snapshot = re.search(r"^Results: (.+)$", first, re.M)
            check("a whole-process first scan finds the value", f"{fixture.value:#x}" in first.lower() and snapshot, first[-2000:])
            run("write", pid, hex(fixture.value), 7654322, "--type", "i32")
            nxt = run("scan", pid, "--type", "i32", "--value", 7654322, "--previous", snapshot.group(1)) if snapshot else ""
            check("a next scan follows the changed value", f"{fixture.value:#x}" in nxt.lower(), nxt[-2000:])

            pointers = run("pointerscan", pid, hex(fixture.value), 1, 64)
            check("a pointer scan finds the static pointer path", path.name in pointers and f"-> {fixture.value:#x}" in pointers.lower(),
                  pointers[-2000:])

            # `read --type aob` prints "ADDRESS: BYTES"; keep only the bytes.
            original = run("read", pid, "ce_writer", 5, "--type", "aob").split(":", 1)[-1].strip()
            with tempfile.TemporaryDirectory() as directory:
                script = pathlib.Path(directory) / "hook.aa"
                script.write_text(
                    # The process symbol names the hook point and the cave's
                    # preferred location, as CE scripts do for named functions.
                    "[ENABLE]\ndefine(hook,ce_writer)\nalloc(newmem,256,ce_writer)\nnewmem:\n"
                    f"mov {'ecx' if fixture.bits == 32 else 'rcx'},{fixture.value:#x}\nmov eax,#1000\n"
                    f"mov [{'ecx' if fixture.bits == 32 else 'rcx'}],eax\nret\n"
                    "hook:\njmp newmem\n"
                    f"[DISABLE]\nhook:\ndb {original}\ndealloc(newmem)\n")
                hook = subprocess.Popen([cescan, "autoasm", str(pid), str(script), "--disable-after", "3"],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                time.sleep(1.2)
                hooked = fixture.command("b")
                output = hook.communicate(timeout=30)[0]
            restored = run("read", pid, "ce_writer", 5, "--type", "aob").split(":", 1)[-1].strip()
            check("an Auto Assembler hook with a code cave changes the program's behavior", hooked == 1000, output)
            check("disabling the hook restores the original bytes and behavior",
                  restored == original and fixture.command("b") == 1001 and "Disabled" in output, output)

            watch = subprocess.Popen([cescan, "watch", str(pid), hex(fixture.value), "--duration", "3"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(1.2)
            written = fixture.command("b")
            output = watch.communicate(timeout=30)[0]
            check("find-what-writes names the writer instruction",
                  written == 1002 and re.search(r"ce_writer|" + f"{fixture.writer:x}", output.lower()) is not None, output)

            script = (f"assert(openProcess({pid}))\n"
                      "local hit = nil\n"
                      "function debugger_onBreakpoint() hit = RIP or EIP; return 1 end\n"
                      f"assert(debug_setBreakpoint({fixture.writer}))\n"
                      "print('SESSION_READY'); io.flush()\n"
                      "for i = 1, 50 do debug_pumpEvents(100); if hit then break end end\n"
                      f"assert(hit == {fixture.writer}, 'breakpoint did not stop at the writer: ' .. tostring(hit))\n"
                      f"debug_removeBreakpoint({fixture.writer})\n"
                      "debugProcess_detach = debugProcess_detach or function() end\n"
                      "print('SESSION_HIT'); io.flush()\n")
            debugger = subprocess.Popen([cescan, "lua", "-e", script], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
            ready = select.select([debugger.stdout], [], [], 10)[0] and debugger.stdout.readline().strip() == "SESSION_READY"
            if ready:
                fixture.process.stdin.write("b")
                fixture.process.stdin.flush()
            output, error = debugger.communicate(timeout=30)
            check("a Lua debugger breakpoint stops at the writer and the call completes",
                  ready and debugger.returncode == 0 and "SESSION_HIT" in output and int(fixture.line()) == 1003,
                  output + error)
            check("the program keeps running after every frontend detached", fixture.command("r") == 1003)
        except Exception as error:  # report and continue with the next fixture
            check("the workflow completes", False, repr(error))
        finally:
            fixture.close()
    report["status"] = "failed" if failures else "passed"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    total = sum(len(entry["checks"]) for entry in report["targets"])
    print(f"LIBC_TARGET_RESULT={report['status'].upper()} checks={total} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
