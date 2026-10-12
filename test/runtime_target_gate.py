#!/usr/bin/env python3
"""Drive JIT runtimes (V8/Node, HotSpot) through the CLI, Lua and GUI frontends.

usage: runtime_target_gate.py BUILD [--node NODE] [--java JAVA] [--mono-exe EXE]
           [--dotnet-dll DLL] [--gui] [--report JSON]

The fixtures (test/runtimes/) keep a value in off-heap memory that the garbage
collector does not move, and update it from a JIT-compiled function. As a
user would, the gate finds the value by scanning for a marker and narrowing
with a next scan after a real change, and names the generated code through
the runtime's perf map (/tmp/perf-<pid>.map: V8 --perf-basic-prof, HotSpot
`jcmd <pid> Compiler.perfmap`, Mono --jitmap, CoreCLR DOTNET_PerfMapEnabled=1).
--mono-exe and --dotnet-dll take test/runtimes/JitFixture.cs built by mcs
and by the .NET SDK. It then checks writes, disassembly and
find-what-writes naming the JIT function, a Lua breakpoint in the code that
actually runs, and with --gui the Qt main and debugger windows.
"""
import argparse
import json
import os
import pathlib
import re
import select
import shutil
import tempfile
import subprocess
import sys
import time

MARKER = 1515852340   # 0x5a5a1234
HERE = pathlib.Path(__file__).resolve().parent


class Runtime:
    def __init__(self, command, cwd=None, env=None):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True, bufsize=1, cwd=cwd, env=env)
        header = self.line(timeout=120).split()
        if len(header) != 2 or header[0] != "CE_RUNTIME":
            raise RuntimeError(f"unexpected runtime header {header}")
        self.pid = int(header[1])

    def line(self, timeout=20):
        if not select.select([self.process.stdout], [], [], timeout)[0]:
            raise RuntimeError("the runtime did not answer")
        return self.process.stdout.readline().strip()

    def send(self, letter):
        self.process.stdin.write(letter)
        self.process.stdin.flush()

    def command(self, letter):
        self.send(letter)
        return int(self.line())

    def close(self):
        self.process.kill()
        self.process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--node", default=shutil.which("node"))
    parser.add_argument("--java", default=shutil.which("java"))
    parser.add_argument("--only", choices=("node", "jvm", "mono", "coreclr"), action="append",
                        help="run only these runtimes")
    parser.add_argument("--mono-exe", type=pathlib.Path, help="JitFixture.cs compiled by mcs")
    parser.add_argument("--dotnet-dll", type=pathlib.Path, help="JitFixture.cs built by the .NET SDK")
    parser.add_argument("--gui", action="store_true")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    cescan = str((args.build / "cescan").resolve())
    report = {"runtimes": [], "status": "failed"}
    failures = 0

    def run(*argv, timeout=120, expect=0):
        result = subprocess.run([cescan, *map(str, argv)], capture_output=True, text=True, timeout=timeout)
        if expect is not None and result.returncode != expect:
            raise RuntimeError(f"cescan {argv[0]} exited {result.returncode}: {result.stdout}{result.stderr}")
        return result.stdout + result.stderr

    runtimes = []
    if args.node:
        # --perf-basic-prof also writes isolate-*-v8.log into the working
        # directory; the runtimes start in a temporary directory instead.
        runtimes.append(("node", "V8 / Node", [args.node, "--perf-basic-prof", str(HERE / "runtimes/jit_fixture.js")], None))
    if args.java:
        jcmd = pathlib.Path(args.java).resolve().with_name("jcmd")
        runtimes.append(("jvm", "Java", [args.java, "-Xss1m", str(HERE / "runtimes/JitFixture.java")], jcmd))
    if args.mono_exe:
        runtimes.append(("mono", "Mono", [shutil.which("mono") or "mono", "--jitmap", str(args.mono_exe.resolve())], None))
    if args.dotnet_dll:
        runtimes.append(("coreclr", "CoreCLR (.NET)", [shutil.which("dotnet") or "dotnet", str(args.dotnet_dll.resolve())], None))
    if args.only:
        runtimes = [entry for entry in runtimes if entry[0] in args.only]
    if not runtimes:
        parser.error("no runtime is available")

    scratch = tempfile.mkdtemp(prefix="ce-runtime-gate-")
    for name, label, command, jcmd in runtimes:
        entry = {"runtime": name, "checks": {}}
        report["runtimes"].append(entry)

        def check(title, ok, detail=""):
            nonlocal failures
            entry["checks"][title] = bool(ok)
            print(f"RUNTIME_TARGET_CHECK {'OK' if ok else 'FAILED'}: {name}: {title}", flush=True)
            if not ok:
                failures += 1
                if detail:
                    print(detail[-3000:], flush=True)

        # CoreCLR runs with its default W^X double mapping (code patches go
        # through the shared mapping's backing file) and one compiled version.
        runtime = Runtime(command, cwd=scratch, env=dict(os.environ, DOTNET_PerfMapEnabled="1", DOTNET_CLI_TELEMETRY_OPTOUT="1",
                                            DOTNET_TieredCompilation="0"))
        try:
            pid = runtime.pid
            if jcmd:
                subprocess.run([str(jcmd), str(pid), "Compiler.perfmap"], capture_output=True, timeout=60, check=True)
            info = run("info", pid)
            check(f"info identifies the {label} runtime", re.search(r"^runtime:.*" + re.escape(label.split()[0]), info, re.M) is not None, info)
            listing = run("symbols", pid, "ceJitWriter")
            writers = [int(match.group(1), 16) for match in re.finditer(r"^([0-9a-f]+)\s+\d+\s+.*ceJitWriter.*\[jit\]$", listing, re.M)]
            check("the perf map names the JIT-compiled writer", bool(writers), listing[-2000:])

            first = run("scan", pid, "--type", "i32", "--value", MARKER)
            snapshot = re.search(r"^Results: (.+)$", first, re.M)
            expected = runtime.command("b")
            narrowed = run("scan", pid, "--type", "i32", "--value", expected, "--previous", snapshot.group(1)) if snapshot else ""
            found = re.findall(r"^\s*(0x[0-9a-f]+) = " + str(expected), narrowed, re.M)
            check("a first scan and a next scan after a real change isolate the off-heap value",
                  expected == MARKER + 1 and len(found) == 1, first[-1500:] + narrowed[-1500:])
            if len(found) != 1:
                continue
            value = int(found[0], 16)

            run("write", pid, hex(value), 777, "--type", "i32")
            check("a typed write reaches the managed program", runtime.command("r") == 777)

            # The runtime keeps the off-heap address in a heap object: a
            # non-static pointer scan finds such a path and it resolves.
            pointers = subprocess.run([cescan, "lua", "-e", f"""
assert(openProcess({pid}))
local found = 0
for _, path in ipairs(pointerScan({value}, 1, 256, {{staticOnly=false}}) or {{}}) do
  -- Heap paths can move with the GC between the scan and this check.
  local address = path.moduleBase + path.baseOffset
  for _, offset in ipairs(path.offsets) do
    local next = address and readPointer(address)
    address = next and next + offset
  end
  if address == {value} then found = found + 1 end
end
assert(found > 0, 'no resolving pointer path')
print('POINTER_PATHS ' .. found)
"""], capture_output=True, text=True, timeout=300)
            check("a non-static pointer scan finds a heap path to the off-heap value",
                  pointers.returncode == 0 and "POINTER_PATHS" in pointers.stdout, pointers.stdout + pointers.stderr)

            disasm = run("disasm", pid, hex(writers[-1]), 4) if writers else ""
            check("disassembly of generated code is annotated with its JIT name", "ceJitWriter" in disasm, disasm)

            watch = subprocess.Popen([cescan, "watch", str(pid), hex(value), "--duration", "4"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(2)
            written = runtime.command("b")
            output = watch.communicate(timeout=60)[0]
            # The writer may run through other compiled code (HotSpot reports
            # DirectByteBuffer.putInt); the instruction must carry a JIT name.
            writer = re.search(r"^\s*\d+ x\s+(0x[0-9a-f]+)\s.*;\s*\[jit\]!(.+)$", output, re.M)
            check("find-what-writes names the JIT-compiled code that writes",
                  written == 778 and writer is not None and (name != "node" or "ceJitWriter" in writer.group(2)), output)
            expected = 778
            if writer:
                # Diagnostics: the reported writer and the code around it.
                print(f"WRITER {name}: {writer.group(0).strip()}", flush=True)
                print(run("disasm", pid, writer.group(1), 4), flush=True)
                # A CE code-injection template at the writing instruction: the
                # stolen instructions run from a code cave, so the JIT code keeps
                # computing correctly while hooked; disable restores its bytes.
                site = writer.group(1)
                before = run("read", pid, site, 5, "--type", "aob").split(":", 1)[-1].strip()
                hook = subprocess.Popen([cescan, "lua", "-e", f"""
assert(openProcess({pid}))
local script = assert(generateCodeInjectionScript({int(site, 16)}))
local ok, disable = autoAssemble(script)
assert(ok, tostring(disable))
print('INJECTED'); io.flush()
io.read('l')
assert(autoAssemble(script, disable))
print('RESTORED'); io.flush()
"""], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                first = hook.stdout.readline() if select.select([hook.stdout], [], [], 120)[0] else ""
                injected = first.strip() == "INJECTED"
                during = run("read", pid, site, 5, "--type", "aob").split(":", 1)[-1].strip() if injected else ""
                hooked_value = runtime.command("b") if injected else None
                if injected:
                    hook.stdin.write("go\n")
                    hook.stdin.flush()
                output = first + hook.communicate(timeout=60)[0]
                after = run("read", pid, site, 5, "--type", "aob").split(":", 1)[-1].strip()
                # Count only the calls that ran, so a failed hook does not also fail later checks.
                expected += 2 if injected else 1
                check("a code-injection template hooks the JIT writer and the program still computes through the cave",
                      injected and during.upper().startswith("E9") and hooked_value == 779, output + during)
                check("disabling the injection restores the JIT code and its behavior",
                      "RESTORED" in output and after == before and runtime.command("b") == expected, output)
            if name in ("node", "jvm", "mono", "coreclr"):
                # Native calls borrow a thread that is executing user code.
                maps = open(f"/proc/{pid}/maps").read()
                libc = re.search(r"(/\S*/libc\.so\.6)$", maps, re.M)
                library = pathlib.Path(libc.group(1)).with_name("libm.so.6") if libc else None
                spinning = runtime.command("s") == 1
                calls = subprocess.run([cescan, "lua", "-e", f"""
assert(openProcess({pid}))
assert(executeCode(getAddress('sched_yield')))
local handle, err = injectLibrary('{library}')
assert(handle, tostring(err))
print('NATIVE_CALLS_OK')
"""], capture_output=True, text=True, timeout=120)
                stopped = runtime.command("x") == 0
                check("executeCode and injectLibrary run inside the managed runtime's process",
                      spinning and stopped and library is not None and calls.returncode == 0 and
                      "NATIVE_CALLS_OK" in calls.stdout and str(library) in open(f"/proc/{pid}/maps").read(),
                      calls.stdout + calls.stderr)
            # Break on the writing instruction find-what-writes reported: the
            # code that actually runs, whichever compiled version that is.
            targets = ([int(writer.group(1), 16)] if writer else []) + [w for w in writers if not writer or w != int(writer.group(1), 16)]
            plant = "".join(f"assert(debug_setBreakpoint({address}))\n" for address in targets)
            script = (f"assert(openProcess({pid}))\nlocal hit = nil\n"
                      "function debugger_onBreakpoint() hit = RIP; return 1 end\n" + plant +
                      "print('SESSION_READY'); io.flush()\n"
                      "for i = 1, 150 do debug_pumpEvents(100); if hit then break end end\n"
                      "assert(hit, 'no compiled version of the writer was hit')\n" +
                      "".join(f"debug_removeBreakpoint({address})\n" for address in targets) +
                      "print('SESSION_HIT ' .. hit); io.flush()\n")
            debugger = subprocess.Popen([cescan, "lua", "-e", script], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
            ready = select.select([debugger.stdout], [], [], 60)[0] and debugger.stdout.readline().strip() == "SESSION_READY"
            if ready:
                runtime.send("b")
            output, error = debugger.communicate(timeout=60)
            hit = re.search(r"SESSION_HIT (\d+)", output)
            check("a Lua breakpoint stops in the JIT code that actually runs and the call completes",
                  ready and hit and int(hit.group(1)) in targets and int(runtime.line()) == expected + 1, output + error)
            if args.gui and hit:
                run("write", pid, hex(value), 24681357, "--type", "i32")
                smoke = subprocess.Popen([str((args.build / "gui_lifecycle_smoke").resolve()), "--target", str(pid),
                                          hex(value), hex(int(hit.group(1)))],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                         env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
                lines = []
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    if not select.select([smoke.stdout], [], [], 1)[0]:
                        continue
                    line = smoke.stdout.readline()
                    if not line:
                        break
                    lines.append(line)
                    if line.startswith("GUI_TARGET_ARMED"):
                        runtime.send("b")
                rest = smoke.communicate(timeout=60)[0]
                output = "".join(lines) + rest
                called = int(runtime.line()) if "GUI_TARGET_ARMED" in output else None
                check("the GUI scans, edits and debugs the JIT runtime (6 window checks)",
                      smoke.returncode == 0 and "GUI_TARGET_RESULT=PASSED checks=6" in output, output)
                check("the runtime's GUI-interrupted call completes after detach", called == 13580, output)
        except Exception as error:  # report and continue with the next runtime
            check("the workflow completes", False, repr(error))
        finally:
            runtime.close()
    shutil.rmtree(scratch, ignore_errors=True)
    report["status"] = "failed" if failures else "passed"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    total = sum(len(entry["checks"]) for entry in report["runtimes"])
    print(f"RUNTIME_TARGET_RESULT={report['status'].upper()} checks={total} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
