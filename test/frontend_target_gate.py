#!/usr/bin/env python3
"""Drive real programs through the CLI, Lua and (optionally) GUI frontends.

usage: frontend_target_gate.py BUILD FIXTURE [FIXTURE...]
           [--launcher CMD | --wine-launcher CMD] [--gui] [--report JSON]

Every check goes through the user-facing frontends: `cescan` info/modules,
typed write and read, first/next scans, pointer scan, an Auto Assembler hook
with a code cave and disable, find-what-writes, a `cescan lua` debugger
breakpoint session, and with --gui the Qt main and debugger windows
(`gui_lifecycle_smoke --target`).

Two fixture kinds share that flow:

* libc programs (test/static_fixture.c): glibc or musl, static or dynamic,
  x86-64 or i386. `--launcher` runs each inside a sandbox (bubblewrap,
  `flatpak run`, Podman); the program then reports its namespaced PID and the
  gate operates on the host PID of that process, as a user picking it from
  the host's process list would.
* Windows PE programs (test/wine_fixture.py) under `--wine-launcher` (`wine`,
  or a Proton launcher script). Their native-call frontends must refuse with
  the explicit Wine reason, since Wine-safe loader calls have no backend.
"""
import argparse
import json
import os
import pathlib
import re
import select
import shlex
import struct
import subprocess
import sys
import tempfile
import time


def start_time(pid):
    stat = open(f"/proc/{pid}/stat").read()
    return int(stat[stat.rfind(")") + 2:].split()[19])


def parent(pid):
    return int(re.search(r"^PPid:\s+(\d+)", open(f"/proc/{pid}/status").read(), re.M).group(1))


def descends(pid, ancestor):
    for _ in range(64):
        if pid == ancestor:
            return True
        try:
            pid = parent(pid)
        except (OSError, AttributeError):
            return False
        if pid <= 1:
            return False
    return False


def host_pid(launcher_pid, matches):
    """The launcher's descendant accepted by `matches(pid)`.

    Container engines (Podman's conmon) and Wine reparent the workload away
    from the launcher; then accept the single match started after it.
    """
    launched = start_time(launcher_pid)
    for _ in range(200):
        later = []
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                if not matches(pid):
                    continue
                if descends(pid, launcher_pid):
                    return pid
                if start_time(pid) >= launched:
                    later.append(pid)
            except OSError:
                continue
        if len(later) == 1:
            return later[0]
        time.sleep(0.05)
    raise RuntimeError("the launched program has no identifiable host process")


class Fixture:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)

    def receive(self, count, timeout=15):
        data = b""
        deadline = time.monotonic() + timeout
        while len(data) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise RuntimeError("the program did not answer")
            chunk = os.read(self.process.stdout.fileno(), count - len(data))
            if not chunk:
                raise RuntimeError("the program closed its output")
            data += chunk
        return data

    def line(self, timeout=60):
        text = b""
        while not text.endswith(b"\n"):
            text += self.receive(1, timeout)
        return text.decode().strip()

    def send(self, letter):
        self.process.stdin.write(letter.encode())
        self.process.stdin.flush()

    def command(self, letter):
        self.send(letter)
        return self.reply()

    def close(self):
        self.process.kill()
        self.process.wait()


class LibcFixture(Fixture):
    windows = False

    def __init__(self, path, launcher):
        super().__init__([*launcher, str(path)])
        header = self.line().split()
        # An optional sixth field names the writer's symbol (Go: main.ce_writer).
        if len(header) not in (5, 6) or header[0] != "CE_STATIC" or (not launcher and int(header[1]) != self.process.pid):
            raise RuntimeError(f"unexpected fixture header {header}")
        namespaced = int(header[1])

        def matches(pid):
            nspid = re.search(r"^NSpid:\s+(.*)$", open(f"/proc/{pid}/status").read(), re.M)
            comm = open(f"/proc/{pid}/comm").read().strip()
            return nspid and int(nspid.group(1).split()[-1]) == namespaced and path.name.startswith(comm)

        self.pid = host_pid(self.process.pid, matches) if launcher else self.process.pid
        self.namespaced = self.pid != namespaced
        with open(path, "rb") as elf:
            header_bytes = elf.read(20)
        self.bits = 32 if header_bytes[4] == 1 else 64
        self.arm64 = int.from_bytes(header_bytes[18:20], "little") == 0xB7   # EM_AARCH64
        self.value, self.pointer, self.writer = (int(field, 16) for field in header[2:5])
        self.hook = header[5] if len(header) == 6 else "ce_writer"   # a process symbol names the hook point

    def reply(self):
        return int(self.line(timeout=15))


class WineFixture(Fixture):
    windows = True

    def __init__(self, path, launcher):
        super().__init__([*launcher, str(path)])
        header = self.line().split()
        if len(header) != 5 or header[0] != "CE_WINE":
            raise RuntimeError(f"unexpected fixture header {header}")
        self.bits = int(header[1]) * 8
        self.arm64 = False
        self.value, self.pointer, self.writer = (int(field, 16) for field in header[2:])
        prefix = os.environ.get("WINEPREFIX", "")

        def matches(pid):
            if path.name not in open(f"/proc/{pid}/maps").read():
                return False
            environ = open(f"/proc/{pid}/environ", "rb").read()
            return not prefix or f"WINEPREFIX={prefix}\0".encode() in environ

        self.pid = host_pid(self.process.pid, matches)
        self.namespaced = False
        self.hook = f"{self.writer:#x}"   # PE fixtures carry no symbols

    def reply(self):
        return struct.unpack("<I", self.receive(4))[0]


def hook_script(fixture, site, original, define=True):
    """A code cave that stores 1000 into the value and returns 1000."""
    hook = "hook" if define else site
    if fixture.arm64:
        value = fixture.value
        body = (f"movz x1, #{value & 0xffff:#x}\n" +
                "".join(f"movk x1, #{(value >> shift) & 0xffff:#x}, lsl #{shift}\n" for shift in (16, 32, 48)) +
                "mov w0, #1000\nstr w0, [x1]\nret\n")
        jump = "b newmem"
    else:
        reg = "ecx" if fixture.bits == 32 else "rcx"
        body = f"mov {reg},{fixture.value:#x}\nmov eax,#1000\nmov [{reg}],eax\nret\n"
        jump = "jmp newmem"
    return ((f"[ENABLE]\ndefine(hook,{site})\n" if define else "[ENABLE]\n") +
            f"alloc(newmem,256,{site})\nnewmem:\n{body}{hook}:\n{jump}\n"
            f"[DISABLE]\n{hook}:\ndb {original}\ndealloc(newmem)\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("fixtures", type=pathlib.Path, nargs="+")
    launchers = parser.add_mutually_exclusive_group()
    launchers.add_argument("--launcher", default="",
                           help="sandbox command to prefix; {dir} expands to the fixture's directory")
    launchers.add_argument("--wine-launcher", default="",
                           help="Wine or Proton command that runs the PE fixtures")
    parser.add_argument("--gui", action="store_true",
                        help="also drive the Qt main and debugger windows (gui_lifecycle_smoke --target)")
    parser.add_argument("--ceserver", action="store_true",
                        help="also drive the program remotely: cescan ceserver plus a Lua ceserver client")
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

    def aob(pid, address):
        # `read --type aob` prints "ADDRESS: BYTES"; keep only the bytes.
        return run("read", pid, address, 5, "--type", "aob").split(":", 1)[-1].strip()

    for path in args.fixtures:
        path = path.resolve()
        template = args.wine_launcher or args.launcher
        launcher = [part.replace("{dir}", str(path.parent)) for part in shlex.split(template)]
        entry = {"fixture": path.name, "launcher": launcher, "checks": {}}
        report["targets"].append(entry)
        fixture = (WineFixture if args.wine_launcher else LibcFixture)(path, launcher)
        if launcher:
            print(f"launched {path.name}: host PID {fixture.pid}, namespaced: {fixture.namespaced}", flush=True)

        def check(name, ok, detail=""):
            nonlocal failures
            entry["checks"][name] = bool(ok)
            print(f"FRONTEND_TARGET_CHECK {'OK' if ok else 'FAILED'}: {path.name}: {name}", flush=True)
            if not ok:
                failures += 1
                if detail:
                    print(detail[-3000:], flush=True)

        try:
            pid = fixture.pid
            info = run("info", pid)
            if fixture.windows:
                abi = "Windows i386" if fixture.bits == 32 else "Windows x64"
                check(f"info identifies a Wine-hosted {abi} program", abi in info and "wine:     yes" in info, info)
            else:
                arch, abi = (("ARM64", "Linux AArch64") if fixture.arm64 else
                             ("x86-32", "Linux i386") if fixture.bits == 32 else ("x86-64", "Linux x86-64"))
                check(f"info identifies an {arch} Linux program", arch in info and abi in info, info)
                symbols = run("symbols", pid, "e_writer") + run("symbols", pid, "eValue") + run("symbols", pid, "ce_value")
                check("the symbol table names the writer", "ce_writer" in symbols and ("ce_value" in symbols or "ceValue" in symbols),
                      symbols[:2000])
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
            check("a pointer scan finds the static pointer path",
                  path.name in pointers and f"-> {fixture.value:#x}" in pointers.lower(), pointers[-2000:])

            original = aob(pid, fixture.hook)
            with tempfile.TemporaryDirectory() as directory:
                script = pathlib.Path(directory) / "hook.aa"
                script.write_text(hook_script(fixture, fixture.hook, original))
                hook = subprocess.Popen([cescan, "autoasm", str(pid), str(script), "--disable-after", "4"],
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                time.sleep(2)
                hooked = fixture.command("b")
                output = hook.communicate(timeout=30)[0]
            restored = aob(pid, fixture.hook)
            check("an Auto Assembler hook with a code cave changes the program's behavior", hooked == 1000, output)
            check("disabling the hook restores the original bytes and behavior",
                  restored == original and fixture.command("b") == 1001 and "Disabled" in output, output)

            watch = subprocess.Popen([cescan, "watch", str(pid), hex(fixture.value), "--duration", "4"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            time.sleep(2)
            written = fixture.command("b")
            output = watch.communicate(timeout=30)[0]
            check("find-what-writes names the writer instruction",
                  written == 1002 and re.search(r"ce_writer|" + f"{fixture.writer:x}", output.lower()) is not None, output)

            script = (f"assert(openProcess({pid}))\n"
                      "local hit = nil\n"
                      "function debugger_onBreakpoint() hit = BPAddress; return 1 end\n"
                      f"assert(debug_setBreakpoint({fixture.writer}))\n"
                      "print('SESSION_READY'); io.flush()\n"
                      "for i = 1, 100 do debug_pumpEvents(100); if hit then break end end\n"
                      f"assert(hit == {fixture.writer}, 'breakpoint did not stop at the writer: ' .. tostring(hit))\n"
                      f"debug_removeBreakpoint({fixture.writer})\n"
                      "print('SESSION_HIT'); io.flush()\n")
            debugger = subprocess.Popen([cescan, "lua", "-e", script], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
            ready = select.select([debugger.stdout], [], [], 15)[0] and debugger.stdout.readline().strip() == "SESSION_READY"
            if ready:
                fixture.send("b")
            output, error = debugger.communicate(timeout=30)
            check("a Lua debugger breakpoint stops at the writer and the call completes",
                  ready and debugger.returncode == 0 and "SESSION_HIT" in output and fixture.reply() == 1003,
                  output + error)
            if fixture.windows:
                # Native calls need Wine-safe loader/thread backends: refused, not attempted.
                refusal = subprocess.run([cescan, "lua", "-e",
                    f"assert(openProcess({pid}))\n"
                    "local a, e = injectLibrary('/nonexistent/ce-probe.so')\n"
                    "assert(a == nil and tostring(e):find('Wine', 1, true), 'injectLibrary: ' .. tostring(e))\n"
                    f"local b, f = executeCode({fixture.writer})\n"
                    "assert(b == nil and tostring(f):find('Wine', 1, true), 'executeCode: ' .. tostring(f))\n"
                    "print('REFUSED_OK')\n"], capture_output=True, text=True, timeout=60)
                check("Lua native calls are refused with the explicit Wine reason",
                      refusal.returncode == 0 and "REFUSED_OK" in refusal.stdout, refusal.stdout + refusal.stderr)
            expected = 1003
            if not fixture.windows:
                def lua(script):
                    result = subprocess.run([cescan, "lua", "-e", f"assert(openProcess({pid}))\n" + script],
                                            capture_output=True, text=True, timeout=60)
                    return result.returncode, result.stdout + result.stderr
                # Symbols resolve as soon as the process is open, as in CE.
                code, output = lua(f"assert(getAddress('{fixture.hook}') == {fixture.writer}, tostring(getAddress('{fixture.hook}')))\n"
                                   "print('SYMBOL_OK')\n")
                check("Lua resolves the program's own symbol right after openProcess", code == 0 and "SYMBOL_OK" in output, output)
                maps = open(f"/proc/{pid}/maps").read()
                dynamic = re.search(r"/(ld-linux[^/\s]*|ld-musl[^/\s]*|libc\.so\.6)$", maps, re.M) is not None
                if dynamic:
                    # Every thread blocked in a system call: refused with the reason.
                    code, output = lua(f"local r, e = executeCode({fixture.writer})\n"
                                       "assert(r == nil and tostring(e):find('blocked in a system call', 1, true), tostring(e))\n"
                                       "print('PARKED_REFUSED')\n")
                    check("a native call into a wholly syscall-parked program is refused with its reason",
                          code == 0 and "PARKED_REFUSED" in output, output)
                    # A thread executing user code (like a game loop) hosts the call.
                    spinning = fixture.command("s") == 1
                    code, output = lua(f"assert(executeCode({fixture.writer}))\nprint('CALLED')\n")
                    stopped = fixture.command("x") == 0
                    expected += 1
                    check("executeCode runs the program's own function on a new thread",
                          spinning and stopped and code == 0 and "CALLED" in output and fixture.command("r") == expected, output)
                else:
                    # Static programs carry only the thread functions they use.
                    code, output = lua(f"local r, e = executeCode({fixture.writer})\n"
                                       "assert(r == nil and tostring(e):find('static program', 1, true), tostring(e))\n"
                                       "print('STATIC_REFUSED')\n")
                    check("a static program without pthread_detach refuses native calls with that reason",
                          code == 0 and "STATIC_REFUSED" in output, output)
                libc = re.search(r"(/\S*/libc\.so\.6)$", maps, re.M)
                library = libc and pathlib.Path(libc.group(1)).with_name("libm.so.6")
                if not launcher and library and library.is_file():
                    fixture.command("s")
                    code, output = lua(f"local h, e = injectLibrary('{library}')\nassert(h, tostring(e))\nprint('LOADED')\n")
                    fixture.command("x")
                    check("injectLibrary loads a real shared library into the program",
                          code == 0 and "LOADED" in output and str(library) in open(f"/proc/{pid}/maps").read(), output)
                elif "ld-musl" not in maps and not libc:
                    code, output = lua("local h, e = injectLibrary('/nonexistent/ce-probe.so')\n"
                                       # musl static has no dlopen; glibc static has one but
                                       # this idle program has no thread to host the call.
                                       "assert(h == nil and tostring(e):find('dlopen', 1, true), tostring(e))\n"
                                       "print('NO_LOADER')\n")
                    check("a static program refuses library injection with an explicit reason",
                          code == 0 and "NO_LOADER" in output, output)
            check("the program keeps running after every frontend detached", fixture.command("r") == expected)
            if args.gui:
                run("write", pid, hex(fixture.value), 24681357, "--type", "i32")
                smoke = subprocess.Popen([str((args.build / "gui_lifecycle_smoke").resolve()), "--target", str(pid),
                                          hex(fixture.value), hex(fixture.writer)],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                         env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
                lines = []
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    if not select.select([smoke.stdout], [], [], 1)[0]:
                        continue
                    line = smoke.stdout.readline()
                    if not line:
                        break
                    lines.append(line)
                    if line.startswith("GUI_TARGET_ARMED"):
                        fixture.send("b")
                rest = smoke.communicate(timeout=30)[0]
                output = "".join(lines) + rest
                called = fixture.reply() if "GUI_TARGET_ARMED" in output else None
                check("the GUI scans, edits and debugs the target (6 window checks)",
                      smoke.returncode == 0 and "GUI_TARGET_RESULT=PASSED checks=6" in output, output)
                check("the program's GUI-interrupted call completes after detach", called == 13580, output)
            if args.ceserver and not fixture.windows:
                server = subprocess.Popen([cescan, "ceserver", "--port", "0"], stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT, text=True, bufsize=1)
                try:
                    listening = select.select([server.stdout], [], [], 10)[0] and server.stdout.readline()
                    port = re.search(r"127\.0\.0\.1:(\d+)", listening or "")
                    check("cescan ceserver listens on loopback", port is not None, listening or "")
                    original = aob(pid, hex(fixture.writer))
                    hook = hook_script(fixture, f"{fixture.writer:#x}", original, define=False)
                    remote = subprocess.Popen([cescan, "lua", "-e", f"""
assert(connectToCeserver('127.0.0.1', {port.group(1) if port else 1}, {pid}))
local info = getTargetInfo()
assert(info.transport == 'ceserver', 'transport ' .. tostring(info.transport))
assert(writeInteger({fixture.value}, 4242))
print('REMOTE_WRITTEN'); io.flush()
-- 48-bit user space: ARM64 PIE programs load near 0xaaaaaaaa0000.
local scan = createMemScan()
assert(scan:firstScan(0, 2, '4242', 0, 0xffffffffffff, 4))
local function has(s) for i = 0, s:getFoundCount() - 1 do if s:getAddress(i) == {fixture.value} then return true end end end
assert(has(scan), 'first scan over ceserver missed the value')
assert(writeInteger({fixture.value}, 4243))
assert(scan:nextScan(0, 2, '4243', 0, 0xffffffffffff, 4))
assert(has(scan), 'next scan over ceserver missed the value')
print('REMOTE_SCANNED'); io.flush()
local resolved = false
for _, path in ipairs(pointerScan({fixture.value}, 1, 64) or {{}}) do
  if path.moduleBase + path.baseOffset == {fixture.pointer} then resolved = true end
end
assert(resolved, 'pointer scan over ceserver missed the static path')
print('REMOTE_POINTERS'); io.flush()
local hook = [[{hook}]]
local ok, disable = autoAssemble(hook)
if {'true' if fixture.arm64 else 'false'} then
  -- Remote ARM code writes have no backend yet: refused explicitly.
  assert(not ok and tostring(disable):find('not supported', 1, true), tostring(disable))
  print('REMOTE_HOOK_REFUSED'); io.flush()
else
  assert(ok, tostring(disable))
  print('REMOTE_HOOKED'); io.flush()
  io.read('l')
  local undone, err = autoAssemble(hook, disable)
  assert(undone, tostring(err))
  print('REMOTE_UNHOOKED'); io.flush()
end
local r, e = executeCode({fixture.writer})
assert(r == nil and e, 'remote native call was not refused')
print('REMOTE_CALL_REFUSED ' .. tostring(e)); io.flush()
"""], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                    seen, hooked = [], None
                    deadline = time.monotonic() + 120
                    while time.monotonic() < deadline and select.select([remote.stdout], [], [], 1):
                        line = remote.stdout.readline()
                        if not line:
                            break
                        seen.append(line)
                        if line.startswith("REMOTE_HOOKED"):
                            hooked = fixture.command("b")
                            remote.stdin.write("go\n")
                            remote.stdin.flush()
                    remote.wait(timeout=30)
                    output = "".join(seen)
                    check("a Lua client writes the program through cescan ceserver",
                          "REMOTE_WRITTEN" in output, output)
                    check("first and next scans run over the ceserver transport", "REMOTE_SCANNED" in output, output)
                    check("a pointer scan over ceserver finds the static path", "REMOTE_POINTERS" in output, output)
                    if fixture.arm64:
                        check("remote ARM code patches are refused with an explicit reason",
                              "REMOTE_HOOK_REFUSED" in output and fixture.command("b") == 4244, output)
                    else:
                        check("an Auto Assembler hook applied over ceserver changes the program", hooked == 1000, output)
                        check("autoAssemble(script, disableInfo) undoes it over ceserver",
                              "REMOTE_UNHOOKED" in output and fixture.command("b") == 1001, output)
                    check("native calls over ceserver are refused with a reason", "REMOTE_CALL_REFUSED" in output, output)
                    if args.gui and port:
                        run("write", pid, hex(fixture.value), 24681357, "--type", "i32")
                        gui = subprocess.run([str((args.build / "gui_lifecycle_smoke").resolve()), "--ceserver-target",
                                              port.group(1), str(pid), hex(fixture.value)], capture_output=True, text=True,
                                             timeout=120, env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
                        check("the GUI scans and edits the program through ceserver (4 window checks)",
                              gui.returncode == 0 and "GUI_CESERVER_RESULT=PASSED checks=4" in gui.stdout,
                              gui.stdout + gui.stderr)
                        expected = 13579
                    expected = 1001
                finally:
                    server.terminate()
                    server.wait(timeout=10)
        except Exception as error:  # report and continue with the next fixture
            check("the workflow completes", False, repr(error))
        finally:
            fixture.close()
    report["status"] = "failed" if failures else "passed"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    total = sum(len(entry["checks"]) for entry in report["targets"])
    print(f"FRONTEND_TARGET_RESULT={report['status'].upper()} checks={total} failed={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
