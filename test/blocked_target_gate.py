#!/usr/bin/env python3
"""Refused operations on a blocked target must report the capability reason.

A real target is held by another debugger (its parent, so Yama ptrace_scope=1
permits the SEIZE). Every ptrace-backed operation through the CLI and Lua must
then fail with "traced by another debugger" instead of a silent nil, an empty
result or a generic permission guess. The GUI half lives in gui_debugger_smoke.
"""
import ctypes
import os
import pathlib
import signal
import subprocess
import sys

REASON = "traced by another debugger"
PTRACE_SEIZE = 0x4206


def start_blocked_target():
    ready_read, ready_write = os.pipe()
    tracer = os.fork()
    if tracer == 0:
        os.close(ready_read)
        target = os.fork()
        if target == 0:
            while True:
                signal.pause()
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        seized = libc.ptrace(PTRACE_SEIZE, target, None, None)
        os.write(ready_write, f"{target} {int(seized == 0)}\n".encode())
        while True:
            signal.pause()
    os.close(ready_write)
    with os.fdopen(ready_read) as ready:
        target, seized = map(int, ready.readline().split())
    if not seized:
        os.kill(tracer, signal.SIGKILL)
        os.waitpid(tracer, 0)
        raise RuntimeError("the holding tracer could not seize its child")
    return tracer, target


def readable_address(pid):
    with open(f"/proc/{pid}/maps") as maps:
        for line in maps:
            span, perms = line.split()[:2]
            if perms.startswith("rw"):
                return int(span.split("-")[0], 16)
    raise RuntimeError("no writable mapping in the blocked target")


def reads_permitted():
    """cescan is not the target's ancestor, so Yama scope 1+ forbids even reads."""
    try:
        scope = int(pathlib.Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
    except (OSError, ValueError):
        scope = 0
    return scope == 0 or os.geteuid() == 0


def main():
    cescan = (pathlib.Path(sys.argv[1]) / "cescan").resolve()
    tracer, target = start_blocked_target()
    failures = []
    checks = 0

    def check(ok, name, detail=""):
        nonlocal checks
        checks += 1
        print(f"BLOCKED_TARGET_CHECK {'OK' if ok else 'FAILED'}: {name}")
        if not ok:
            failures.append(name)
            if detail:
                print(detail)

    try:
        address = readable_address(target)
        watch = subprocess.run([str(cescan), "watch", str(target), hex(address), "--duration", "1"],
                               capture_output=True, text=True, timeout=30)
        check(watch.returncode != 0 and REASON in watch.stderr,
              "CLI watch names the blocking debugger", watch.stdout + watch.stderr)
        script = f"""
assert(openProcess({target}))
local function refused(name, value, reason)
  print(name, value == nil, tostring(reason))
  assert(value == nil and type(reason) == 'string' and reason:find('{REASON}', 1, true), name)
end
refused('allocateMemory', allocateMemory(4096))
refused('fullAccess', fullAccess({address}, 16))
refused('findWhatWrites', findWhatWrites({address}, 0.1))
refused('findWhatAccesses', findWhatAccesses({address}, 0.1))
refused('breakAndTrace', breakAndTrace({address}, 4))
local id, reason = debug_setBreakpoint({address})
print('debug_setBreakpoint', id, tostring(reason))
assert(type(id) == 'number' and reason and reason:find('{REASON}', 1, true), 'debug_setBreakpoint')
if {str(reads_permitted()).lower()} then
  assert(readInteger({address}) ~= nil, 'plain reads keep working on the blocked target')
end
print('LUA_BLOCKED_OK')
"""
        lua = subprocess.run([str(cescan), "lua", "-e", script], capture_output=True, text=True, timeout=60)
        check(lua.returncode == 0 and "LUA_BLOCKED_OK" in lua.stdout,
              "Lua ptrace operations return the capability reason; reads still work", lua.stdout + lua.stderr)
        status = open(f"/proc/{target}/status").read()
        check(f"TracerPid:\t{tracer}\n" in status, "the original holder still owns the target")
    finally:
        os.kill(target, signal.SIGKILL)
        os.kill(tracer, signal.SIGKILL)
        os.waitpid(tracer, 0)
    print(f"BLOCKED_TARGET_RESULT={'FAILED' if failures else 'PASSED'} checks={checks}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
