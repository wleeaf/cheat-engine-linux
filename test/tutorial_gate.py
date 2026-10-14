#!/usr/bin/env python3
"""Finish the Cheat Engine tutorials (cetutorial, cegtutorial) with our own tools.

Two players complete all nine steps of the tutorial and the three levels of
the graphical tutorial, each on fresh games in text mode:

  cli    what a terminal user types: cescan scan, write, watch, accessed,
         freeze and autoasm, plus a Lua pointer scan;
  agent  an AI agent's tool calls over MCP (cescan mcp), scripted the way a
         model would use them.

Neither player knows where anything is: they find every value, pointer and
instruction by scanning and watching, as the tutorial asks.

Usage: test/tutorial_gate.py <build-dir> [--player cli|agent|both] [--seed N] [--report file.json]
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
import threading
import time

PASSWORDS = {2: "LX4F2Q", 3: "RM8K3T", 4: "BW6N1D", 5: "HJ2P9C", 6: "TQ5V7Z", 7: "KD3R8M", 8: "YF9W4H", 9: "PN7C2X"}
FIELD = re.compile(r"^  (.+?): (.*)$")


class Tutorial:
    """The tutorial in text mode, driven over its stdin and stdout."""

    def __init__(self, binary, seed):
        self.proc = subprocess.Popen([str(binary), "--text", "--seed", str(seed)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.pid = self.proc.pid
        self.lines = []
        self.completed = set()
        self.changed = threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()
        self.wait_for(r"^Step 1 of 9")

    def _read(self):
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            with self.changed:
                self.lines.append(line)
                if m := re.match(r"^Step (\d) complete\.", line):
                    self.completed.add(int(m.group(1)))
                self.changed.notify_all()

    def send(self, command):
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()

    def wait_for(self, pattern, start=0, timeout=10):
        regex = re.compile(pattern)
        deadline = time.time() + timeout
        with self.changed:
            while True:
                for i in range(start, len(self.lines)):
                    if m := regex.search(self.lines[i]):
                        return i, m
                left = deadline - time.time()
                if left <= 0:
                    raise TimeoutError(f"no line matching {pattern!r}; last lines: {self.lines[-6:]}")
                self.changed.wait(left)

    def mark(self):
        with self.changed:
            return len(self.lines)

    def action(self, command, last_field):
        """Run a step's button. Returns the message and the values shown after it."""
        start = self.mark()
        self.send(command)
        end, _ = self.wait_for(r"^  " + re.escape(last_field) + ": ", start)
        with self.changed:
            block = self.lines[start:end + 1]
        message = next((l for l in block if not l.startswith("  ") and not re.match(r"^Step \d complete", l)), "")
        values = {m.group(1): m.group(2) for l in block if (m := FIELD.match(l))}
        return message, values

    def values(self, last_field):
        return self.action("values", last_field)[1]

    def wait_complete(self, step, timeout=3.0):
        deadline = time.time() + timeout
        with self.changed:
            while step not in self.completed:
                left = deadline - time.time()
                if left <= 0:
                    return False
                self.changed.wait(left)
        return True

    def next(self, step):
        start = self.mark()
        self.send("next")
        self.wait_for(rf"^Step {step} of 9|^Finished$", start)

    def close(self):
        try:
            self.send("quit")
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
            self.proc.wait()


class GraphicalTutorial:
    """The graphical tutorial in text mode: hold keys for a while, read the status."""

    def __init__(self, binary, seed):
        self.inner = Tutorial.__new__(Tutorial)
        t = self.inner
        t.proc = subprocess.Popen([str(binary), "--text", "--seed", str(seed)], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        t.pid, t.lines, t.completed, t.changed = t.proc.pid, [], set(), threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()
        self.pid = t.pid
        t.wait_for(r"^Level 1 of 3")

    def _read(self):
        t = self.inner
        for line in t.proc.stdout:
            with t.changed:
                t.lines.append(line.rstrip("\n"))
                if m := re.match(r"^Level (\d) complete\.", line):
                    t.completed.add(int(m.group(1)))
                t.changed.notify_all()

    def press(self, keys, ms):
        """Hold keys (or nothing) for ms; returns the bars shown after, as percentages."""
        start = self.inner.mark()
        self.inner.send(f"press {keys} {ms}" if keys else f"wait {ms}")
        end, _ = self.inner.wait_for(r"^Level \d of 3|^Finished", start, timeout=ms / 1000 + 10)
        bars = {}
        with self.inner.changed:
            for line in self.inner.lines[end:end + 4]:
                if m := re.match(r"^  (\w[\w ]*): \[([#.]+)\]", line):
                    bars[m.group(1)] = 100 * m.group(2).count("#") / len(m.group(2))
        return bars

    @staticmethod
    def around(percent, full=100):
        """The range a bar of this length stands for (full = the value of a full
        bar), with room for what changed since. Whole numbers, for integer scans."""
        return str(int(max(0.0, percent - 6) * full / 100)), str(int((percent + 6) * full / 100 + 1))

    def wait_complete(self, level, timeout=3.0):
        return self.inner.wait_complete(level, timeout)

    def next(self, level):
        start = self.inner.mark()
        self.inner.send("next")
        self.inner.wait_for(rf"^Level {level} of 3|^Finished$", start)

    def close(self):
        self.inner.close()


def instruction_operand(text):
    """Base register and displacement of an instruction's [reg + disp] operand."""
    m = re.search(r"\[([a-z0-9]+)\s*(?:([+-])\s*(0x[0-9a-f]+|\d+))?\]", text)
    if not m:
        return None, 0
    disp = int(m.group(3), 0) if m.group(3) else 0
    return m.group(1), -disp if m.group(2) == "-" else disp


# ── The terminal player ──

class CliPlayer:
    name = "cli"

    def __init__(self, build, tutorial, work, check):
        self.cescan = str(build / "cescan")
        self.tut = tutorial
        self.pid = str(tutorial.pid)
        self.work = work
        self.check = check
        self.scan_dirs = []

    def run(self, *args, timeout=120, ok=True):
        result = subprocess.run([self.cescan, *map(str, args)], capture_output=True, text=True, timeout=timeout)
        if ok and result.returncode != 0:
            raise RuntimeError(f"cescan {' '.join(map(str, args))} failed: {result.stdout[-400:]} {result.stderr[-400:]}")
        return result.stdout

    def background(self, *args, allow_file_writes=False):
        # The gate's own Lua signals progress through files, which needs the
        # file-write opt-in a table would need too.
        env = dict(os.environ, CECORE_LUA_ALLOW_UNSAFE="1") if allow_file_writes else None
        return subprocess.Popen([self.cescan, *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, env=env)

    def scan(self, *args, previous=None):
        out = self.run("scan", self.pid, *args, *(["--previous", previous] if previous else []))
        count = int(re.search(r"^Found: (\d+) results", out, re.M).group(1))
        results = re.search(r"^Results: (.+)$", out, re.M).group(1)
        self.scan_dirs.append(pathlib.Path(results).parent)
        rows = re.findall(r"^\s+(0x[0-9a-f]+) = (.*)$", out, re.M)
        return count, results, rows

    def narrow(self, scan_type, field, command, last_field=None, limit=2, rounds=8):
        """First scan for the shown value, then change it in the game and scan again."""
        last_field = last_field or field
        value = self.tut.values(last_field)[field]
        count, results, rows = self.scan("--type", scan_type, "--value", value)
        for _ in range(rounds):
            if count <= limit:
                break
            _, values = self.tut.action(command, last_field)
            count, results, rows = self.scan("--type", scan_type, "--value", values[field], previous=results)
        return rows

    def write_until_complete(self, step, rows, value, scan_type="i32"):
        for address, _ in rows:
            self.run("write", self.pid, address, value, "--type", scan_type)
            if self.tut.wait_complete(step, 1.0):
                return address
        return None

    def watch(self, address, command, last_field, *options):
        """Find what writes (or accesses) an address while a button runs."""
        watcher = self.background("watch", self.pid, address, "--duration", 2, *options)
        time.sleep(1.0)
        self.tut.action(command, last_field)
        out, _ = watcher.communicate(timeout=30)
        hits = re.findall(r"^\s+\d+ x\s+(0x[0-9a-f]+)\s+(.+?)(?:   ; .*)?$", out, re.M)
        return hits, out

    def play(self):
        tut, check = self.tut, self.check
        tut.next(2)

        # Step 2: exact value.
        rows = self.narrow("i32", "Health", "hit")
        check("step 2: scanning narrows health to a few addresses", 0 < len(rows) <= 2, rows)
        self.write_until_complete(2, rows, 1000)
        check("step 2: writing 1000 completes the step", tut.wait_complete(2), tut.lines[-4:])
        tut.next(3)

        # Step 3: unknown initial value, then decreased by the amount shown.
        count, results, rows = self.scan("--type", "i32", "--compare", "unknown")
        for _ in range(10):
            message, _ = tut.action("hit", "Health")
            lost = re.search(r"lost (\d+)", message).group(1)
            count, results, rows = self.scan("--type", "i32", "--compare", "decreasedby", "--value", lost, previous=results)
            if count <= 3:
                break
            time.sleep(0.2)
            count, results, rows = self.scan("--type", "i32", "--compare", "unchanged", previous=results)
        check("step 3: unknown value and decreased-by scans find health", 0 < count <= 3, (count, rows))
        self.write_until_complete(3, rows, 5000)
        check("step 3: writing 5000 completes the step", tut.wait_complete(3), tut.lines[-4:])
        tut.next(4)

        # Step 4: a float and a double, scanned by the rounded value shown.
        health = self.narrow("float", "Health", "hit", last_field="Ammo")
        ammo = self.narrow("double", "Ammo", "fire", last_field="Ammo")
        check("step 4: float and double scans match the rounded values", health and ammo, (health, ammo))
        for address, _ in health:
            self.run("write", self.pid, address, 5000, "--type", "float")
        for address, _ in ammo:
            self.run("write", self.pid, address, 5000, "--type", "double")
        check("step 4: both at 5000 completes the step", tut.wait_complete(4), tut.lines[-4:])
        tut.next(5)

        # Step 5: find what writes the value, then NOP that instruction.
        rows = self.narrow("i32", "Value", "change", limit=1)
        hits, out = self.watch(rows[0][0], "change", "Value")
        check("step 5: watch finds the instruction that writes the value", len(hits) == 1 and "mov" in hits[0][1], out)
        writer = hits[0][0]
        first = re.search(r"^[0-9a-f]{8,}  ((?:[0-9a-f]{2} )+)", self.run("disasm", self.pid, writer, 1), re.M)
        length = len(first.group(1).split())
        self.run("write", self.pid, writer, " ".join(["90"] * length), "--type", "aob")
        message, _ = tut.action("change", "Value")
        check("step 5: with the store NOPed, Change value changes nothing", tut.wait_complete(5), message)
        tut.next(6)

        # Step 6: the pointer, from the register the writer used, then a frozen pointer path.
        rows = self.narrow("i32", "Value", "change", limit=1)
        value_address = rows[0][0]
        hits, out = self.watch(value_address, "change", "Value", "--regs")
        register, offset = instruction_operand(hits[0][1]) if hits else (None, 0)
        base = re.search(rf"\b{register}=([0-9a-f]+)", out) if register else None
        check("step 6: watch --regs shows the pointer in the writer's base register",
              base and int(base.group(1), 16) + offset == int(value_address, 16), out[-600:])
        pointer = hex(int(base.group(1), 16))
        count, _, holders = self.scan("--type", "pointer", "--value", pointer)
        statics = [a for a, _ in holders if int(a, 16) < 0x7f0000000000 and self.in_module(a)]
        check("step 6: a pointer scan finds the static address that holds the pointer", len(statics) == 1, holders)
        path = f"[{statics[0]}]+{offset:x}"
        freezer = self.background("freeze", self.pid, path, 5000, "--interval", 50)
        time.sleep(0.5)
        message, _ = tut.action("pointer", "Value")
        check("step 6: freezing the pointer path survives Change pointer", tut.wait_complete(6, 5.0), (message, tut.lines[-3:]))
        freezer.terminate()
        freezer.communicate(timeout=10)
        tut.next(7)

        # Step 7: find the sub, assemble an add over it.
        rows = self.narrow("i32", "Health", "hit", limit=1)
        hits, out = self.watch(rows[0][0], "hit", "Health")
        check("step 7: watch finds the sub that lowers health", hits and hits[0][1].startswith("sub"), out)
        register, offset = instruction_operand(hits[0][1])
        script = self.work / "step7.cea"
        script.write_text(f"[ENABLE]\n{hits[0][0]}:\n  add dword ptr [{register}+{offset:X}],2\n"
                          f"[DISABLE]\n{hits[0][0]}:\n  sub dword ptr [{register}+{offset:X}],1\n")
        out = self.run("autoasm", self.pid, script)
        message, _ = tut.action("hit", "Health")
        check("step 7: the assembled add makes Hit me give 2 health", tut.wait_complete(7) and "SUCCESS" in out, (out, message))
        tut.next(8)

        # Step 8: four levels. A Lua script pointer scans (four levels, offsets up to 0x400),
        # waits while the value moves, then keeps the paths that lead to the new value.
        rows = self.narrow("i32", "Value", "change", limit=1)
        ready, moved = self.work / "scanned", self.work / "moved"
        lua = self.work / "pointers.lua"
        lua.write_text(f"""openProcess({self.pid})
local paths = pointerScan({rows[0][0]}, 4, 0x400)
writeFile('{ready}', tostring(#paths))
while not fileExists('{moved}') do sleep(50) end
local value = tonumber(readFile('{moved}'))
for _, p in ipairs(paths) do
  local at = getAddressFromName(p.path)
  if at and readInteger(at) == value then print('KEEP ' .. p.path) end
end
""")
        script = self.background("lua", lua, allow_file_writes=True)
        deadline = time.time() + 120
        while not ready.exists() and time.time() < deadline and script.poll() is None:
            time.sleep(0.1)
        count = int(ready.read_text() or 0) if ready.exists() else 0
        check("step 8: the Lua pointer scan finds paths", count > 0, count)
        _, values = tut.action("pointer", "Value")
        moved.write_text(values["Value"])
        out, _ = script.communicate(timeout=300)
        kept = re.findall(r"^KEEP (.+)$", out, re.M)
        check("step 8: rescanning by the new value keeps the four-level path",
              any(path.count("[") == 4 for path in kept), (count, kept[:5], out[-300:]))
        path = next(p for p in kept if p.count("[") == 4)
        freezer = self.background("freeze", self.pid, path, 5000, "--interval", 50)
        time.sleep(0.5)
        message, _ = tut.action("pointer", "Value")
        check("step 8: freezing the four-level path survives Change pointer", tut.wait_complete(8, 5.0), (message, path))
        freezer.terminate()
        freezer.communicate(timeout=10)
        tut.next(9)

        # Step 9: shared code. Find Ada and Grace, the shared writer, every player it
        # touches, the team field, and skip the write for team 1.
        count, results, _ = self.scan("--type", "float", "--value", "100")
        start = tut.mark()
        tut.send("battle")
        tut.wait_for(r"wins|Nobody won", start)
        count, results, team1 = self.scan("--type", "float", "--compare", "decreased", previous=results)
        check("step 9: Ada's and Grace's health found (they lost the battle)", count == 2, team1)
        start = tut.mark()
        hits, out = self.watch(team1[0][0], "battle", "Brute (team 2)")
        writer = hits[0][0] if hits else None
        register, offset = instruction_operand(hits[0][1]) if hits else (None, 0)
        check("step 9: watch finds the store that writes health", writer and "movss" in hits[0][1], out)
        accessed = self.background("accessed", self.pid, writer, "--duration", 3)
        time.sleep(1.0)
        tut.send("battle")
        out, _ = accessed.communicate(timeout=30)
        addresses = re.findall(r"^\s+\d+ x\s+(0x[0-9a-f]+)", out, re.M)
        check("step 9: the instruction writes all four players", len(addresses) == 4, out)
        team1_addresses = {int(a, 16) for a, _ in team1}
        dumps = {}
        for a in addresses:
            dumps[int(a, 16)] = self.read_bytes(hex(int(a, 16) - offset), 32)
        group1 = [d for a, d in dumps.items() if a in team1_addresses]
        group2 = [d for a, d in dumps.items() if a not in team1_addresses]
        team_offset = None
        for field in range(0, 32, 4):
            v1 = {int.from_bytes(d[field:field + 4], "little") for d in group1}
            v2 = {int.from_bytes(d[field:field + 4], "little") for d in group2}
            if len(v1) == 1 and len(v2) == 1 and v1 != v2 and max(v1 | v2) < 100:
                team_offset, team = field, v1.pop()
                break
        check("step 9: comparing the structures finds the team field", team_offset is not None,
              {hex(a): d.hex() for a, d in dumps.items()})
        original = self.read_bytes(writer, 5).hex(" ")
        script = self.work / "step9.cea"
        script.write_text(f"""[ENABLE]
alloc(newmem,64,{writer})
label(return)
label(skip)
newmem:
  cmp dword ptr [{register}+{team_offset:X}],{team}
  je skip
  {hits[0][1]}
skip:
  jmp return
{writer}:
  jmp newmem
return:
[DISABLE]
{writer}:
  db {original}
dealloc(newmem)
""")
        out = self.run("autoasm", self.pid, script)
        start = tut.mark()
        tut.send("battle")
        _, result = tut.wait_for(r"wins.*|Nobody won.*", start, timeout=30)
        check("step 9: with team 1 spared, team 1 wins", tut.wait_complete(9) and "SUCCESS" in out, (out[-300:], result.group(0)))
        tut.next(10)
        check("the tutorial is finished", tut.wait_for(r"^Finished$")[1] is not None)

    def play_graphical(self, game):
        check = self.check
        self.pid = str(game.pid)
        # Level 1: health seen only as a bar; it drops while shot and recovers after.
        count, results, rows = self.scan("--type", "i32", "--compare", "unknown")
        for _ in range(6):
            bar = game.press("fire", 800)["Target"]
            count, results, rows = self.scan("--type", "i32", "--compare", "decreased", previous=results)
            low, high = game.around(bar, 500)
            count, results, rows = self.scan("--type", "i32", "--compare", "between", "--value", low, "--value2", high,
                                             previous=results)
            game.press("", 2600)
            count, results, rows = self.scan("--type", "i32", "--compare", "increased", previous=results)
            if count <= 3:
                break
        check("graphical level 1: decreased and increased scans find the target's health", 0 < count <= 3, rows)
        for address, _ in rows:   # one at a time, as a user tries them
            self.run("write", self.pid, address, 0)
            if game.wait_complete(1, 1.0):
                break
        check("graphical level 1: health 0 destroys the target", game.wait_complete(1), rows)
        game.next(2)

        # Level 2: the gun's heat, a float seen as a bar, frozen at 0.
        count, results, rows = self.scan("--type", "float", "--compare", "unknown")
        for _ in range(6):
            game.press("fire", 400)
            count, results, rows = self.scan("--type", "float", "--compare", "increased", previous=results)
            low, high = game.around(game.press("", 1500)["Heat"])
            count, results, rows = self.scan("--type", "float", "--compare", "decreased", previous=results)
            count, results, rows = self.scan("--type", "float", "--compare", "between", "--value", low, "--value2", high,
                                             previous=results)
            if count <= 3:
                break
        check("graphical level 2: increased and decreased float scans find the heat", 0 < count <= 3, rows)
        freezers = [self.background("freeze", self.pid, address, 0, "--type", "float", "--interval", 20) for address, _ in rows]
        game.press("fire", 12000)
        check("graphical level 2: with the heat frozen, the fortress falls", game.wait_complete(2), game.inner.lines[-3:])
        for freezer in freezers:
            freezer.terminate()
            freezer.communicate(timeout=10)
        game.next(3)

        # Level 3: a setting in static memory.
        count, _, rows = self.scan("--type", "float", "--value", "420", "--writable")
        statics = [a for a, _ in rows if self.in_module(a, "cegtutorial")]
        check("graphical level 3: the jump power is found in static memory", len(statics) == 1, rows)
        self.run("write", self.pid, statics[0], 900, "--type", "float")
        game.press("right", 2600)
        game.press("right+jump", 2500)
        check("graphical level 3: a higher jump reaches the door", game.wait_complete(3), game.inner.lines[-3:])
        game.next(4)
        check("the graphical tutorial is finished", game.inner.wait_for(r"^Finished$")[1] is not None)

    def read_bytes(self, address, size):
        """Bytes from cescan read's hex dump (address, 16 hex bytes, text)."""
        data = b""
        for m in re.finditer(r"^[0-9a-f]+  ((?:[0-9a-f]{2} ?){1,16})", self.run("read", self.pid, address, size), re.M):
            data += bytes.fromhex(m.group(1))
        return data[:size]

    def in_module(self, address, module="cetutorial"):
        """True when the address is in the tutorial's own image (a static address)."""
        for m in re.finditer(r"^([0-9a-f]+)\s+(\d+)\s+(\S+)$", self.run("modules", self.pid), re.M):
            if m.group(3) == module and int(m.group(1), 16) <= int(address, 16) < int(m.group(1), 16) + int(m.group(2)):
                return True
        return False

    def cleanup(self):
        for d in self.scan_dirs:
            shutil.rmtree(d, ignore_errors=True)


# ── The agent player ──

class AgentPlayer:
    name = "agent"

    def __init__(self, build, tutorial, work, check):
        self.tut = tutorial
        self.work = work
        self.check = check
        self.server = subprocess.Popen([str(build / "cescan"), "mcp", "--allow-writes"], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.next_id = 0
        self.calls = 0

    def send(self, name, **arguments):
        self.next_id += 1
        self.calls += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}}
        self.server.stdin.write(json.dumps(message) + "\n")
        self.server.stdin.flush()
        return self.next_id

    def receive(self, request_id):
        reply = json.loads(self.server.stdout.readline())
        assert reply.get("id") == request_id, reply
        result = reply["result"]
        return result.get("isError", False), json.loads(result["content"][0]["text"])

    def tool(self, name, **arguments):
        return self.receive(self.send(name, **arguments))

    def while_playing(self, command, last_field, name, **arguments):
        """A watching tool call, with the user pressing a button meanwhile."""
        request = self.send(name, **arguments)
        time.sleep(1.0)
        self.tut.action(command, last_field)
        return self.receive(request)

    def find(self, scan_type, field, command, last_field=None, limit=1, rounds=8):
        last_field = last_field or field
        value = self.tut.values(last_field)[field]
        error, result = self.tool("first_scan", type=scan_type, value=value)
        for _ in range(rounds):
            if error or result["count"] <= limit:
                break
            _, values = self.tut.action(command, last_field)
            error, result = self.tool("next_scan", value=values[field])
        return [c["address"] for c in result.get("candidates", [])]

    def write_until_complete(self, step, addresses, scan_type, value):
        for address in addresses:
            self.tool("write", address=address, type=scan_type, value=value)
            if self.tut.wait_complete(step, 1.0):
                return True
        return False

    def play(self):
        tut, check, tool = self.tut, self.check, self.tool
        error, attached = tool("attach", target=str(tut.pid))
        check("attach to the tutorial", not error and attached["pid"] == tut.pid, attached)
        tut.next(2)

        # Step 2.
        found = self.find("i32", "Health", "hit", limit=2)
        self.write_until_complete(2, found, "i32", "1000")
        check("step 2: first_scan, next_scan and write complete the step", tut.wait_complete(2), found)
        tut.next(3)

        # Step 3.
        error, result = tool("first_scan", type="i32", compare="unknown")
        for _ in range(10):
            message, _ = tut.action("hit", "Health")
            error, result = tool("next_scan", compare="decreased_by", value=re.search(r"lost (\d+)", message).group(1))
            if error or result["count"] <= 3:
                break
            time.sleep(0.2)
            error, result = tool("next_scan", compare="unchanged")
        candidates = [c["address"] for c in result.get("candidates", [])]
        self.write_until_complete(3, candidates, "i32", "5000")
        check("step 3: unknown and decreased_by scans complete the step", tut.wait_complete(3), result)
        tut.next(4)

        # Step 4.
        health = self.find("float", "Health", "hit", last_field="Ammo", limit=2)
        ammo = self.find("double", "Ammo", "fire", limit=2)
        for address in health:
            tool("write", address=address, type="float", value="5000")
        for address in ammo:
            tool("write", address=address, type="double", value="5000")
        check("step 4: float and double scans complete the step", tut.wait_complete(4), (health, ammo))
        tut.next(5)

        # Step 5: find what writes, then a script that removes the store.
        found = self.find("i32", "Value", "change")
        error, writers = self.while_playing("change", "Value", "find_what_writes", address=found[0], seconds=2)
        instructions = writers.get("instructions", [])
        check("step 5: find_what_writes finds the store", not error and len(instructions) == 1, writers)
        error, template = tool("aa_template", address=instructions[0]["address"])
        script = template.get("script", "")
        # The relocated store is the first line under code:; drop it.
        edited, changes = re.subn(r"(\ncode:\n)  mov[^\n]*\n", r"\1  // the value is no longer written\n", script, count=1)
        error, enabled = tool("aa_enable", script=edited, description="Value never changes")
        message, _ = tut.action("change", "Value")
        check("step 5: an injection without the store completes the step", changes == 1 and not error and tut.wait_complete(5),
              (enabled, message))
        tut.next(6)

        # Step 6: pointer_scan, the value moves, pointer_rescan, freeze the path.
        found = self.find("i32", "Value", "change")
        error, writers = self.while_playing("change", "Value", "find_what_writes", address=found[0], seconds=2)
        hint = writers.get("instructions", [{}])[0]
        check("step 6: find_what_writes reports the pointer the game followed",
              not error and "pointer" in hint and int(hint["pointer"], 16) + int(hint["offset"], 16) == int(found[0], 16), writers)
        error, scanned = tool("pointer_scan", address=found[0])
        check("step 6: pointer_scan finds paths", not error and scanned["count"] >= 1, scanned)
        _, values = tut.action("pointer", "Value")
        error, result = tool("first_scan", type="i32", value=values["Value"])
        survivors = []
        for candidate in result.get("candidates", []):
            error, rescanned = tool("pointer_rescan", address=candidate["address"])
            if not error and rescanned["count"]:
                survivors = rescanned["paths"]
                break
        check("step 6: pointer_rescan keeps the path to the moved value", survivors, result)
        error, record = tool("add_record", address=survivors[0], type="i32", description="Step 6 value")
        error2, frozen = tool("set_frozen", index=record.get("index", -1), frozen=True, value="5000")
        message, _ = tut.action("pointer", "Value")
        check("step 6: a frozen pointer record survives Change pointer",
              not error and not error2 and record.get("follows_pointer") and tut.wait_complete(6, 5.0), (record, frozen, message))
        tool("set_frozen", index=record.get("index", -1), frozen=False)
        tut.next(7)

        # Step 7: injection that adds 2 instead of subtracting 1.
        found = self.find("i32", "Health", "hit")
        error, writers = self.while_playing("hit", "Health", "find_what_writes", address=found[0], seconds=2)
        writer = writers["instructions"][0]
        error, template = tool("aa_template", address=writer["address"])
        script = template.get("script", "")
        edited, changes = re.subn(r"\n  sub (dword ptr \[[^\]]+\]),\s*(?:0x)?0*1\n", r"\n  add \1,2\n", script, count=1)
        error, checked = tool("aa_check", script=edited)
        error2, enabled = tool("aa_enable", script=edited, description="Hit me heals")
        message, _ = tut.action("hit", "Health")
        check("step 7: the edited injection makes Hit me give 2 health",
              changes == 1 and not error and not error2 and tut.wait_complete(7), (script, checked, enabled, message))
        error, record = tool("add_record", description="Hit me heals", script=edited)
        check("step 7: add_record saves the enabled script", not error and record.get("kind") == "script", record)
        tut.next(8)

        # Step 8: four pointer levels.
        found = self.find("i32", "Value", "change")
        error, scanned = tool("pointer_scan", address=found[0], max_depth=4)
        check("step 8: pointer_scan finds four-level paths", not error and scanned["count"] >= 1, scanned)
        _, values = tut.action("pointer", "Value")
        error, result = tool("first_scan", type="i32", value=values["Value"])
        survivors = []
        for candidate in result.get("candidates", []):
            error, rescanned = tool("pointer_rescan", address=candidate["address"])
            if not error and rescanned["count"]:
                survivors = rescanned["paths"]
                break
        check("step 8: pointer_rescan keeps only four-level paths", survivors and all(p.count("[") == 4 for p in survivors), survivors)
        error, record = tool("add_record", address=survivors[0], type="i32", description="Step 8 value")
        tool("set_frozen", index=record.get("index", -1), frozen=True, value="5000")
        message, _ = tut.action("pointer", "Value")
        check("step 8: a frozen four-level pointer record survives Change pointer", tut.wait_complete(8, 5.0), (record, message))
        tut.next(9)

        # Step 9: shared code.
        error, result = tool("first_scan", type="float", value="100")
        start = tut.mark()
        tut.send("battle")
        tut.wait_for(r"wins|Nobody won", start)
        error, result = tool("next_scan", compare="decreased")
        team1 = [c["address"] for c in result.get("candidates", [])]
        check("step 9: Ada's and Grace's health found", len(team1) == 2, result)
        request = self.send("find_what_writes", address=team1[0], seconds=2)
        time.sleep(1.0)
        tut.send("battle")
        error, writers = self.receive(request)
        writer = writers.get("instructions", [{}])[0]
        check("step 9: find_what_writes finds the shared store", not error and "movss" in writer.get("instruction", ""), writers)
        request = self.send("find_accessed_addresses", address=writer["address"], seconds=3)
        time.sleep(1.0)
        tut.send("battle")
        error, accessed = self.receive(request)
        addresses = [a["address"] for a in accessed.get("addresses", [])]
        check("step 9: find_accessed_addresses shows all four players", not error and len(addresses) == 4, accessed)
        offset = int(writer.get("offset", "0x0"), 16)
        group1 = [hex(int(a, 16) - offset) for a in addresses if a in team1]
        group2 = [hex(int(a, 16) - offset) for a in addresses if a not in team1]
        error, compared = tool("compare_structures", group1=group1, group2=group2, size=32)
        fields = [f for f in compared.get("fields", []) if f.get("differs_between_groups") and f["type"] == "i32"]
        check("step 9: compare_structures finds the team field", not error and len(fields) == 1, compared)
        team_offset, team = int(fields[0]["offset"], 16), fields[0]["values"][0]
        register, _ = instruction_operand(writer["instruction"])
        error, template = tool("aa_template", address=writer["address"])
        script = template["script"]
        edited = script.replace("label(return)\n", "label(return)\nlabel(skip)\n", 1)
        edited, changes = re.subn(r"(\ncode:\n)(  movss[^\n]*\n)",
                                  rf"\1  cmp dword ptr [{register}+{team_offset:X}],{team}\n  je skip\n\2skip:\n",
                                  edited, count=1)
        error, checked = tool("aa_check", script=edited)
        error2, enabled = tool("aa_enable", script=edited, description="Team 1 takes no damage")
        start = tut.mark()
        tut.send("battle")
        _, result = tut.wait_for(r"wins.*|Nobody won.*", start, timeout=30)
        check("step 9: an injection that checks the team makes team 1 win",
              changes == 1 and not error and not error2 and tut.wait_complete(9), (checked, enabled, result.group(0)))
        error, record = tool("add_record", description="Team 1 takes no damage", script=edited)
        check("step 9: add_record saves the enabled script", not error and record.get("kind") == "script", record)
        tut.next(10)

        table = self.work / "tutorial.CT"
        error, saved = tool("save_table", path=str(table))
        text = table.read_text() if table.exists() else ""
        check("save_table keeps the pointer paths and scripts", not error and saved.get("records") == 4
              and text.count("<Offsets>") == 2 and "Hit me heals" in text and "Team 1 takes no damage" in text, saved)
        check(f"the agent finished the tutorial in {self.calls} tool calls", tut.wait_for(r"^Finished$")[1] is not None)

    def play_graphical(self, game):
        check, tool = self.check, self.tool
        error, attached = tool("attach", target=str(game.pid))
        check("attach to the graphical tutorial", not error, attached)
        # Level 1.
        error, result = tool("first_scan", type="i32", compare="unknown")
        for _ in range(6):
            bar = game.press("fire", 800)["Target"]
            tool("next_scan", compare="decreased")
            low, high = game.around(bar, 500)
            tool("next_scan", compare="between", value=low, value2=high)
            game.press("", 2600)
            error, result = tool("next_scan", compare="increased")
            if error or result["count"] <= 3:
                break
        for candidate in result.get("candidates", []):
            tool("write", address=candidate["address"], type="i32", value="0")
            if game.wait_complete(1, 1.0):
                break
        check("graphical level 1: the target's health found and set to 0", game.wait_complete(1), result)
        game.next(2)
        # Level 2.
        error, result = tool("first_scan", type="float", compare="unknown")
        for _ in range(6):
            game.press("fire", 400)
            tool("next_scan", compare="increased")
            low, high = game.around(game.press("", 1500)["Heat"])
            tool("next_scan", compare="decreased")
            error, result = tool("next_scan", compare="between", value=low, value2=high)
            if error or result["count"] <= 3:
                break
        for candidate in result.get("candidates", []):
            error, record = tool("add_record", address=candidate["address"], type="float", description="Gun heat")
            tool("set_frozen", index=record["index"], frozen=True, value="0")
        game.press("fire", 12000)
        check("graphical level 2: frozen heat lets the fortress fall", game.wait_complete(2), result)
        game.next(3)
        # Level 3.
        error, result = tool("first_scan", type="float", value="420")
        statics = [c["address"] for c in result.get("candidates", []) if c.get("location", "").startswith("cegtutorial+")]
        check("graphical level 3: the jump power is in static memory", len(statics) == 1, result)
        tool("write", address=statics[0], type="float", value="900")
        game.press("right", 2600)
        game.press("right+jump", 2500)
        check("graphical level 3: a higher jump reaches the door", game.wait_complete(3), game.inner.lines[-3:])
        game.next(4)
        check("the agent finished the graphical tutorial", game.inner.wait_for(r"^Finished$")[1] is not None)

    def cleanup(self):
        self.server.stdin.close()
        try:
            self.server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.server.kill()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build")
    parser.add_argument("--player", choices=["cli", "agent", "both"], default="both")
    parser.add_argument("--seed", type=int, default=20261013, help="the games' random numbers")
    parser.add_argument("--report")
    args = parser.parse_args()
    build = pathlib.Path(args.build).resolve()
    results = []

    for player_class in [CliPlayer, AgentPlayer]:
        if args.player not in ("both", player_class.name):
            continue
        prefix = player_class.name

        def check(name, ok, detail="", prefix=prefix):
            results.append({"check": f"{prefix}: {name}", "ok": bool(ok), "detail": str(detail)[:600]})
            print(f"TUTORIAL_GATE_CHECK {'OK' if ok else 'FAILED'}: {prefix}: {name}" + ("" if ok else f" ({str(detail)[:600]})"),
                  flush=True)
            if not ok:
                raise AssertionError(name)
            return ok

        with tempfile.TemporaryDirectory(prefix=f"ce-tutorial-{prefix}-") as work:
            tutorial = Tutorial(build / "cetutorial", seed=args.seed)
            player = player_class(build, tutorial, pathlib.Path(work), check)
            try:
                player.play()
                tutorial.close()
                tutorial = GraphicalTutorial(build / "cegtutorial", seed=args.seed)
                player.play_graphical(tutorial)
            except AssertionError:
                pass
            except Exception as error:   # a crash in the player is a failed check, not a gate crash
                results.append({"check": f"{prefix}: no unexpected error", "ok": False, "detail": repr(error)[:600]})
                print(f"TUTORIAL_GATE_CHECK FAILED: {prefix}: unexpected error ({error!r})", flush=True)
            finally:
                player.cleanup()
                tutorial.close()

    failed = [r for r in results if not r["ok"]]
    print(f"TUTORIAL_GATE_RESULT={'FAILED' if failed else 'PASSED'} checks={len(results)} failed={len(failed)}")
    if args.report:
        pathlib.Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.report).write_text(json.dumps({"checks": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
