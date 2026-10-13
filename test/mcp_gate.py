#!/usr/bin/env python3
"""End-to-end check of `cescan mcp`, the server AI agents use.

Starts the stand-in game (test/readme_game.c), runs the MCP server over pipes
the way an MCP client does, and walks the agent workflow: find health, narrow
it after the game changes it, confirm, freeze it, and save a table.

Usage: test/mcp_gate.py <build-dir> [--report file.json]
"""
import argparse
import json
import os
import re
import pathlib
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build")
    parser.add_argument("--report")
    args = parser.parse_args()
    build = pathlib.Path(args.build).resolve()
    source = pathlib.Path(__file__).resolve().parent / "readme_game.c"
    results = []

    def check(name, ok, detail=""):
        results.append({"check": name, "ok": bool(ok), "detail": str(detail)[:400]})
        print(f"MCP_GATE_CHECK {'OK' if ok else 'FAILED'}: {name}" + ("" if ok else f" ({detail})"), flush=True)
        return ok

    with tempfile.TemporaryDirectory(prefix="ce-mcp-") as work:
        work = pathlib.Path(work)
        game_bin = work / "game"
        subprocess.run(["cc", "-O0", "-o", str(game_bin), str(source)], check=True)
        game = subprocess.Popen([str(game_bin)], stdout=subprocess.PIPE, text=True)
        server = subprocess.Popen([str(build / "cescan"), "mcp", "--allow-writes"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        next_id = [0]

        def rpc(method, params=None, notify=False):
            message = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                message["params"] = params
            if not notify:
                next_id[0] += 1
                message["id"] = next_id[0]
            server.stdin.write(json.dumps(message) + "\n")
            server.stdin.flush()
            if notify:
                return None
            reply = json.loads(server.stdout.readline())
            assert reply.get("id") == next_id[0], reply
            return reply

        def tool(name, **arguments):
            reply = rpc("tools/call", {"name": name, "arguments": arguments})
            result = reply["result"]
            return result.get("isError", False), json.loads(result["content"][0]["text"])

        def cli_write(address, value):
            subprocess.run([str(build / "cescan"), "write", str(game.pid), address, str(value)],
                           check=True, capture_output=True)

        try:
            health, ammo, gold, speed = game.stdout.readline().split()
            init = rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "mcp_gate", "version": "1"}})
            check("initialize returns server info and instructions",
                  init["result"]["serverInfo"]["name"] == "cheat-engine-linux" and init["result"].get("instructions"), init)
            rpc("notifications/initialized", notify=True)
            tools = {t["name"] for t in rpc("tools/list")["result"]["tools"]}
            check("tools/list offers the scan, memory and table tools",
                  {"attach", "first_scan", "next_scan", "write", "set_frozen", "save_table"} <= tools, sorted(tools))

            error, listed = tool("list_processes", filter="game")
            check("list_processes finds the game", not error and any(p["pid"] == game.pid for p in listed["processes"]), listed)
            error, attached = tool("attach", target=str(game.pid))
            check("attach to the game", not error and attached["pid"] == game.pid, attached)

            error, first = tool("first_scan", type="i32", value="100")
            addresses = {c["address"] for c in first.get("candidates", [])}
            if health not in addresses and first.get("count", 0) > 10:
                addresses |= {c["address"] for c in tool("scan_results", limit=50)[1]["candidates"]}
            check("first_scan finds health = 100", not error and health in addresses, first)

            cli_write(health, 75)   # the player takes damage
            error, second = tool("next_scan", compare="exact", value="75")
            narrowed = {c["address"] for c in second.get("candidates", [])}
            check("next_scan narrows to health after it changes", not error and health in narrowed and second["count"] <= 3, second)

            error, read = tool("read", address=health, type="i32")
            check("read confirms the value", not error and read["value"] == "75" and read.get("location", "").startswith("game+"), read)

            error, record = tool("add_record", address=health, type="i32", description="Health")
            check("add_record stores a module-relative address", not error and record["address"].startswith("game+"), record)
            error, frozen = tool("set_frozen", index=0, frozen=True, value="100")
            cli_write(health, 1)    # the game changes it again
            time.sleep(0.4)
            error2, after = tool("read", address=health, type="i32")
            check("set_frozen holds the value against the game", not error and not error2 and after["value"] == "100", after)

            error, code = tool("disassemble", address="main", count=6)
            check("disassemble resolves a symbol", not error and len(code.get("instructions", [])) >= 3, code)

            error, rejected = tool("first_scan", type="i32", compare="increased")
            check("an invalid request is refused with a reason", error and "next_scan" in rejected.get("error", ""), rejected)

            # Change behaviour with Auto Assembler, on a copy of the game that takes damage.
            damaged = subprocess.Popen([str(game_bin), "--damage"], stdout=subprocess.PIPE, text=True)
            try:
                hurt_health = damaged.stdout.readline().split()[0]
                error, attached = tool("attach", target=str(damaged.pid))
                check("attach to the game that takes damage", not error, attached)
                error, writers = tool("find_what_writes", address=hurt_health, seconds=2)
                found = writers.get("instructions", [])
                check("find_what_writes finds the code that lowers health",
                      not error and found and "take_damage" in found[0].get("location", ""), writers)
                error, template = tool("aa_template", address=found[0]["address"]) if found else (True, {})
                script = template.get("script", "")
                check("aa_template builds an injection with a restore section",
                      not error and "[ENABLE]" in script and "[DISABLE]" in script and "db " in script, template)
                # The agent's edit: drop the relocated store, so health is never written.
                edited, changes = re.subn(r"(\ncode:\n)(  (?!jmp)[^\n]*\n)", r"\1  // health no longer decreases\n", script, count=1)
                error, checked = tool("aa_check", script=edited)
                check("aa_check accepts the edited script", changes == 1 and not error, checked)
                error, broken = tool("aa_check", script="[ENABLE]\nnot an instruction\n[DISABLE]\n")
                check("aa_check reports a broken script", error and "error" in broken, broken)
                error, lua = tool("aa_check", script="[ENABLE]\n{$lua}\nreturn ''\n{$asm}\n[DISABLE]\n")
                check("agent scripts cannot run Lua", error, lua)
                # The dry run assembles against the live code, so it catches what a structural check cannot.
                code_bytes = lambda: tool("read", address=found[0]["address"], type="aob", size=6)[1].get("value")
                original = code_bytes()
                typo = edited.replace("// health no longer decreases", "movv eax, 1")
                error, typo_result = tool("aa_check", script=typo)
                check("aa_check catches a misspelled instruction", error, typo_result)
                stale = re.sub(r"assert\(INJECT,[^)]*\)", "assert(INJECT,90 90 90 90 90 90)", edited)
                error, stale_result = tool("aa_check", script=stale)
                check("aa_check catches an assert that no longer matches the code", error, stale_result)
                check("aa_check leaves the game's code untouched", code_bytes() == original, (original, code_bytes()))

                error, enabled = tool("aa_enable", script=edited, description="Infinite health")
                before = tool("read", address=hurt_health, type="i32")[1].get("value")
                time.sleep(0.6)
                after = tool("read", address=hurt_health, type="i32")[1].get("value")
                check("aa_enable stops the damage", not error and before == after, (enabled, before, after))
                error, listed = tool("aa_list")
                check("aa_list shows the enabled script",
                      not error and [s["description"] for s in listed["enabled"]] == ["Infinite health"], listed)
                error, disabled = tool("aa_disable", id=enabled.get("id", -1))
                start = tool("read", address=hurt_health, type="i32")[1].get("value")
                time.sleep(0.6)
                later = tool("read", address=hurt_health, type="i32")[1].get("value")
                check("aa_disable restores the original code", not error and start != later, (disabled, start, later))

                # A session that ends (the client quits or crashes) undoes its scripts.
                calls = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "attach", "arguments": {"target": str(damaged.pid)}}},
                         {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": "aa_enable", "arguments": {"script": edited, "description": "Infinite health"}}}]
                short = subprocess.run([str(build / "cescan"), "mcp", "--allow-writes"], capture_output=True, text=True,
                                       input="".join(json.dumps(c) + "\n" for c in calls), timeout=60)
                replies = [json.loads(line) for line in short.stdout.splitlines() if line.strip()]
                enabled_in_short = len(replies) == 2 and not replies[1]["result"]["isError"]
                first_read = tool("read", address=hurt_health, type="i32")[1].get("value")
                time.sleep(0.6)
                second_read = tool("read", address=hurt_health, type="i32")[1].get("value")
                check("ending the session undoes its scripts", enabled_in_short and first_read != second_read,
                      (short.stdout[-300:], first_read, second_read))

                error, record = tool("add_record", description="Infinite health", script=edited)
                check("add_record stores the script", not error and record.get("kind") == "script", record)
                table = work / "game.CT"
                error, saved = tool("save_table", path=str(table))
                text = table.read_text() if table.exists() else ""
                check("save_table writes the script entry", not error and "Infinite health" in text
                      and "Auto Assembler Script" in text, saved)
            finally:
                damaged.kill()
                damaged.wait()
        finally:
            server.stdin.close()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
            check("the server exits cleanly at end of input", server.returncode == 0, server.stderr.read()[-400:])
            game.kill()
            game.wait()

    # Node-based clients (Claude Code, Claude Desktop, VS Code) give the server
    # sockets for stdio, not pipes.
    import signal
    import socket
    ours, theirs = socket.socketpair()
    server = subprocess.Popen([str(build / "cescan"), "mcp"], stdin=theirs, stdout=theirs, stderr=subprocess.PIPE)
    theirs.close()
    ours.settimeout(10)
    stream = ours.makefile("rw", encoding="utf-8", newline="\n")
    try:
        def exchange(text):
            stream.write(text + "\n")
            stream.flush()
            return json.loads(stream.readline())
        reply = exchange(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                     "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                                                "clientInfo": {"name": "gate", "version": "1"}}}))
        check("the server works with socket stdio", reply.get("result", {}).get("serverInfo", {}).get("name") == "cheat-engine-linux", reply)
        reply = exchange(json.dumps([{"jsonrpc": "2.0", "id": 2, "method": "ping"},
                                     {"jsonrpc": "2.0", "method": "notifications/initialized"},
                                     {"jsonrpc": "2.0", "id": 3, "method": "ping"}]))
        check("a batch gets one array of replies", isinstance(reply, list) and [r.get("id") for r in reply] == [2, 3], reply)
        reply = exchange(json.dumps({"jsonrpc": "2.0", "id": 4, "params": {}}))
        check("a request without a method gets an error", reply.get("id") == 4 and reply.get("error", {}).get("code") == -32600, reply)
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        check("SIGTERM ends the server cleanly", server.returncode == 0, server.returncode)
    except (OSError, ValueError) as error:
        check("the server works with socket stdio", False, error)
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()
        stream.close()
        ours.close()

    failed = [r for r in results if not r["ok"]]
    print(f"MCP_GATE_RESULT={'FAILED' if failed else 'PASSED'} checks={len(results)} failed={len(failed)}")
    if args.report:
        pathlib.Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.report).write_text(json.dumps({"checks": results}, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
