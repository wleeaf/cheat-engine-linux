#!/usr/bin/env python3
"""Independent RSP peers and an optional real, stopped, single-CPU QEMU fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from gdb_register_proxy import WholeRegisterProxy

X64_XML = b'''<?xml version="1.0"?><target xmlns:xi="http://www.w3.org/2001/XInclude"><architecture>i386:x86-64</architecture><osabi>GNU/Linux</osabi><xi:include href="core.xml"/></target>'''
CORE_XML = b'''<feature name="org.gnu.gdb.i386.core"><reg name="rax" bitsize="64"/><reg name="rip" bitsize="64" regnum="20"/></feature>'''
ARM_XML = b'''<target><architecture>aarch64</architecture><feature name="org.gnu.gdb.aarch64.core"><reg name="x0" bitsize="64"/><reg name="pc" bitsize="64" regnum="32"/></feature></target>'''


def frame(payload, raw=False, corrupt=False):
    data = payload if raw else b"".join(
        bytes((125, c ^ 32)) if c in b"$#}*" else bytes((c,)) for c in payload
    )
    checksum = (sum(data) + bool(corrupt)) & 255
    return b"$" + data + b"#" + f"{checksum:02x}".encode()


class Peer:
    def __init__(self, connection, mode):
        self.connection = connection
        self.mode = mode
        self.no_ack = False
        self.packets = []
        self.memory = bytearray(4096)
        self.memory_base = (1 << 52) if mode in ("adapter-high", "cli-high-scan", "cli-high-lua") else 0x1000
        self.memory[:12] = bytes.fromhex("112233445566778899aabbcc")
        if mode == "cli-scan-subnormal":
            self.memory[:8] = bytes.fromhex("0000000000000001")
        self.writes = 0
        self.stops = 0
        self.registers = {"0": bytes.fromhex("e012341234567890"), "14": bytes.fromhex("e012341234567890")}
        self.xml = {"target.xml": X64_XML, "core.xml": CORE_XML}
        self.bank_reads = self.bank_writes = self.p_reads = self.p_writes = 0
        if mode.startswith("bank-"):
            # Deliberately sparse and out of XML order. g/G use numeric order,
            # without invented padding for missing register numbers.
            self.xml = {"target.xml": b'''<target><architecture>aarch64</architecture><feature name="bank"><reg name="v0" bitsize="128" regnum="20"/><reg name="pc" bitsize="64" regnum="32"/><reg name="x0" bitsize="64" regnum="0"/><reg name="narrow" bitsize="17" regnum="4"/></feature></target>'''}
            self.registers = {"0": bytes.fromhex("e012341234567890"),
                              "4": bytes.fromhex("123401"),
                              "14": bytes(range(16)),
                              "20": bytes.fromhex("7856341200000040")}
        if mode.startswith("adapter") or mode.startswith("cli") or mode.startswith("gui"):
            self.xml = {"target.xml": ARM_XML}
        if mode in ("adapter-width", "adapter-endian-conflict"):
            self.xml = {"target.xml": X64_XML, "core.xml": CORE_XML}
        if mode == "xml-cycle":
            self.xml["core.xml"] = b'<feature xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="target.xml"/></feature>'
        elif mode == "xml-duplicate":
            self.xml["core.xml"] = b'<feature><reg name="rax" bitsize="64"/><reg name="rip" bitsize="64" regnum="0"/></feature>'
        elif mode == "xml-missing-bits":
            self.xml["core.xml"] = b'<feature><reg name="rax"/></feature>'
        elif mode == "xml-missing-arch":
            self.xml["target.xml"] = b'<target><reg name="rax" bitsize="64"/></target>'
        elif mode == "xml-namespace":
            self.xml["target.xml"] = X64_XML.replace(b"xmlns:xi=", b"xmlns:inc=").replace(b"xi:include", b"inc:include")
        elif mode == "xml-dtd-default":
            self.xml["target.xml"] = X64_XML.replace(b' xmlns:xi="http://www.w3.org/2001/XInclude"', b'').replace(b"<target>", b'<!DOCTYPE target SYSTEM "gdb-target.dtd"><target>')

    def byte(self):
        data = self.connection.recv(1)
        if not data:
            raise EOFError
        return data[0]

    def packet(self):
        while True:
            start = self.byte()
            if start == 36:
                break
            assert start in (43, 45), f"unexpected request prefix {start}"
        wire = bytearray()
        while True:
            c = self.byte()
            if c == 35:
                break
            wire.append(c)
            assert len(wire) <= 1 << 20
        checksum = bytes((self.byte(), self.byte()))
        assert int(checksum, 16) == sum(wire) % 256, "request checksum uses actual wire bytes"
        decoded = bytearray()
        i = 0
        while i < len(wire):
            c = wire[i]
            if c == 125:
                i += 1
                assert i < len(wire)
                c = wire[i] ^ 32
            decoded.append(c)
            i += 1
        self.packets.append(bytes(decoded))
        return bytes(decoded)

    def send(self, payload, **kwargs):
        response = frame(payload, **kwargs)
        # Fragment delimiters and both checksum digits at separate writes.
        self.connection.sendall(response[:-2])
        self.connection.sendall(response[-2:-1])
        self.connection.sendall(response[-1:])

    def run_raw(self):
        request = self.packet()
        assert request == (b"X$#}*" if self.mode == "raw-escape" else
                           b"m1000,4" if self.mode == "raw-short" else
                           b"m1000,2" if self.mode in ("raw-error", "raw-oversized") else b"g")
        if self.mode == "raw-request-retry":
            self.connection.sendall(b"-")
            assert self.packet() == request
        self.connection.sendall(b"+")
        if self.mode in ("raw-timeout", "raw-cancel"):
            # A trickling incomplete frame cannot reset the client's deadline.
            self.connection.sendall(b"$")
            for _ in range(8):
                time.sleep(0.025)
                try:
                    self.connection.sendall(b"1")
                except (BrokenPipeError, ConnectionResetError):
                    break
            return
        if self.mode == "raw-eof":
            return
        if self.mode == "raw-bad-prefix":
            self.connection.sendall(b"!garbage")
            return
        if self.mode == "raw-bad-rle":
            self.send(b"1*\x1f", raw=True)
            return
        if self.mode == "raw-bad-escape":
            self.send(b"1122}", raw=True)
            return
        if self.mode == "raw-rle":
            self.send(b"1* 2* ", raw=True)
            assert self.byte() == 43
            return
        if self.mode == "raw-response-retry":
            self.send(b"1122", corrupt=True)
            assert self.byte() == 45, "checksum rejection must request retransmission"
        if self.mode == "raw-console":
            self.send(b"O6869")
            assert self.byte() == 43
        response = {
            "raw-hex": b"E012341234", "raw-escape": b"$#}*",
            "raw-short": b"1122", "raw-error": b"E01", "raw-oversized": b"112233",
        }.get(self.mode, b"1122")
        self.send(response)
        assert self.byte() == 43, "successful response must be acknowledged"

    def respond(self, request):
        text = request.decode()
        if text.startswith("qSupported"):
            if self.mode.startswith("bank-"):
                size = "40" if self.mode == "bank-too-large" else "80"
                return f"PacketSize={size};QStartNoAckMode+;qXfer:features:read+;qXfer:memory-map:read+".encode()
            return b"PacketSize=40;QStartNoAckMode+;qXfer:features:read+;qXfer:memory-map:read+"
        if text == "QStartNoAckMode":
            return b"OK"
        if text == "?":
            self.stops += 1
            if self.mode == "adapter-bad-stop":
                return b"Szz"
            if self.mode in ("adapter-exited", "cli-exited") and self.stops>1:
                return b"W00"
            return b"S05"
        if text == "D":
            assert self.mode not in ("adapter-bad-stop", "adapter-bad-map", "adapter-exited", "cli-exited", "adapter-endian-conflict"), "failed or retired setup must not resume the guest via detach"
            return b"OK"
        if text.startswith("qXfer:"):
            _, obj, _, annex, offset_size = text.split(":")
            offset, count = (int(v, 16) for v in offset_size.split(","))
            content = self.xml.get(annex) if obj == "features" else f'<memory-map><memory type="ram" start="{self.memory_base:#x}" length="4096"/></memory-map>'.encode()
            if obj == "memory-map" and self.mode == "adapter-bad-map":
                content = b'<memory-map><memory type="ram" start="0x1000" length="4096"/><memory type="ram" start="0x1100" length="4096"/></memory-map>'
            assert content is not None
            chunk = content[offset:offset + count]
            return (b"l" if offset + count >= len(content) else b"m") + chunk
        if text.startswith("m"):
            address, count = (int(v, 16) for v in text[1:].split(","))
            offset = address - self.memory_base
            if not 0 <= offset < len(self.memory):
                return b"E01"
            limit = 64 if self.mode.startswith("bank-") and self.mode != "bank-too-large" else 32
            assert count <= limit, "read size must honor negotiated PacketSize"
            if self.mode == "adapter" and offset == 4092:
                count = 4
            return bytes(self.memory[offset:offset + count]).hex().encode()
        if text.startswith("M"):
            limit = 128 if self.mode.startswith("bank-") and self.mode != "bank-too-large" else 64
            assert len(request) <= limit, "write payload exceeds the stub's PacketSize"
            header, data = text[1:].split(":")
            address, count = (int(v, 16) for v in header.split(","))
            payload = bytes.fromhex(data)
            assert len(payload) == count
            self.writes += 1
            if self.mode == "partial-write" and self.writes == 2:
                return b"E01"
            offset = address - self.memory_base
            assert 0 <= offset <= len(self.memory) - count
            self.memory[offset:offset + count] = payload
            return b"OK"
        if text.startswith("p"):
            if self.mode.startswith("bank-"):
                self.p_reads += 1
                if self.mode == "bank-p-error":
                    return b"E01"
                if self.mode == "bank-p-malformed":
                    return b"bad-data"
                if self.mode != "bank-write-only":
                    return b""
            if self.mode in ("adapter", "gui-unavailable"):
                return b"x" * 16
            return self.registers.get(text[1:], bytes(8)).hex().encode()
        if text.startswith("P"):
            if self.mode.startswith("bank-"):
                self.p_writes += 1
                if self.mode == "bank-p-error":
                    return b"E01"
                if self.mode == "bank-p-malformed":
                    return b"not-OK"
                if self.mode != "bank-read-only":
                    return b""
            number, data = text[1:].split("=")
            self.registers[number] = bytes.fromhex(data)
            return b"OK"
        if text == "g" and self.mode.startswith("bank-"):
            self.bank_reads += 1
            if self.mode == "bank-g-error":
                return b"E01"
            data = b"".join(self.registers[n].hex().encode() for n in ("0", "4", "14", "20"))
            if self.mode == "bank-unavailable" and self.bank_writes == 0:
                data = data[:22] + b"x" * 32 + data[54:]
            elif self.mode == "bank-truncated":
                data = data[:16]
            elif self.mode == "bank-misaligned":
                data = data[:18]
            elif self.mode == "bank-oversized":
                data += b"00"
            elif self.mode == "bank-invalid":
                data = data[:-2] + b"z0"
            return data
        if text.startswith("G") and self.mode.startswith("bank-"):
            self.bank_writes += 1
            assert self.mode not in ("bank-misaligned", "bank-oversized", "bank-invalid", "bank-too-large", "bank-p-error", "bank-p-malformed", "bank-g-error"), "unsafe or unnecessary bank write"
            assert len(request) <= 128
            if self.mode == "bank-G-error":
                return b"E01"
            data = bytes.fromhex(text[1:])  # Unknown bytes must never be fabricated.
            expected = b"".join(self.registers[n] for n in ("0", "4", "14", "20"))
            assert len(data) == (8 if self.mode == "bank-truncated" else len(expected))
            offset = 0
            changed = 0
            for n in ("0", "4", "14", "20"):
                size = len(self.registers[n])
                if offset + size > len(data):
                    break
                fresh = data[offset:offset + size]
                changed += fresh != self.registers[n]
                self.registers[n] = fresh
                offset += size
            assert changed <= 1, "one edit cannot change an unrelated register"
            if self.mode == "bank-only" and self.bank_writes == 1:
                # A later write must reread the real bank, not replay a cache.
                self.registers["20"] = bytes.fromhex("efcdab8900000040")
            return b"OK"
        raise AssertionError(f"unexpected request {text}")

    def run(self):
        if self.mode.startswith("raw-"):
            self.run_raw()
            return
        while True:
            try:
                request = self.packet()
            except EOFError:
                return
            if not self.no_ack:
                self.connection.sendall(b"+")
            if self.mode == "gui-cancel":
                self.connection.sendall(b"$")
                while self.connection.recv(1024):
                    pass
                return
            if request == b"g" and self.mode in ("bank-disconnect", "bank-stall"):
                if self.mode == "bank-stall":
                    self.connection.sendall(b"$")
                    for _ in range(8):
                        time.sleep(0.025)
                        try:
                            self.connection.sendall(b"1")
                        except (BrokenPipeError, ConnectionResetError):
                            break
                return
            response = self.respond(request)
            self.send(response)
            if request == b"QStartNoAckMode":
                assert self.byte() == 43, "last acknowledgment completes no-ack negotiation"
                self.no_ack = True
            if request == b"D":
                return


def run_peer_case(driver, mode, driver_mode=None, cli_args=None, expected_return=0, lua_code=None):
    errors = []
    peers = []
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]

        def serve():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    peer = Peer(connection, mode)
                    peers.append(peer)
                    peer.run()
            except Exception as error:
                errors.append(repr(error))

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        command = ([str(driver), "gdb", "127.0.0.1", str(port), *cli_args]
                   if cli_args is not None else [str(driver), driver_mode or mode, "127.0.0.1", str(port)])
        if lua_code is not None:
            command = [str(driver), "lua", "-e", lua_prefix(port, False) + lua_code]
        started = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=12)
            record = {"name": mode, "returnCode": result.returncode,
                      "output": result.stdout + result.stderr, "seconds": round(time.monotonic() - started, 3)}
        except subprocess.TimeoutExpired:
            record = {"name": mode, "returnCode": -1, "output": "driver deadline exceeded"}
        worker.join(4)
        if worker.is_alive():
            errors.append("peer thread did not finish")
        record["peerErrors"] = errors
        record["packets"] = len(peers[0].packets) if peers else 0
        if peers and mode.startswith("bank-"):
            peer = peers[0]
            # Count actual received requests, including a g that disconnected
            # or stalled before its ordinary response handler could run.
            record["registerPackets"] = {name: sum(packet == b"g" if name == "g" else packet.startswith(name.encode())
                                                   for packet in peer.packets)
                                         for name in ("p", "P", "g", "G")}
            record["finalRegisters"] = {n: v.hex() for n, v in peer.registers.items()}
        record["passed"] = record["returnCode"] == expected_return and not errors
        if mode == "bank-only" and cli_args is None and lua_code is None and (driver_mode is None):
            counts = record.get("registerPackets", {})
            record["passed"] = record["passed"] and counts == {"p": 1, "P": 1, "g": 8, "G": 3}
        return record


def lua_prefix(port, qemu):
    return f'CE_GDB_HOST="127.0.0.1"; CE_GDB_PORT={port}; CE_GDB_QEMU={"true" if qemu else "false"};\n'


def qemu_case(driver, container, temp_dir, mode="qemu", bank_only=False):
    """Bridge QEMU's stdio RSP without exposing a listener inside a container."""
    executable = "/usr/bin/qemu-system-aarch64" if container else shutil.which("qemu-system-aarch64")
    if not executable:
        return {"name": "qemu-arm64", "passed": False, "output": "qemu-system-aarch64 unavailable"}
    token = "cecompat-gdb-" + uuid.uuid4().hex
    # Use a relative UNIX socket name locally; deep CI checkout paths can exceed
    # sockaddr_un's path limit even though ordinary filesystem paths are valid.
    monitor = ("/var/tmp/" if container else "") + token + ".monitor"
    prefix = ["podman", "exec", "-i", container] if container else []
    command = [*prefix, "timeout", "45s", "nice", "-n", "10", executable,
               "-machine", "virt", "-cpu", "cortex-a57", "-smp", "1", "-m", "64M",
               "-display", "none", "-serial", "none", "-nic", "none", "-qmp",
               f"unix:{monitor},server=on,wait=off", "-S", "-gdb", "stdio"]
    errors = []
    register_proxy = []
    started = time.monotonic()
    with tempfile.TemporaryFile(dir=temp_dir) as stderr, socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        port = listener.getsockname()[1]
        guest = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, cwd=temp_dir)

        def bridge():
            try:
                connection, _ = listener.accept()
                with connection, selectors.DefaultSelector() as selector:
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    def to_guest(data):
                        guest.stdin.write(data)
                        guest.stdin.flush()
                    proxy = WholeRegisterProxy(to_guest, connection.sendall, frame) if bank_only else None
                    if proxy:
                        register_proxy.append(proxy)
                    selector.register(connection, selectors.EVENT_READ, "client")
                    selector.register(guest.stdout, selectors.EVENT_READ, "guest")
                    end = time.monotonic() + 40
                    while time.monotonic() < end:
                        for key, _ in selector.select(1):
                            if key.data == "client":
                                data = connection.recv(65536)
                                if not data:
                                    return
                                if proxy:
                                    proxy.feed_client(data)
                                else:
                                    to_guest(data)
                            else:
                                data = os.read(guest.stdout.fileno(), 65536)
                                if not data:
                                    return
                                if proxy:
                                    proxy.feed_guest(data)
                                else:
                                    connection.sendall(data)
                    errors.append("bridge deadline exceeded")
            except Exception as error:
                errors.append(repr(error))

        worker = threading.Thread(target=bridge, daemon=True)
        worker.start()
        try:
            client_mode = "qemu-bank" if mode == "qemu" and bank_only else mode
            client = [str(driver), client_mode, "127.0.0.1", str(port)]
            if mode == "qemu-lua":
                code = Path(__file__).with_name("gdb_lua_checks.lua").read_text()
                client = [str(driver), "lua", "-e", lua_prefix(port, True) + ("CE_GDB_BANK_ONLY=true;\n" if bank_only else "") + code]
            result = subprocess.run(client,
                                    capture_output=True, text=True, timeout=35)
            record = {"name": "qemu-arm64" if mode == "qemu" else mode, "returnCode": result.returncode,
                      "output": result.stdout + result.stderr}
        except subprocess.TimeoutExpired:
            record = {"name": "qemu-arm64", "returnCode": -1, "output": "guest driver exceeded deadline"}
        finally:
            # Stop only this uniquely named guest, never unrelated QEMU/user processes.
            quit_code = ("import socket,sys,json; s=socket.socket(socket.AF_UNIX); "
                         "s.settimeout(2); s.connect(sys.argv[1]); f=s.makefile('rb'); "
                         "json.loads(f.readline()); s.sendall(b'{\"execute\":\"qmp_capabilities\"}\\n'); "
                         "json.loads(f.readline()); s.sendall(b'{\"execute\":\"quit\"}\\n'); "
                         "f.readline(); s.close()")
            control = ["podman", "exec", container, "python3"] if container else ["python3"]
            try:
                subprocess.run([*control, "-c", quit_code, monitor], capture_output=True, timeout=5, cwd=temp_dir)
                guest.wait(timeout=6)
            except (subprocess.TimeoutExpired, OSError):
                # Outer timeout owns the guest even if the control monitor is unavailable.
                guest.wait(timeout=50)
            worker.join(4)
            if worker.is_alive():
                errors.append("bridge did not finish")
            guest.stdin.close()
            guest.stdout.close()
            if container:
                cleanup = subprocess.run([*control, "-c", "from pathlib import Path; import sys; Path(sys.argv[1]).unlink(missing_ok=True)", monitor],
                                         capture_output=True, text=True, timeout=3)
                if cleanup.returncode:
                    errors.append("owned monitor cleanup failed: " + cleanup.stderr)
            else:
                (temp_dir / monitor).unlink(missing_ok=True)
            stderr.seek(0)
            record["guestLog"] = stderr.read().decode(errors="replace")
            record["guestExit"] = guest.returncode
            record["peerErrors"] = errors
            record["seconds"] = round(time.monotonic() - started, 3)
            record["command"] = command
            record["scope"] = "Bare-metal ARM64 QEMU RAM and vCPU; not Linux guest processes or MMU mapping"
            record["passed"] = record["returnCode"] == 0 and guest.returncode == 0 and not errors
            if bank_only:
                record["name"] += "-bank-only"
                counts = register_proxy[0].packets if register_proxy else {}
                record["registerProxy"] = counts
                record["passed"] = record["passed"] and counts.get("p") == 1 and counts.get("P") == 1 and counts.get("g", 0) > 0 and counts.get("G", 0) > 0
                record["scope"] += "; individual-register packets disabled by an independently framed proxy; all g/G values come from QEMU"
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=Path)
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--raw-only", action="store_true")
    parser.add_argument("--require-qemu", action="store_true")
    parser.add_argument("--qemu-container")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    driver = (args.driver or build / "gdb_transport_integration").resolve()
    temp_dir = Path(os.environ.get("TMPDIR", build / ".ci-tmp"))
    temp_dir.mkdir(parents=True, exist_ok=True)
    records = []
    raw = ["raw-hex", "raw-escape", "raw-rle", "raw-request-retry", "raw-response-retry",
           "raw-console", "raw-bad-prefix", "raw-bad-rle", "raw-bad-escape",
           "raw-timeout", "raw-cancel", "raw-eof", "raw-short", "raw-error", "raw-oversized"]
    cases = [(mode, None) for mode in raw]
    if not args.raw_only:
        cases += [(mode, None) for mode in ("bank-only", "bank-read-only", "bank-write-only",
                  "bank-unavailable", "bank-truncated", "bank-misaligned", "bank-oversized",
                  "bank-invalid", "bank-p-error", "bank-p-malformed", "bank-g-error", "bank-G-error", "bank-too-large",
                  "bank-disconnect", "bank-stall")]
        cases += [(mode, "xml-fail") for mode in
                  ("xml-cycle", "xml-duplicate", "xml-missing-bits", "xml-missing-arch")]
        cases += [(mode, None) for mode in ("xml", "chunks", "partial-write", "adapter")]
        cases += [("xml-namespace", "xml"), ("adapter-bad-stop", "adapter-fail"), ("adapter-bad-map", "adapter-fail")]
        cases += [("xml-dtd-default", "xml")]
        cases += [("adapter-exited", "adapter-dead")]
        cases += [("adapter-width", None), ("adapter-endian-conflict", None), ("adapter-high", None)]
    for mode, driver_mode in cases:
        record = run_peer_case(driver, mode, driver_mode)
        records.append(record)
        print(("PASS " if record["passed"] else "FAIL ") + mode, flush=True)
        if not record["passed"]:
            print(record["output"], record["peerErrors"], flush=True)
    if not args.raw_only:
        symbols = subprocess.run(["nm", "-D", "--defined-only", str(build / "libcecore.so")],
                                 capture_output=True, text=True, timeout=5)
        record = {"name": "private-xml-linkage", "returnCode": symbols.returncode,
                  "passed": symbols.returncode == 0 and "tinyxml2" not in symbols.stdout}
        records.append(record)
        print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
        cli_cases = [
            ("cli-info", ["info", "--be"], "architecture=aarch64"),
            ("cli-read", ["read", "0x1000", "12"], "112233445566778899aabbcc"),
            ("cli-write", ["write", "0x1000", "E012341234"], "Wrote 5 bytes"),
            ("cli-reg", ["reg", "x0"], "x0=e012341234567890"),
            ("cli-edit-reg", ["reg", "x0", "1234567890abcdef"], "x0=1234567890abcdef"),
            ("cli-scan", ["scan", "0x1000", "4096", "11 22 33 44"], "0x1000"),
            ("cli-scan-be-i32", ["scan", "0x1000", "4", "287454020", "--type", "i32", "--be"], "0x1000 = 287454020"),
            ("cli-scan-le-i32", ["scan", "0x1000", "4", "1144201745", "--type", "i32", "--le"], "0x1000 = 1144201745"),
            ("cli-scan-pointer4", ["scan", "0x1000", "4", "0x11223344", "--type", "pointer", "--be", "--width", "4"], "0x1000 = 0x11223344"),
            ("cli-scan-last-byte", ["scan", "0x1003", "1", "44"], "0x1003"),
            ("cli-high-scan", ["scan", "0x10000000000000", "4", "287454020", "--type", "i32", "--be"], "0x10000000000000 = 287454020"),
            ("cli-scan-subnormal", ["scan", "0x1000", "8", "5e-324", "--type", "double", "--be"], "0x1000 = 5e-324"),
        ]
        for mode, command, expected in cli_cases:
            record = run_peer_case(build / "cescan", mode, cli_args=command)
            record["passed"] = record["passed"] and expected in record["output"]
            records.append(record)
            print(("PASS " if record["passed"] else "FAIL ") + mode, flush=True)
            if not record["passed"]:
                print(record["output"], record["peerErrors"], flush=True)
        record = run_peer_case(build / "cescan", "cli-lua", lua_code=Path(__file__).with_name("gdb_lua_checks.lua").read_text())
        record["passed"] = record["passed"] and "GDB_LUA_RESULT=PASSED" in record["output"]
        records.append(record)
        print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
        if not record["passed"]:
            print(record["output"], record["peerErrors"], flush=True)
        for command, expected in ((["reg", "pc"], "pc=7856341200000040"),
                                  (["reg", "x0", "0102030405060708"], "x0=0102030405060708")):
            record = run_peer_case(build / "cescan", "bank-only", cli_args=command)
            record["name"] = "cli-bank-" + command[1]
            record["passed"] = record["passed"] and expected in record["output"]
            records.append(record)
            print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
        record = run_peer_case(build / "cescan", "bank-only", lua_code=Path(__file__).with_name("gdb_register_bank_checks.lua").read_text())
        record["name"] = "lua-register-bank"
        record["passed"] = record["passed"] and "GDB_LUA_BANK=PASSED" in record["output"]
        records.append(record)
        print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
        if not record["passed"]:
            print(record["output"], record["peerErrors"], flush=True)
        record = run_peer_case(build / "cescan", "cli-exited", cli_args=["info"], expected_return=1)
        records.append(record)
        print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
        code="""local base=0x10000000000000
assert(connectToGdb(CE_GDB_HOST,CE_GDB_PORT,{byteOrder='big',regions={{base=base,size=64}}}))
local scan=createMemScan(); assert(scan:firstScan(0,2,'0x11223344'))
assert(scan:getFoundCount()==1 and scan:getAddress(0)==base and scan:getValue(0)=='287454020')
assert(scan:nextScan(8,2,'0') and scan:getFoundCount()==1)
assert(disconnectProcess()); print('HIGH_GDB_LUA=PASSED')"""
        record=run_peer_case(build / "cescan", "cli-high-lua", lua_code=code)
        record["passed"]=record["passed"] and "HIGH_GDB_LUA=PASSED" in record["output"]
        records.append(record)
        print(("PASS " if record["passed"] else "FAIL ")+record["name"],flush=True)
        if not record["passed"]: print(record["output"],record["peerErrors"],flush=True)
        for command in (["read"], ["info", "extra"], ["info", "--width", "4", "--width", "8"],
                        ["info", "--le", "--be"], ["write", "0x1000", "abc"], ["scan", "0x1000", "10", "qq"],
                        ["scan", "0x1000", "4", "oops", "--type", "i32"],
                        ["scan", "0x1000", "4", "12abc", "--type", "float"],
                        ["scan", "0x1000", "4", "10", "--type", "unknown"],
                        ["info", "--type", "i32"]):
            # Validation must fail before endpoint resolution or socket connection.
            result = subprocess.run([str(build / "cescan"), "gdb", "invalid.invalid", "1", *command],
                                    capture_output=True, text=True, timeout=2)
            record = {"name": "cli-invalid-" + "-".join(command), "returnCode": result.returncode,
                      "output": result.stdout + result.stderr,
                      "passed": result.returncode == 1 and bool(result.stderr) and "GDB:" not in result.stderr}
            records.append(record)
            print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
        if args.require_qemu:
            record = qemu_case(driver, args.qemu_container, temp_dir)
            records.append(record)
            print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
            print(record["output"], record["peerErrors"], record.get("guestLog", ""), flush=True)
            for executable, mode in ((driver, "qemu"), (build / "cescan", "qemu-lua")):
                record = qemu_case(executable, args.qemu_container, temp_dir, mode, bank_only=True)
                if mode == "qemu-lua":
                    record["passed"] = record["passed"] and "GDB_LUA_RESULT=PASSED" in record["output"]
                records.append(record)
                print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
                print(record["output"], record["peerErrors"], record.get("guestLog", ""), flush=True)
            record = qemu_case(build / "cescan", args.qemu_container, temp_dir, "qemu-lua")
            record["passed"] = record["passed"] and "GDB_LUA_RESULT=PASSED" in record["output"]
            records.append(record)
            print(("PASS " if record["passed"] else "FAIL ") + record["name"], flush=True)
            print(record["output"], record["peerErrors"], record.get("guestLog", ""), flush=True)
    report = {
        "schemaVersion": 1, "createdUTC": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sourceRevision": os.environ.get("GITHUB_SHA"),
        "sourceState": "CI checkout" if os.environ.get("GITHUB_SHA") else "uncommitted worktree snapshot",
        "driver": {"path": str(driver), "sha256": hashlib.sha256(driver.read_bytes()).hexdigest()},
        "realGuestRequired": args.require_qemu, "passed": all(r["passed"] for r in records),
        "cases": records,
    }
    if not args.raw_only:
        report["binaries"] = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                              for name in ("libcecore.so", "cescan")}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
