#!/usr/bin/env python3
"""Check actual objcopy debug links using nm references and independent CRC32."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shlex
import struct
import subprocess
import tempfile
import zlib


def command(argv, **kwargs):
    return subprocess.run([str(arg) for arg in argv], check=True, capture_output=True,
                          text=True, timeout=30, **kwargs).stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--require-i386", action="store_true")
    parser.add_argument("--container", help="also test global debug directories in an existing private container")
    parser.add_argument("--container-arch", choices=("i386", "arm64"), action="append",
                        help="container fixture ISA (repeatable; defaults to i386; ARM64 needs its cross toolchain)")
    parser.add_argument("--shared-image", action="store_true",
                        help="also run an idle i386 target sharing its ELF inode with the host; uses the container's cached image")
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if (args.container_arch or args.shared_image) and not args.container:
        parser.error("container checks require --container")
    build = args.build.resolve()
    report = {"suite": "elf-separate-debug-symbols", "status": "failed",
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "sourceRevision": os.environ.get("GITHUB_SHA"),
              "sourceRef": os.environ.get("GITHUB_REF"), "platform": platform.platform(),
              "targets": []}
    try:
        report["coreSha256"] = hashlib.sha256((build / "libcecore.so").read_bytes()).hexdigest()
        report["driverSha256"] = hashlib.sha256((build / "elf_symbol_integration").read_bytes()).hexdigest()
        report["gateSha256"] = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="ce-elf-debug-") as temporary:
            root = pathlib.Path(temporary)
            src = root / "fixture.c"
            src.write_text("__attribute__((used,noinline)) static int ce_debug_hidden(int x) { return x*3; }\n"
                           "int ce_debug_export(int x) { return ce_debug_hidden(x)+1; }\n")
            variants = [("native", [])]
            if args.require_i386:
                variants.append(("i386", ["-m32"]))
            for name, flags in variants:
                directory = root / name
                directory.mkdir()
                image, debug = directory / "fixture.so", directory / "fixture.debug"
                command(["gcc", *flags, "-g", "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none",
                         src, "-o", image])
                symbols = command(["nm", "-a", image])
                hidden = next(int(row.split()[0], 16) for row in symbols.splitlines()
                              if row.split()[-1] == "ce_debug_hidden")
                command(["objcopy", "--only-keep-debug", image, debug])
                command(["strip", "--strip-all", image])
                command(["objcopy", "--add-gnu-debuglink=" + str(debug), image])
                original = debug.read_bytes()
                target = {"name": name, "status": "failed", "checks": [],
                          "elfClass": image.read_bytes()[4],
                          "elfMachine": struct.unpack_from("<H", image.read_bytes(), 18)[0],
                          "referenceSymbolValue": hidden, "loadBase": 0x100000,
                          "imageSha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                          "debugSha256": hashlib.sha256(original).hexdigest(),
                          "debugCrc32": zlib.crc32(original)}
                report["targets"].append(target)

                def probe(label, expected):
                    output = command([build / "elf_symbol_integration", image,
                                      "ce_debug_hidden", "0x100000", str(expected)])
                    if "ELF_SYMBOL_RESULT=PASSED " not in output:
                        raise RuntimeError(label + ": missing required result")
                    target["checks"].append(label)
                    print("OK: " + name + " " + label, flush=True)

                probe("matching debuglink resolves stripped static symbols at the correct base", hidden + 0x100000)
                debug.write_bytes(original + b"changed build")
                probe("mismatched full-file checksum rejects an otherwise readable symbol table", 0)
                fallback = directory / ".debug"
                fallback.mkdir()
                (fallback / debug.name).write_bytes(original)
                probe("a wrong adjacent file does not hide the matching .debug fallback", hidden + 0x100000)
                debug.unlink()
                probe("the .debug sidecar works without an adjacent copy", hidden + 0x100000)
                (fallback / debug.name).unlink()
                probe("a missing separate file keeps stripped symbols unavailable", 0)
                debug.write_bytes(original)

                # Change only the debuglink section. Checksums are independent
                # of our implementation and remain objcopy/zlib generated.
                section = directory / "debuglink.bin"
                command(["objcopy", "--dump-section", ".gnu_debuglink=" + str(section), image])
                valid_link = section.read_bytes()
                if struct.unpack("<I", valid_link[-4:])[0] != zlib.crc32(original):
                    raise RuntimeError("objcopy debuglink checksum differs from independent zlib CRC32")
                def replace_link(data):
                    section.write_bytes(data)
                    command(["objcopy", "--update-section", ".gnu_debuglink=" + str(section), image])

                replace_link(valid_link[:-4])
                probe("a missing checksum is rejected", 0)
                replace_link(valid_link[:-1])
                probe("a truncated checksum is rejected", 0)
                escape = b"../" + name.encode() + b"/fixture.debug\0"
                escape += b"\0" * (-len(escape) % 4) + struct.pack("<I", zlib.crc32(original))
                replace_link(escape)
                probe("debuglink directory traversal is rejected even with a matching checksum", 0)
                replace_link(valid_link)
                probe("valid debuglink remains usable after malformed inputs", hidden + 0x100000)
                wrong_machine = bytearray(original)
                wrong_machine[18:20] = struct.pack("<H", 183 if struct.unpack_from("<H", original, 18)[0] != 183 else 62)
                debug.write_bytes(wrong_machine)
                replace_link(valid_link[:-4] + struct.pack("<I", zlib.crc32(wrong_machine)))
                probe("a checksummed sidecar for a different ISA is rejected", 0)
                large_debug = original + b"\0" * (192 * 1024)
                debug.write_bytes(large_debug)
                replace_link(valid_link[:-4] + struct.pack("<I", zlib.crc32(large_debug)))
                probe("a matching sidecar larger than the checksum buffer resolves", hidden + 0x100000)
                corrupt_debug = bytearray(large_debug)
                corrupt_debug[-1] = 1
                debug.write_bytes(corrupt_debug)
                probe("checksum validation includes bytes after the last full buffer", 0)
                target["status"] = "passed"
        if args.container:
            for isa in args.container_arch or ["i386"]:
                container_checks(args.container, build, report, isa)
        if args.shared_image:
            shared_image_checks(args.container, build, report)
        report["status"] = "passed"
    except (OSError, ValueError, StopIteration, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.CalledProcessError):
            report.update(output=error.stdout, stderr=error.stderr, exitCode=error.returncode)
            print(error.stdout or "", end="", flush=True)
            print(error.stderr or "", end="", flush=True)
        raise SystemExit(str(error)) from error
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")


def container_checks(container, build, report, isa="i386"):
    """Generated files stay inside the named container's private filesystem."""
    def run(*argv, **kwargs):
        return command(["podman", "exec", "-i", container, "nice", "-n", "10", *argv], **kwargs)

    pid = int(command(["podman", "inspect", "--format", "{{.State.Pid}}", container]).strip())
    directory = pathlib.Path(run("mktemp", "-d", "/var/tmp/ce-elf-debug.XXXXXX").strip())
    if directory.parent != pathlib.Path("/var/tmp") or not directory.name.startswith("ce-elf-debug."):
        raise RuntimeError("invalid private container fixture directory")
    global_dir = pathlib.Path("/usr/lib/debug") / directory.relative_to("/")
    id_dir = None
    owns_id_file = False
    owns_global_dir = False
    target = {"name": "container-i386", "status": "failed", "container": container,
              "rootPid": pid, "checks": []}
    report["targets"].append(target)
    target["name"] = "container-" + isa
    compiler, flags, prefix = (("gcc", ["-m32"], "") if isa == "i386" else
                               ("aarch64-linux-gnu-gcc", [], "aarch64-linux-gnu-"))
    try:
        image, debug = directory / "fixture.so", directory / "fixture.debug"
        source = ("__attribute__((used,noinline)) static int ce_debug_hidden(int x) { return x*3; }\n"
                  "int ce_debug_export(int x) { return ce_debug_hidden(x)+1; }\n")
        run(compiler, *flags, "-g", "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=none",
            "-x", "c", "-", "-o", image, input=source)
        hidden = next(int(row.split()[0], 16) for row in run(prefix + "nm", "-a", image).splitlines()
                      if row.split()[-1] == "ce_debug_hidden")
        run(prefix + "objcopy", "--only-keep-debug", image, debug)
        run(prefix + "strip", "--strip-all", image)
        run(prefix + "objcopy", "--add-gnu-debuglink=" + str(debug), image)
        if (pathlib.Path(f"/proc/{pid}/root") / global_dir.relative_to("/")).exists():
            raise RuntimeError("refusing to replace an existing global debug fixture directory")
        owns_global_dir = True
        run("mkdir", "-p", global_dir)
        run("mv", debug, global_dir / debug.name)
        target_path = pathlib.Path(f"/proc/{pid}/root") / image.relative_to("/")
        target["imageSha256"] = hashlib.sha256(target_path.read_bytes()).hexdigest()
        target["elfClass"] = target_path.read_bytes()[4]
        target["elfMachine"] = struct.unpack_from("<H", target_path.read_bytes(), 18)[0]
        target["debuglinkReferenceSymbolValue"] = hidden

        def probe(label, expected):
            output = command([build / "elf_symbol_integration", target_path,
                              "ce_debug_hidden", "0x100000", str(expected)])
            if "ELF_SYMBOL_RESULT=PASSED " not in output:
                raise RuntimeError(label + ": missing required result")
            target["checks"].append(label)
            print("OK: " + target["name"] + " " + label, flush=True)

        probe("target-root global debuglink directory resolves a stripped static symbol", hidden + 0x100000)
        run("sh", "-c", 'printf "wrong build" >> "$1"', "sh", str(global_dir / debug.name))
        probe("a corrupt target-root global sidecar is rejected", 0)
        run("rm", "--", global_dir / debug.name)

        # A unique explicit ID avoids touching or depending on installed packages.
        build_id = hashlib.sha256(str(directory).encode()).hexdigest()[:40]
        id_dir = pathlib.Path("/usr/lib/debug/.build-id") / build_id[:2]
        id_file = id_dir / (build_id[2:] + ".debug")
        run(compiler, *flags, "-g", "-shared", "-fPIC", "-nostdlib", "-Wl,--build-id=0x" + build_id,
            "-x", "c", "-", "-o", image, input=source)
        hidden = next(int(row.split()[0], 16) for row in run(prefix + "nm", "-a", image).splitlines()
                      if row.split()[-1] == "ce_debug_hidden")
        run(prefix + "objcopy", "--only-keep-debug", image, debug)
        run(prefix + "strip", "--strip-all", image)
        run("mkdir", "-p", id_dir)
        if (pathlib.Path(f"/proc/{pid}/root") / id_file.relative_to("/")).exists():
            raise RuntimeError("refusing to replace an existing build-ID debug file")
        owns_id_file = True
        run("cp", debug, id_file)
        target["buildId"] = build_id
        target["buildIdReferenceSymbolValue"] = hidden
        target["buildIdImageSha256"] = hashlib.sha256(target_path.read_bytes()).hexdigest()
        target["buildIdDebugSha256"] = hashlib.sha256(
            (pathlib.Path(f"/proc/{pid}/root") / id_file.relative_to("/")).read_bytes()).hexdigest()
        probe("target-root build-ID lookup resolves the matching separate ELF", hidden + 0x100000)
        note = struct.pack("<III", 4, 20, 3) + b"GNU\0" + bytes.fromhex(build_id[:-2] + ("00" if build_id[-2:] != "00" else "01"))
        note_file = directory / "wrong-note.bin"
        command(["podman", "exec", "-i", container, "sh", "-c", 'cat > "$1"', "sh", str(note_file)],
                input=note.decode("latin1"), encoding="latin1")
        run(prefix + "objcopy", "--update-section", ".note.gnu.build-id=" + str(note_file), id_file)
        probe("a readable debug file stored under the wrong build-ID name is rejected", 0)
        run(prefix + "objcopy", "--remove-section", ".note.gnu.build-id", id_file)
        probe("a build-ID debug candidate with its identity note removed is rejected", 0)
        run("cp", debug, id_file)
        probe("restoring the matching build-ID candidate restores symbol resolution", hidden + 0x100000)
        target["status"] = "passed"
    finally:
        if owns_id_file:
            # Remove only our uniquely named file, never the shared prefix directory.
            run("rm", "-f", "--", id_dir / (build_id[2:] + ".debug"))
        run("rm", "-rf", "--", directory)
        if owns_global_dir:
            run("rm", "-rf", "--", global_dir)


def shared_image_checks(template, build, report):
    """Keep the library inode shared, but place its debug file only in the guest."""
    from native_namespace_gate import line
    image_id = command(["podman", "inspect", "--format", "{{.Image}}", template]).strip()
    with tempfile.TemporaryDirectory(prefix="ce-elf-shared-") as temporary:
        root = pathlib.Path(temporary)
        source, image, debug = root / "fixture.c", root / "fixture", root / "fixture.debug"
        source.write_text('''
__attribute__((used,noinline)) static int ce_debug_hidden(int x) { return x*3; }
void _start(void) {
    const char message[] = "CE_SHARED_DEBUG_READY\\n";
    char token;
    long count;
    __asm__ volatile("int $0x80" : : "a"(4), "b"(1), "c"(message), "d"(sizeof(message)-1) : "memory");
    __asm__ volatile("int $0x80" : "=a"(count) : "0"(3), "b"(0), "c"(&token), "d"(1) : "memory");
    __asm__ volatile("int $0x80" : : "a"(1), "b"(count == 1 && token == 'x' ? 0 : 7) : "memory");
    __builtin_unreachable();
}
''')
        command(["gcc", "-m32", "-g", "-fno-pie", "-fno-stack-protector", "-nostdlib", "-static",
                 "-Wl,--build-id=none", source, "-o", image])
        hidden = next(int(row.split()[0], 16) for row in command(["nm", "-a", image]).splitlines()
                      if row.split()[-1] == "ce_debug_hidden")
        command(["objcopy", "--only-keep-debug", image, debug])
        command(["strip", "--strip-all", image])
        command(["objcopy", "--add-gnu-debuglink=" + str(debug), image])
        stored = root / "stored.debug"
        debug.rename(stored)
        global_debug = pathlib.Path("/usr/lib/debug") / debug.relative_to("/")
        if global_debug.exists():
            raise RuntimeError("shared fixture unexpectedly has host global debuginfo")
        target = {"name": "shared-image-i386", "status": "failed", "checks": [],
                  "imageSha256": hashlib.sha256(image.read_bytes()).hexdigest(),
                  "debugSha256": hashlib.sha256(stored.read_bytes()).hexdigest(),
                  "referenceSymbolValue": hidden}
        report["targets"].append(target)
        container = None
        fixture = None
        try:
            container = command(["podman", "create", "--pull=never", "--network=none",
                                 "--security-opt", "label=disable", "--entrypoint", "/bin/sleep",
                                 "--volume", f"{root}:{root}:ro", image_id, "300"]).strip()
            target["containerId"] = container
            command(["podman", "start", container])
            command(["podman", "exec", container, "mkdir", "-p", global_debug.parent])
            command(["podman", "exec", container, "cp", stored, global_debug])
            init_pid = int(command(["podman", "inspect", "--format", "{{.State.Pid}}", container]))
            namespace = os.readlink(f"/proc/{init_pid}/ns/pid")
            fixture = subprocess.Popen(["podman", "exec", "-i", container, "nice", "-n", "10", "sh", "-c",
                                        "echo CE_NAMESPACE_PID $$; exec " + shlex.quote(str(image))],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            ready = line(fixture.stdout).split()
            if len(ready) != 2 or ready[0] != "CE_NAMESPACE_PID":
                raise RuntimeError("invalid shared fixture PID handshake")
            inner_pid = int(ready[1])
            if line(fixture.stdout) != "CE_SHARED_DEBUG_READY":
                raise RuntimeError("shared fixture did not enter its kernel wait")
            pid = None
            for entry in pathlib.Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    if os.readlink(entry / "ns/pid") != namespace:
                        continue
                    chain = next([int(value) for value in row.split()[1:]]
                                 for row in (entry / "status").read_text(errors="replace").splitlines()
                                 if row.startswith("NSpid:"))
                    if chain[-1] == inner_pid:
                        pid = int(entry.name)
                        target["namespacePidChain"] = chain
                        break
                except (OSError, StopIteration):
                    continue
            if pid is None or pid == inner_pid:
                raise RuntimeError("shared fixture is not in a distinct visible PID namespace")
            rooted = pathlib.Path(f"/proc/{pid}/root") / image.relative_to("/")
            if not os.path.samefile(rooted, image):
                raise RuntimeError("shared fixture does not use the identical host inode")
            target["checks"].append("the target and host ELF paths share the same inode")
            output = command([build / "elf_symbol_integration", "--process", str(pid),
                              "ce_debug_hidden", str(hidden)])
            if "ELF_SYMBOL_RESULT=PASSED " not in output:
                raise RuntimeError("shared process symbol lookup did not verify its address")
            target["checks"].append("loadProcess finds target-only global debuginfo for the shared ELF")
            target["output"] = output
            fixture.stdin.write(b"x"); fixture.stdin.flush()
            if fixture.wait(timeout=5):
                raise RuntimeError("shared target did not finish its original kernel read normally")
            target["checks"].append("the original target read and normal process completion are preserved")
            target["status"] = "passed"
            print("OK: shared-image-i386 target-only debuginfo resolves and the process completes normally", flush=True)
        finally:
            if fixture is not None and fixture.poll() is None:
                fixture.terminate()
                try:
                    fixture.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    fixture.kill(); fixture.wait(timeout=5)
            if container is not None:
                command(["podman", "rm", "-f", container])


if __name__ == "__main__":
    main()
