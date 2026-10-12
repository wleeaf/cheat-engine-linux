#!/usr/bin/env python3
"""Run the real Windows fixtures through Valve Proton's own launcher.

Each Proton build uses its own launcher script, Wine, wineserver, prefix
template and environment (esync/fsync/ntsync, DXVK DLL overrides). `proton run`
creates and updates the prefix exactly as Steam does. The fixtures then start
with `proton runinprefix`: the same Proton Wine and environment without the
`steam.exe` wrapper, which exits without a running Steam client and would not
pass the console handles the fixtures use. wine_integration then exercises attach, typed writes, value and
pointer scans, Auto Assembler injection with exact undo, main-thread hardware
find-what-writes, and busy-loop allocation/protection on both PE widths.

Proton without the Steam client needs only a compat-data directory and the
client install path. The prefix lives in the build tree, never in Steam's own
compatdata. Builds that ship `files/lib/wine/i386-unix` (Proton 9 and
Experimental 11 at the time of writing) run PE32 programs on a 32-bit Unix
loader; a pure new-WoW64 build without it must use a 64-bit loader.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

from wine_fixture import build_fixture

STEAM = pathlib.Path.home() / ".local/share/Steam"


def installed_protons():
    common = STEAM / "steamapps/common"
    return sorted(p for p in common.glob("Proton*") if (p / "proton").is_file()) if common.is_dir() else []


def run_proton(build, proton, work, fixtures, report, client):
    version = (proton / "version").read_text().split()[-1] if (proton / "version").is_file() else proton.name
    # Proton ships a 32-bit Unix loader (i386-unix) unless it is a pure new-WoW64 build.
    legacy = (proton / "files/lib/wine/i386-unix").is_dir()
    entry = {"proton": proton.name, "version": version, "loader": "legacy-wine32" if legacy else "wow64",
             "status": "failed"}
    report["builds"].append(entry)
    print(f"== {proton.name} ({version}, {entry['loader']})", flush=True)
    with tempfile.TemporaryDirectory(prefix="ce-proton-", dir=work) as temporary:
        directory = pathlib.Path(temporary)
        compat = directory / "compatdata"
        compat.mkdir()
        # WINEPREFIX matches Proton's own value (with its trailing slash) so the
        # driver identifies its fixture by prefix even if Wine reparents it.
        env = dict(os.environ, STEAM_COMPAT_DATA_PATH=str(compat), WINEPREFIX=f"{compat}/pfx/",
                   STEAM_COMPAT_CLIENT_INSTALL_PATH=str(client), WINEDEBUG="-all")
        # Wine's server socket directory must not follow a relocated TMPDIR.
        env.pop("TMPDIR", None)
        launcher = directory / "proton-run"
        launcher.write_text(f'#!/bin/sh\nexec "{proton / "proton"}" runinprefix "$@"\n')
        launcher.chmod(0o755)
        server = proton / "files/bin/wineserver"
        prefix_env = dict(env, WINEPREFIX=str(compat / "pfx"))
        try:
            entry["stage"] = "prefix-initialization"
            # The steam.exe wrapper itself fails without a Steam client; the
            # prefix it set up first is what this step requires.
            boot = subprocess.run([str(proton / "proton"), "run", "cmd.exe", "/c", "exit"], env=env,
                                  capture_output=True, text=True, timeout=300)
            if not (compat / "pfx/system.reg").is_file():
                raise RuntimeError(f"Proton prefix initialization failed: {boot.stdout}\n{boot.stderr}")
            entry["stage"] = "operations"
            command = [str(build / "wine_integration"), str(launcher), *map(str, fixtures),
                       "--require-legacy-wine32" if legacy else "--require-wow64"]
            # Files, not pipes: Proton's wineserver inherits the driver's
            # descriptors and can outlive it, so a pipe might never see EOF.
            with open(directory / "out.txt", "w+") as out, open(directory / "err.txt", "w+") as err:
                try:
                    code = subprocess.run(command, env=env, stdout=out, stderr=err, timeout=300).returncode
                except subprocess.TimeoutExpired:
                    code = "timeout"
                out.seek(0)
                err.seek(0)
                stdout, stderr = out.read(), err.read()
            entry.update(exitCode=code, output=stdout, stderr=stderr)
            print(stdout, end="", flush=True)
            if stderr:
                print(stderr, end="", flush=True)
            if (code != 0 or "FAILED:" in stdout or "0 failed Wine integration checks\n" not in stdout or
                    any(f"WINE_BUSY_RESULT=PASSED programWidth={width}\n" not in stdout for width in (8, 4))):
                raise RuntimeError(f"{proton.name} compatibility checks failed")
            entry["checks"] = sum(line.startswith("OK: ") for line in stdout.splitlines())
            entry["status"] = "passed"
        finally:
            # Only this test's private prefix: Steam's games are never touched.
            if server.is_file():
                subprocess.run([str(server), "-k"], env=prefix_env, timeout=30)
                subprocess.run([str(server), "-w"], env=prefix_env, timeout=30)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--proton", type=pathlib.Path, action="append",
                        help="Proton install directory (default: every Proton in the Steam library)")
    parser.add_argument("--client-install", type=pathlib.Path,
                        help="Steam client directory (default: the local Steam install, else an empty directory)")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    build = args.build.resolve()
    protons = [p.resolve() for p in args.proton] if args.proton else installed_protons()
    if not protons:
        parser.error("no Proton install found; pass --proton DIR")
    report = {"platform": platform.platform(), "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "sourceRevision": os.environ.get("GITHUB_SHA"), "status": "failed", "builds": [],
              "driverSha256": hashlib.sha256((build / "wine_integration").read_bytes()).hexdigest()}
    try:
        # Prefixes are large; keep them on the build filesystem, not tmpfs.
        work = build / ".proton-compat"
        work.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="ce-proton-fixtures-", dir=work) as fixtures_dir:
            fixtures = [pathlib.Path(fixtures_dir) / f"ce-fixture-{bits}.exe" for bits in (64, 32)]
            for path, bits in zip(fixtures, (64, 32)):
                build_fixture(build / "cescan", path, bits)
            # Hosted runners have no Steam client; Proton then skips its
            # steamclient copies, which these fixtures do not use.
            client = args.client_install or (STEAM if STEAM.is_dir() else pathlib.Path(fixtures_dir) / "no-steam-client")
            client.mkdir(parents=True, exist_ok=True)
            report["clientInstall"] = str(client)
            # One Proton at a time: each starts its own wineserver and prefix.
            for proton in protons:
                run_proton(build, proton, work, fixtures, report, client)
        report["status"] = "passed"
    except BaseException as error:
        report["error"] = str(error)
        raise
    finally:
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"PROTON_RESULT={report['status'].upper()} builds={len(report['builds'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
