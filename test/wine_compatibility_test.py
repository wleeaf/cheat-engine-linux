#!/usr/bin/env python3
"""Run mandatory real Windows fixtures in an isolated Wine prefix."""
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("build", type=pathlib.Path)
    parser.add_argument("--wine", default=shutil.which("wine") or shutil.which("wine64"))
    parser.add_argument("--work-dir", type=pathlib.Path,
                        help="Fixture/prefix scratch directory (default: BUILD/.wine-compat)")
    loader = parser.add_mutually_exclusive_group()
    loader.add_argument("--require-wow64", action="store_true")
    loader.add_argument("--require-legacy-wine32", action="store_true")
    parser.add_argument("--report", type=pathlib.Path)
    args = parser.parse_args()
    if not args.wine:
        parser.error("Wine is required for this compatibility gate")
    build = args.build.resolve()
    for binary in ("cescan", "wine_integration"):
        if not (build / binary).is_file():
            parser.error(f"required compatibility binary is missing: {build / binary}")
    wine = pathlib.Path(args.wine).resolve()
    server = shutil.which("wineserver") or shutil.which("wineserver64")
    if not server:
        parser.error("wineserver is required to clean up the isolated test prefix")
    version = subprocess.check_output([str(wine), "--version"], text=True, timeout=15).strip()
    print(f"Testing {version} on {platform.platform()}", flush=True)
    report = {
        "wine": version, "platform": platform.platform(),
        "requireWow64": args.require_wow64,
        "requireLegacyWine32": args.require_legacy_wine32,
        "sourceRevision": os.environ.get("GITHUB_SHA"),
        "sourceRef": os.environ.get("GITHUB_REF"),
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "failed",
        "stage": "fixture-build",
        "driverSha256": hashlib.sha256((build / "wine_integration").read_bytes()).hexdigest(),
        "assemblerSha256": hashlib.sha256((build / "cescan").read_bytes()).hexdigest(),
        "coreSha256": hashlib.sha256((build / "libcecore.so").read_bytes()).hexdigest(),
    }
    try:
        # A fresh Wine prefix can occupy hundreds of megabytes. /tmp is often
        # tmpfs; keep those files with the build instead of consuming scarce RAM.
        work = (args.work_dir or build / ".wine-compat").resolve()
        work.mkdir(parents=True, exist_ok=True)
        report["workDirectory"] = str(work)
        with tempfile.TemporaryDirectory(prefix="ce-wine-compatibility-", dir=work) as temporary:
            directory = pathlib.Path(temporary)
            prefix = directory / "prefix"
            prefix.mkdir()
            env = dict(os.environ, WINEPREFIX=str(prefix), WINEARCH="win64", WINEDEBUG="-all")
            # Python/compiler storage may be relocated for space. Wine's server
            # socket directory is independent; Wine 9 can abort with an explicit
            # TMPDIR override. Keep its default while retaining the isolated prefix.
            env.pop("TMPDIR", None)
            paths = [directory / f"ce-fixture-{bits}.exe" for bits in (64, 32)]
            for path, bits in zip(paths, (64, 32)):
                build_fixture(build / "cescan", path, bits)
            report["fixtures"] = [{"bits": bits, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                  for path, bits in zip(paths, (64, 32))]
            try:
                # This also checks that the prefix has the required loader and APIs.
                report["stage"] = "prefix-initialization"
                boot = subprocess.run([str(wine), "wineboot", "-u"], env=env,
                                      capture_output=True, text=True, timeout=120)
                if boot.returncode:
                    raise RuntimeError(f"Wine prefix initialization failed: {boot.stdout}\n{boot.stderr}")
                report["stage"] = "operations"
                command = [str(build / "wine_integration"), str(wine), *map(str, paths)]
                if args.require_wow64:
                    command.append("--require-wow64")
                if args.require_legacy_wine32:
                    command.append("--require-legacy-wine32")
                result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=150)
                report["output"] = result.stdout
                report["stderr"] = result.stderr
                print(result.stdout, end="", flush=True)
                if result.stderr:
                    print(result.stderr, end="", flush=True)
                if result.returncode:
                    raise RuntimeError(f"Wine compatibility checks failed with exit code {result.returncode}")
                if (any(f"WINE_BUSY_RESULT=PASSED programWidth={width}\n" not in result.stdout for width in (8, 4)) or
                        "FAILED:" in result.stdout or "0 failed Wine integration checks\n" not in result.stdout):
                    raise RuntimeError("Required busy Windows memory-operation checks did not complete for both program ABIs")
            finally:
                # This affects only this test's prefix, never the user's Wine apps.
                # The server can already be gone after the final client exits.
                primary_failure = sys.exc_info()[0] is not None
                cleanup_errors = []
                try:
                    killed = subprocess.run([server, "-k"], env=env, timeout=15)
                    if killed.returncode < 0:
                        cleanup_errors.append(f"isolated wineserver cleanup crashed: {killed.returncode}")
                    subprocess.run([server, "-w"], env=env, check=True, timeout=15)
                except (OSError, subprocess.SubprocessError) as error:
                    cleanup_errors.append(str(error))
                if cleanup_errors:
                    report["cleanupErrors"] = cleanup_errors
                    if not primary_failure:
                        raise RuntimeError("; ".join(cleanup_errors))
            report["status"] = "passed"
            report["stage"] = "complete"
    except BaseException as error:
        report["error"] = str(error)
        if isinstance(error, subprocess.TimeoutExpired):
            def decoded(value):
                return value.decode(errors="replace") if isinstance(value, bytes) else value or ""
            report["timeoutOutput"] = decoded(error.stdout)
            report["timeoutStderr"] = decoded(error.stderr)
        raise
    finally:
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
