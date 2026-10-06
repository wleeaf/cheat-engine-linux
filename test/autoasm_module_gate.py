#!/usr/bin/env python3
"""Require live Auto Assembler module refresh and symbol ownership checks."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    build = args.build.resolve()
    report = {'suite': 'autoasm-live-module-lifecycle', 'passed': False,
              'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'platform': platform.platform(), 'output': ''}
    try:
        paths = [build / name for name in ('compatibility_integration',
                 'compatibility_fixture64', 'compatibility_fixture32')]
        report['binarySha256'] = {}
        for path in [*paths, build / 'libcecore.so']:
            with path.open('rb') as source:
                report['binarySha256'][path.name] = hashlib.file_digest(source, 'sha256').hexdigest()
        command = list(map(str, paths))
        report['command'] = command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding='utf-8', errors='replace', timeout=50)
        report.update(exitCode=result.returncode, output=result.stdout)
        summaries = re.findall(r'^AA_MODULE_RESULT width=(\d+) checks=(\d+) failures=(\d+)$', result.stdout, re.M)
        if result.returncode or summaries != [('8', '24', '0'), ('4', '24', '0')]:
            raise RuntimeError('Required x86-64/i386 module lifecycle profiles failed or are incomplete')
        for width in (8, 4):
            checks = re.findall(rf'^AA_MODULE {width} (OK|FAILED):', result.stdout, re.M)
            if len(checks) != 24 or any(check != 'OK' for check in checks):
                raise RuntimeError('Missing or failed live module assertions')
        if not re.search(r'^0 failed live integration checks$', result.stdout, re.M):
            raise RuntimeError('The existing live process integration suite did not complete')
        report.update(passed=True, targetWidths=[8, 4], moduleChecks=48)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        report.update(output=output, timedOut=True, failure='Live module lifecycle checks exceeded their deadline')
    except (OSError, RuntimeError) as error:
        report['failure'] = str(error)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print('AA_MODULE_GATE=' + ('PASSED' if report['passed'] else 'FAILED'))
    if not report['passed']:
        print(report.get('failure', 'Unknown failure'))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
