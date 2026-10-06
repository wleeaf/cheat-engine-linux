#!/usr/bin/env python3
"""Exercise production Qt actions against independent RSP peers and real QEMU."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from gdb_transport_gate import run_peer_case, qemu_case


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('build', type=Path)
    parser.add_argument('--require-qemu', action='store_true')
    parser.add_argument('--qemu-container')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    build = args.build.resolve()
    driver = build / 'gui_lifecycle_smoke'
    root = Path(os.environ.get('TMPDIR', build / '.ci-tmp'))
    root.mkdir(parents=True, exist_ok=True)
    records = []
    os.environ.setdefault('CE_GDB_SCREENSHOT_DIR', str(build / 'compatibility-evidence' / 'gdb-gui'))
    for peer, mode in [('xml-duplicate', 'gdb-fail'), ('gui-cancel', 'gdb-cancel'),
                       ('gui-pointer', 'gdb-pointer'), ('gui-unknown', 'gdb-unknown'),
                       ('gui-unavailable', 'gdb-unavailable'), ('bank-only', 'gdb-bank')]:
        record = run_peer_case(driver, peer, mode)
        record['passed'] = record['passed'] and 'GDB_GUI_RESULT=PASSED' in record['output']
        records.append(record)
        print(('PASS ' if record['passed'] else 'FAIL ') + mode, flush=True)
        if not record['passed']:
            print(record['output'], record['peerErrors'], flush=True)
    if args.require_qemu:
        os.environ.setdefault('CE_GDB_SCREENSHOT_DIR', str(build / 'compatibility-evidence' / 'gdb-gui'))
        with tempfile.TemporaryDirectory(prefix='gdb-gui-', dir=root) as temp:
            record = qemu_case(driver, args.qemu_container, Path(temp), 'qemu-gui')
        record['passed'] = record['passed'] and 'GDB_GUI_RESULT=PASSED' in record['output']
        records.append(record)
        print(('PASS ' if record['passed'] else 'FAIL ') + record['name'], flush=True)
        print(record['output'], record['peerErrors'], record.get('guestLog', ''), flush=True)
    report = {'schemaVersion': 1, 'createdUTC': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'sourceRevision': os.environ.get('GITHUB_SHA'),
              'sourceState': 'CI checkout' if os.environ.get('GITHUB_SHA') else 'uncommitted worktree snapshot',
              'realGuestRequired': args.require_qemu,
              'binaries': {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                           for name in ('gui_lifecycle_smoke', 'libcecore.so', 'cheatengine')},
              'passed': all(r['passed'] for r in records), 'cases': records}
    screenshots = Path(os.environ.get('CE_GDB_SCREENSHOT_DIR', build / 'compatibility-evidence' / 'gdb-gui'))
    report['screenshots'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in sorted(screenshots.glob('*.png'))} if args.require_qemu else {}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
