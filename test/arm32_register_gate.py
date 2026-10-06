#!/usr/bin/env python3
"""Require ARM/Thumb registers, traps and private memory syscalls under real Linux kernels."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
from fullsystem_vm import write_initramfs


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('init', type=Path)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('--profile', choices=('arm32', 'arm64-compat'), required=True)
    parser.add_argument('--kernel-sha256', required=True)
    parser.add_argument('--qemu')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report = {'suite': 'arm32-native-register-breakpoints-private-memory', 'passed': False, 'profile': args.profile,
              'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'hostPlatform': platform.platform(),
              'output': '', 'resources': {'cpus': 1, 'ramMiB': 128}}
    try:
        report['binarySha256'] = {str(p): sha(p) for p in (args.kernel, args.init, args.fixture)}
        if sha(args.kernel) != args.kernel_sha256.lower():
            raise RuntimeError('Required kernel hash does not match')
        for path, bits, machine in ((args.init, 1 if args.profile == 'arm32' else 2, 40 if args.profile == 'arm32' else 183), (args.fixture, 1, 40)):
            with path.open('rb') as stream:
                header = stream.read(20)
            if len(header) != 20 or header[:6] != b'\x7fELF' + bytes([bits, 1]) or int.from_bytes(header[18:20], 'little') != machine:
                raise RuntimeError('Required driver/fixture has the wrong actual ELF architecture')
        ramfs = args.output.with_suffix('.initramfs.gz')
        write_initramfs(ramfs, [('init', args.init), ('fixture', args.fixture)])
        qemu = args.qemu or ('qemu-system-arm' if args.profile == 'arm32' else 'qemu-system-aarch64')
        report['qemu'] = subprocess.check_output([qemu, '--version'], text=True, timeout=10).splitlines()[0]
        command = [qemu, '-machine', 'virt', '-cpu', 'cortex-a15' if args.profile == 'arm32' else 'max',
                   '-smp', '1', '-m', '128M', '-nographic', '-nic', 'none', '-monitor', 'none', '-no-reboot',
                   '-kernel', str(args.kernel), '-initrd', str(ramfs), '-append', 'console=ttyAMA0 rdinit=/init panic=1']
        report['command'] = command
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=70)
        output = result.stdout.decode(errors='replace').replace('\r', '')
        report.update(exitCode=result.returncode, output=output)
        if 'Kernel panic - not syncing:' in output or 'Internal error: Oops' in output:
            raise RuntimeError('Actual ARM guest reported a kernel panic or oops')
        if 'runtime error:' in output or 'UndefinedBehaviorSanitizer:' in output:
            raise RuntimeError('Sanitizer reported undefined behavior in the guest')
        summary = re.findall(r'^ARM32_REG_RESULT mode=(ARM|THUMB) checks=(\d+) failures=(\d+)$', output, re.M)
        if result.returncode or summary != [('ARM', '26', '0'), ('THUMB', '26', '0')] or 'ARM32_REG_VM_RESULT=PASSED failures=0\n' not in output:
            raise RuntimeError('Required actual ARM and Thumb operation profiles did not complete')
        for mode in ('ARM', 'THUMB'):
            checks = re.findall(rf'^ARM32_REG {mode} (OK|FAILED):', output, re.M)
            if len(checks) != 26 or any(value != 'OK' for value in checks):
                raise RuntimeError('Required actual register/breakpoint assertions are incomplete or failed')
        extended = re.findall(r'^ARM32_EXT_RESULT mode=(ARM|THUMB) checks=(\d+) failures=(\d+)$', output, re.M)
        if extended != [('ARM', '14', '0'), ('THUMB', '14', '0')]:
            raise RuntimeError('Required actual ARM/Thumb extension recovery profiles did not complete')
        for mode in ('ARM', 'THUMB'):
            assertions = re.findall(rf'^ARM32_REG VFP_{mode} (OK|FAILED):', output, re.M)
            if len(assertions) != 14 or any(value != 'OK' for value in assertions):
                raise RuntimeError('Required actual ARM VFP restoration assertions are incomplete or failed')
        memory = re.findall(r'^ARM32_MEM_RESULT mode=(ARM|THUMB) checks=(\d+) failures=(\d+)$', output, re.M)
        if memory != [('ARM', '27', '0'), ('THUMB', '27', '0')]:
            raise RuntimeError('Required actual ARM/Thumb private memory-syscall profiles did not complete')
        for mode in ('ARM', 'THUMB'):
            assertions = re.findall(rf'^ARM32_REG MEM_{mode} (OK|FAILED):', output, re.M)
            if len(assertions) != 27 or any(value != 'OK' for value in assertions):
                raise RuntimeError('Required actual ARM memory-syscall assertions are incomplete or failed')
        assertions = re.findall(r'^ARM32_REG MEM_IT_THUMB (OK|FAILED):', output, re.M)
        if re.findall(r'^ARM32_IT_MEM_RESULT.*$', output, re.M) != ['ARM32_IT_MEM_RESULT checks=4 failures=0'] or len(assertions) != 4 or any(value != 'OK' for value in assertions):
            raise RuntimeError('Required actual Thumb conditional-state memory profile did not complete')
        assertions = re.findall(r'^ARM32_REG MEM_BOUNDARY_THUMB (OK|FAILED):', output, re.M)
        if re.findall(r'^THUMB_RETURN_BOUNDARY_RESULT.*$', output, re.M) != ['THUMB_RETURN_BOUNDARY_RESULT checks=22 failures=0'] or len(assertions) != 22 or any(value != 'OK' for value in assertions):
            raise RuntimeError('Required actual Thumb return-instruction boundary profile did not complete')
        guest = re.search(r'^ARM32_REG_GUEST kernel=(\S+) machine=(\S+) page=(\d+) engine=(ARM32|ARM64)$', output, re.M)
        expected = ('armv7l', 'ARM32') if args.profile == 'arm32' else ('aarch64', 'ARM64')
        if not guest or (guest[2], guest[4]) != expected or guest[3] != '4096':
            raise RuntimeError('Actual kernel or engine architecture/page size is incorrect')
        native_checks = 0
        native_extended_checks = 0
        native_memory_checks = 0
        if args.profile == 'arm64-compat':
            if re.findall(r'^AARCH64_REG_RESULT.*$', output, re.M) != ['AARCH64_REG_RESULT checks=13 failures=0']:
                raise RuntimeError('Native ARM64 register regression profile did not complete')
            assertions = re.findall(r'^ARM32_REG AARCH64 (OK|FAILED):', output, re.M)
            if len(assertions) != 13 or any(value != 'OK' for value in assertions):
                raise RuntimeError('Native ARM64 register assertions are incomplete or failed')
            native_checks = 13
            assertions = re.findall(r'^ARM32_REG VFP_AARCH64 (OK|FAILED):', output, re.M)
            if re.findall(r'^AARCH64_EXT_RESULT.*$', output, re.M) != ['AARCH64_EXT_RESULT checks=8 failures=0'] or len(assertions) != 8 or any(value != 'OK' for value in assertions):
                raise RuntimeError('Native ARM64 extension recovery regression profile did not complete')
            native_extended_checks = 8
            assertions = re.findall(r'^ARM32_REG MEM_AARCH64 (OK|FAILED):', output, re.M)
            if re.findall(r'^AARCH64_MEM_GUARD_RESULT.*$', output, re.M) != ['AARCH64_MEM_GUARD_RESULT checks=4 failures=0'] or len(assertions) != 4 or any(value != 'OK' for value in assertions):
                raise RuntimeError('Native ARM64 private return-code safety assertions did not complete')
            native_memory_checks = 4
        report.update(passed=True, checks=160 + native_checks + native_extended_checks + native_memory_checks, arm32Checks=52, arm32ExtendedChecks=28, arm32MemoryChecks=54, thumbItMemoryChecks=4, thumbReturnBoundaryChecks=22,
                      nativeArm64Checks=native_checks, nativeArm64ExtendedChecks=native_extended_checks, nativeArm64MemoryChecks=native_memory_checks,
                      guestKernel=guest[1], guestMachine=guest[2], pageSize=int(guest[3]))
    except subprocess.TimeoutExpired as error:
        output = error.stdout or b''
        if isinstance(output, bytes):
            output = output.decode(errors='replace')
        report.update(output=output.replace('\r', ''), timedOut=True, failure='Actual ARM guest exceeded its deadline')
    except (OSError, RuntimeError) as error:
        report['failure'] = str(error)
    args.output.write_text(report['output'])
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print('ARM32_REGISTER_GATE=' + ('PASSED' if report['passed'] else 'FAILED'))
    if not report['passed']:
        print(report.get('failure', 'Unknown failure'))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
