#!/usr/bin/env python3
"""Exercise CLI workflows against an explicitly ptrace-accessible child."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/cescan').resolve())
reader, writer = os.pipe()
child = os.fork()
if child == 0:
    os.close(reader)
    libc = ctypes.CDLL(None)
    libc.prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG
    if libc.prctl(0x59616D61, ctypes.c_ulong(-1), 0, 0, 0) != 0:  # PR_SET_PTRACER_ANY
        os._exit(2)
    name = ('ce-ease' + str(os.getpid()))[:15]
    libc.prctl(15, name.encode(), 0, 0, 0)  # PR_SET_NAME
    memory = ctypes.create_string_buffer(512)
    address = ctypes.addressof(memory)
    pointer = ctypes.c_void_p(address)
    def overwrite(signum, frame):
        memory[0] = b'\x00'
    signal.signal(signal.SIGALRM, overwrite)
    signal.signal(signal.SIGUSR1, lambda signum, frame: signal.setitimer(signal.ITIMER_REAL, 0.005, 0.005))
    signal.signal(signal.SIGUSR2, lambda signum, frame: signal.setitimer(signal.ITIMER_REAL, 0))
    description = json.dumps(dict(pid=os.getpid(), name=name, address=address,
                                  pointer=ctypes.addressof(pointer))).encode() + b'\n'
    os.write(writer, description)
    os.close(writer)
    while True:
        signal.pause()
os.close(writer)
checks = 0


def run(*args, expected=0):
    result = subprocess.run([binary, *map(str, args)], capture_output=True,
                            text=True, timeout=20)
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    return result.stdout + result.stderr


try:
    with os.fdopen(reader) as pipe:
        target = json.loads(pipe.readline())
    address = hex(target['address'])
    pid = target['pid']
    name = target['name']
    run('write', name, address, '18446744073709551615', '--type', 'u64', '--verify-ms', 1)
    assert '18446744073709551615' in run('read', name, address, '--type', 'u64')
    checks += 1
    expression = '[' + hex(target['pointer']) + ']+0x8'
    run('write', pid, expression, '2,5', '--type', 'float')
    assert '2.5' in run('read', pid, expression, '--type', 'float')
    checks += 1
    run('write', pid, address, '世界 😀', '--type', 'unicode', '--be', '--terminate', '--verify-ms', 1)
    assert '世界 😀' in run('read', pid, address, 32, '--type', 'unicode', '--be')
    checks += 1
    run('write', pid, address, 'café', '--type', 'string', '--encoding', 'CP1252', '--terminate')
    assert 'café' in run('read', pid, address, 8, '--type', 'string', '--encoding', 'CP1252')
    checks += 1
    run('freeze', name, address, '90, 48\n8B', '--type', 'aob', '--count', 2, '--interval', 1)
    assert '90 48 8B' in run('read', pid, address, 3, '--type', 'aob')
    checks += 1
    run('freeze', pid, address, 'é', '--type', 'unicode', '--terminate', '--count', 1, '--interval', 100000)
    assert 'é' in run('read', pid, address, 8, '--type', 'unicode')
    checks += 1
    run('write', pid, address, '9007199254740992', '--type', 'u64')
    run('freeze', pid, address, '9007199254740993', '--type', 'u64', '--mode', 'floor', '--count', 1, '--interval', 1)
    assert '9007199254740993' in run('read', pid, address, '--type', 'u64')
    checks += 1
    run('write', pid, address, '18446744073709551615', '--type', 'u64')
    run('freeze', pid, address, '9007199254740993', '--type', 'u64', '--mode', 'ceil', '--count', 1, '--interval', 1)
    assert '9007199254740993' in run('read', pid, address, '--type', 'U64')
    checks += 1
    before = run('read', pid, address, 8, '--type', 'aob')
    run('write', pid, address, '90 ZZ 90', '--type', 'aob', expected=1)
    run('write', pid, address, '256', '--type', 'byte', expected=1)
    run('write', pid, address, '8', '--type', 'i32', '--typo', expected=1)
    assert run('read', pid, address, 8, '--type', 'aob') == before
    checks += 1
    # Values that happen to match the help flag must remain writable.
    run('write', pid, address, '--help', '--type', 'string', '--terminate')
    assert '--help' in run('read', pid, address, 16, '--type', 'string')
    assert 'Commands:' in run('write', '--help')
    checks += 1
    os.kill(child, signal.SIGUSR1)
    try:
        assert 'value changed' in run('write', pid, address, '777', '--type', 'i32', '--verify-ms', 100, expected=1)
    finally:
        os.kill(child, signal.SIGUSR2)
    checks += 1
    script = (f'assert(openProcess({pid}))\n'
              f"assert(writeValue('{address}', 'u64', '18446744073709551615', {{bigEndian=true, codec='xor:0x12'}}))\n"
              f"assert(readValue('{address}', 'u64', {{bigEndian=true, codec='xor:0x12'}}) == '18446744073709551615')\n")
    run('lua', '-e', script)
    checks += 1
    before = run('read', pid, address, 1, '--type', 'aob')
    with tempfile.TemporaryDirectory(prefix='ce-cli-ease-') as directory:
        path = Path(directory) / 'patch.aa'
        path.write_text(f'[ENABLE]\n{{$if true}}\n{address}:\ndb 7F\n{{$endif}}\n[DISABLE]\n')
        output = run('autoasm', name, path, '--disable-after', 0)
        assert 'SUCCESS:' in output and 'Disabled:' in output
    assert run('read', pid, address, 1, '--type', 'aob') == before
    checks += 1
    # Renaming the parent to match the child creates an intentionally ambiguous target.
    libc = ctypes.CDLL(None)
    old_name = ctypes.create_string_buffer(16)
    libc.prctl(16, old_name, 0, 0, 0)  # PR_GET_NAME
    try:
        libc.prctl(15, name.encode(), 0, 0, 0)
        assert 'ambiguous' in run('read', name, address, '--type', 'byte', expected=1)
    finally:
        libc.prctl(15, old_name, 0, 0, 0)
    checks += 1
    print(f'CLI usability: {checks} workflow checks passed')
finally:
    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
