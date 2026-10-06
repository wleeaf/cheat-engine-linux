#!/usr/bin/env python3
"""Exercise CLI workflows against an explicitly ptrace-accessible child."""
import ctypes
import json
import os
import select
from pathlib import Path
import signal
import re
import shutil
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
    assert run('asm', 'call 0x401100', '--origin', '0x401000').startswith('e8 fb 00 00 00\n')
    run('asm', 'nop', '--origin', '-1', expected=1)
    run('asm', 'nop', '--origin', expected=1)
    checks += 1
    with os.fdopen(reader) as pipe:
        target = json.loads(pipe.readline())
    address = hex(target['address'])
    pid = target['pid']
    name = target['name']
    run('write', name, address, '18446744073709551615', '--type', 'u64', '--verify-ms', 1)
    assert '18446744073709551615' in run('read', name, address, '--type', 'u64')
    checks += 1
    # Bound scans to the fixture bytes, keeping frontend coverage cheap on a
    # constrained machine. The target is native LE; its encoded data is BE32.
    run('write',pid,address,'12 34 56 78 AA BB CC DD','--type','aob')
    scan_options=['--from',address,'--to',hex(target['address']+3),'--byte-order','big','--align',1]
    snapshot_dirs=[]
    try:
        for scan_type in ('i32','pointer'):
            width_options=['--pointer-width',4] if scan_type=='pointer' else []
            output=run('scan',pid,'--type',scan_type,'--value','0x12345678',*scan_options,*width_options)
            expected='0x12345678' if scan_type=='pointer' else '305419896'
            assert 'Found: 1 results' in output and f'{address} = {expected}' in output,output
            snapshot=Path(re.search(r'^Results: (.+)$',output,re.MULTILINE).group(1))
            snapshot_dirs.append(snapshot.parent)
            output=run('scan',pid,'--type',scan_type,'--value','0x12345678','--previous',snapshot,*scan_options,*width_options)
            assert 'Found: 1 results' in output and f'{address} = {expected}' in output,output
            snapshot_dirs.append(Path(re.search(r'^Results: (.+)$',output,re.MULTILINE).group(1)).parent)
            checks+=1
        for bad in (['--byte-order','wrong'],['--pointer-width','3'],['--from','4','--to','3'],['--typo'],['--value','12oops'],['--type','aob','--value','ZZ']):
            run('scan',pid,*bad,expected=1)
        checks+=1
        # All scans use one exact numeric parser, independently of record width.
        one_byte=['--from',address,'--to',address,'--align',1,'--byte-order','big']
        for stored,needle,compare,count,extra in [
            (2,'2.5','exact',0,[]),(2,'2.5','less',1,[]),
            (20,'2e1','exact',1,[]),(42,'0x2A','exact',1,[]),
            (2,'1.5','between',1,['--value2','2.5'])]:
            run('write',pid,address,str(stored),'--type','byte')
            output=run('scan',pid,'--type','all','--value',needle,'--compare',compare,*one_byte,*extra)
            all_snapshot=Path(re.search(r'^Results: (.+)$',output,re.MULTILINE).group(1))
            snapshot_dirs.append(all_snapshot.parent)
            assert f'Found: {count} results' in output,output
            if count: assert f'{address} = {stored:02x}' in output.lower(),output
        run('write',pid,address,'4','--type','byte')
        output=run('scan',pid,'--type','all','--previous',all_snapshot,'--compare','between',
                   '--percent','100','--percent2','100',*one_byte)
        snapshot_dirs.append(Path(re.search(r'^Results: (.+)$',output,re.MULTILINE).group(1)).parent)
        assert 'Found: 1 results' in output and f'{address} = 04' in output,output
        for bad in (['--value','2oops'],['--value','2.5oops'],['--value','1e9999'],
                    ['--value','1','--compare','between'],['--value','1','--compare','between','--value2','2bad'],
                    ['--compare','between','--percent','oops'],['--compare','between','--percent','100','--percent2','nan'],
                    ['--percent2','100'],[]):
            run('scan',pid,'--type','all',*one_byte,*bad,expected=1)
        checks+=1
        floating_range=['--from',address,'--to',hex(target['address']+3),'--align',4]
        for kind in ('float','all'):
            for stored,needle,mode,count,extra in [('0.05','0.1','rounded',1,[]),
                ('0.05','1e-1','rounded',1,[]),('0','1e-1','rounded',0,[]),('16777216','16777217','truncated',0,[]),
                ('16777216','16777217','extreme',0,['--tolerance','0.000001'])]:
                run('write',pid,address,stored,'--type','float')
                output=run('scan',pid,'--type',kind,'--value',needle,'--rounding',mode,*floating_range,*extra)
                snapshot=Path(re.search(r'^Results: (.+)$',output,re.MULTILINE).group(1));snapshot_dirs.append(snapshot.parent)
                assert f'Found: {count} results' in output,output
                if count:
                    output=run('scan',pid,'--type',kind,'--value',needle,'--rounding',mode,'--previous',snapshot,*floating_range,*extra)
                    snapshot_dirs.append(Path(re.search(r'^Results: (.+)$',output,re.MULTILINE).group(1)).parent)
                    assert 'Found: 1 results' in output,output
        for bad in (['--value','0.1oops'],['--value','0.1','--rounding','wrong'],
                    ['--value','0.1','--tolerance','nan'],['--value','0.1','--tolerance','oops'],
                    ['--value','0.1','--tolerance','-1'],['--compare','between','--value','0.1']):
            run('scan',pid,'--type','float',*floating_range,*bad,expected=1)
        checks+=1
    finally:
        for directory in snapshot_dirs: shutil.rmtree(directory)
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
    # Exercise the real Lua event pump across exec, including retirement of the
    # original breakpoint list and continued execution of the replacement image.
    for bits in (64, 32):
        fixture_path = str(Path(binary).parent / f'compatibility_fixture{bits}')
        fixture = subprocess.Popen([fixture_path, fixture_path], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
        debugger = None
        try:
            assert select.select([fixture.stdout], [], [], 5)[0], 'fixture startup timed out'
            header = fixture.stdout.readline().split()
            assert header[0] == 'CE_TARGET' and int(header[1]) == fixture.pid, header
            script = (f'assert(openProcess({fixture.pid}))\n'
                      f'assert(debug_setBreakpoint({int(header[5], 16)}))\n'
                      'local executed = false\n'
                      'function debugger_onProcessExecuted()\n'
                      '  assert(#debug_getBreakpointList() == 0, "old breakpoint survived exec")\n'
                      '  executed = true\n'
                      'end\n'
                      'print("SESSION_READY"); io.flush()\n'
                      'for i = 1, 50 do debug_pumpEvents(100); if executed then break end end\n'
                      'assert(executed, "exec event was not pumped")\n'
                      'print("SESSION_EXEC_PASSED"); io.flush()\n')
            debugger = subprocess.Popen([binary, 'lua', '-e', script], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
            assert select.select([debugger.stdout], [], [], 5)[0], 'Lua attachment timed out'
            assert debugger.stdout.readline().strip() == 'SESSION_READY'
            fixture.stdin.write('x'); fixture.stdin.flush()
            output, error = debugger.communicate(timeout=10)
            assert debugger.returncode == 0 and 'SESSION_EXEC_PASSED' in output, (output, error)
            assert select.select([fixture.stdout], [], [], 5)[0], 'replacement fixture did not start'
            assert fixture.stdout.readline().startswith('CE_TARGET ')
            fixture.stdin.write('b'); fixture.stdin.flush()
            assert select.select([fixture.stdout], [], [], 5)[0], 'replacement writer timed out'
            assert fixture.stdout.readline().strip() == '123456790'
            checks += 1
        finally:
            fixture.kill(); fixture.wait()
            if debugger and debugger.poll() is None:
                debugger.kill(); debugger.wait()
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
