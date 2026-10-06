"""Build real PE32/PE32+ console fixtures using the project's assembler.

No MinGW or 32-bit Unix libraries are needed. The Windows program imports real
kernel32 console APIs, exposes a four-byte value and a target-width pointer, and
executes a patchable function when its stdin receives b'b'. This is a Windows
fixture, not a Linux executable renamed to .exe.
"""

import argparse
import pathlib
import struct
import subprocess


def build_fixture(cescan: pathlib.Path, output: pathlib.Path, bits: int) -> None:
    if bits not in (32, 64):
        raise ValueError("PE fixture width must be 32 or 64")
    width = bits // 8
    base = 0x400000
    text, data, imports = base + 0x1000, base + 0x2000, base + 0x3000
    value, pointer = data, data + 8
    command, count, stdin, stdout, writer_pointer = (data + n for n in (0x20, 0x24, 0x30, 0x38, 0x40))
    writer, message = text + 0x300, data + 0x100
    busy_flag, heartbeat, busy_message = data + 0x48, data + 0x4c, data + 0x160
    ready = f"CE_WINE {width} {value:#x} {pointer:#x} {writer:#x}\n".encode()
    iat = imports + 0x140

    def assemble(code: str, origin: int) -> bytes:
        result = subprocess.run([str(cescan), "asm", code, "--arch", f"x86-{bits}", "--origin", hex(origin)],
                                check=True, capture_output=True, text=True, timeout=20)
        return bytes.fromhex(result.stdout.strip())

    if bits == 64:
        def call_api(index, handle, buffer, length):
            return f"""mov rcx,qword [{handle:#x}]
mov rdx,{buffer:#x}
mov r8d,{length:#x}
mov r9,{count:#x}
mov qword [rsp+0x20],0
call qword [{iat + index * width:#x}]"""
        setup = f"""sub rsp,0x38
mov ecx,0xfffffff6
call qword [{iat:#x}]
mov qword [{stdin:#x}],rax
mov ecx,0xfffffff5
call qword [{iat:#x}]
mov qword [{stdout:#x}],rax"""
        exit_code = f"xor ecx,ecx\ncall qword [{iat + 3 * width:#x}]"
        invoke_writer = f"call qword [{writer_pointer:#x}]"
    else:
        def call_api(index, handle, buffer, length):
            return f"""push 0
push {count:#x}
push {length:#x}
push {buffer:#x}
push dword [{handle:#x}]
call dword [{iat + index * width:#x}]"""
        setup = f"""push 0xfffffff6
call dword [{iat:#x}]
mov dword [{stdin:#x}],eax
push 0xfffffff5
call dword [{iat:#x}]
mov dword [{stdout:#x}],eax"""
        exit_code = f"push 0\ncall dword [{iat + 3 * width:#x}]"
        invoke_writer = f"call dword [{writer_pointer:#x}]"
    code = f"""{setup}
{call_api(1, stdout, message, len(ready))}
main_loop:
{call_api(2, stdin, command, 1)}
cmp dword [{count:#x}],0
je exit_main
cmp byte [{command:#x}],0x71
je exit_main
cmp byte [{command:#x}],0x73
je busy_start
cmp byte [{command:#x}],0x62
jne check_read
{invoke_writer}
jmp send_value
check_read:
cmp byte [{command:#x}],0x72
jne main_loop
send_value:
{call_api(1, stdout, value, 4)}
jmp main_loop
busy_start:
mov dword [{busy_flag:#x}],1
{call_api(1, stdout, busy_message, 8)}
busy_loop:
inc dword [{heartbeat:#x}]
cmp dword [{busy_flag:#x}],0
jne busy_loop
jmp main_loop
exit_main:
{exit_code}
int3"""
    entry = assemble(code, text)
    if len(entry) > 0x300:
        raise ValueError("PE entry overlaps the function fixture")
    text_bytes = bytearray(0x1000)
    text_bytes[:len(entry)] = entry
    function = assemble(f"inc dword [{value:#x}]\nret", writer)
    text_bytes[0x300:0x300 + len(function)] = function
    data_bytes = bytearray(0x200)
    struct.pack_into("<I", data_bytes, 0, 123456789)
    pointer_format = "<Q" if bits == 64 else "<I"
    struct.pack_into(pointer_format, data_bytes, 8, value)
    struct.pack_into("<I", data_bytes, 8 + width, 0xdeadbeef)
    struct.pack_into(pointer_format, data_bytes, 0x40, writer)
    data_bytes[0x100:0x100 + len(ready)] = ready
    data_bytes[0x160:0x168] = b"CE_BUSY\n"
    import_bytes = bytearray(0x200)
    import_bytes[0x40:0x4d] = b"kernel32.dll\0"
    struct.pack_into("<IIIII", import_bytes, 0, 0x3100, 0, 0, 0x3040, 0x3140)
    offset = 0x80
    for index, name in enumerate((b"GetStdHandle", b"WriteFile", b"ReadFile", b"ExitProcess")):
        hint_name = b"\0\0" + name + b"\0"
        import_bytes[offset:offset + len(hint_name)] = hint_name
        for table in (0x100, 0x140):
            struct.pack_into(pointer_format, import_bytes, table + index * width, 0x3000 + offset)
        offset = (offset + len(hint_name) + 1) & ~1
    optional_size = 0xf0 if bits == 64 else 0xe0
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20b if bits == 64 else 0x10b)
    struct.pack_into("<III", optional, 4, 0x1000, 0x400, 0)
    struct.pack_into("<II", optional, 16, 0x1000, 0x1000)
    if bits == 64:
        struct.pack_into("<Q", optional, 24, base)
        struct.pack_into("<QQQQII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        directories = 112
    else:
        struct.pack_into("<II", optional, 24, 0x2000, base)
        struct.pack_into("<IIIIII", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        directories = 96
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)
    struct.pack_into("<H", optional, 40, 6)
    struct.pack_into("<H", optional, 48, 6)
    struct.pack_into("<II", optional, 56, 0x4000, 0x400)
    struct.pack_into("<HH", optional, 68, 3, 0x100)
    struct.pack_into("<II", optional, directories + 8, 0x3000, 40)
    struct.pack_into("<II", optional, directories + 12 * 8, 0x3140, 5 * width)
    headers = bytearray(0x400)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3c, 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x8664 if bits == 64 else 0x14c,
                     3, 0, 0, 0, optional_size, 0x23 if bits == 64 else 0x103)
    headers[0x98:0x98 + optional_size] = optional
    for index, (name, rva, raw_size, raw_offset, flags) in enumerate((
        (b".text", 0x1000, 0x1000, 0x400, 0x60000020),
        (b".data", 0x2000, 0x200, 0x1400, 0xc0000040),
        (b".idata", 0x3000, 0x200, 0x1600, 0xc0000040),
    )):
        struct.pack_into("<8sIIIIIIHHI", headers, 0x98 + optional_size + index * 40,
                         name, raw_size, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
    output.write_bytes(headers + text_bytes + data_bytes + import_bytes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cescan", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--bits", type=int, choices=(32, 64), required=True)
    args = parser.parse_args()
    build_fixture(args.cescan.resolve(), args.output, args.bits)
