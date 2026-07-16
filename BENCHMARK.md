# Scanner benchmarks

How fast this project's memory scanner finds values, measured head-to-head
against the other tools that can scan a live Linux process. Every number here is
a real measurement on one machine, same target, same value, same run.

If you find a case where another tool is faster, please open an issue with the
setup: these numbers are meant to be reproducible and honest, not marketing gloss.

## TL;DR

On a 12-thread laptop, scanning a process for an exact value:

| vs. | Typical | Best case |
|---|---|---|
| **Cheat Engine 7.7** (native Linux build) | ~2x faster | up to ~13x (rounded-float / pattern scans) |
| **scanmem 0.17**, the GameConqueror / PINCE engine | ~30 to 40x faster | up to ~145x (reserved memory) |
| **gdb** `find` | ~8 to 9x faster | n/a |
| **radare2** `/v` | ~1000x faster | n/a |

We are faster than every tool tested, at every value type and size. The lead is
smallest (~1.8x) against Cheat Engine 7.7 on plain aligned-integer first scans
(CE's scanner is genuinely good), and largest on float/pattern scans, reserved
address space, and dense next-scans.

## Machine and method

- **CPU:** Intel Core i5-10500H (6 cores / 12 threads), 256 KiB L2 per core.
- **OS:** Linux 6.17, `ptrace_scope=0` (same-user scanning, no root).
- **Target:** a process that `mmap`s an anonymous region, fills it with
  pseudo-random data, and plants 64 copies of the search value scattered through
  it (so the match count is dominated by that region and every tool scans the
  same bulk). Source at the bottom of this file.
- **Timing:** best of 5 runs (radare2: 1 run, it is very slow). The target's
  memory is resident (warm) for every tool.
- **Fairness:** all tools search for the same value with the same alignment, and
  their match counts agree (cescan/CE/gdb find 65; scanmem finds 64, one stray
  differs by tool). Where a tool's default differs it was configured to match
  (scanmem `scan_data_type int32`, CE `fsmAligned "4"`).

### Tool notes (read these before quoting a number)

- **cescan**: this project's CLI (`cescan scan <pid> --type i32 --value <v>`).
  Timed as the full process invocation (its startup is a few ms).
- **Cheat Engine 7.7**: the official native Linux build, driven by an `autorun`
  Lua script (`createMemScan`, `firstScan`, `waitTillDone`). Timed *inside* CE
  with `getTickCount`, which **excludes CE's multi-second GUI startup**, i.e. the
  comparison is generous to CE (pure scan time only).
- **scanmem 0.17**: the de-facto Linux scanner. **GameConqueror and PINCE both
  use `libscanmem`** (verified: `gameconqueror` `Depends: scanmem` and links
  `libscanmem.so`), so their scan speed equals this column; the GUIs only add
  overhead. Driven via its command session.
- **gdb 15.1**: `find /w <start>, <end>, <value>`, pointed at the target region.
  It is a debugger, not a scanner: it does not enumerate regions or narrow
  results, and it was handed the region to search.
- **radare2 5.5.0**: `/v4` over `dbg.maps`. A reverse-engineering framework, not
  a scanner; included for reference.

## First scan: exact int32, aligned (the "search for a value" operation)

Wall-clock, best of 5. Lower is better.

| Region | **cescan** | CE 7.7 | gdb `find` | scanmem / GC / PINCE | radare2 |
|---:|---:|---:|---:|---:|---:|
| 256 MB | **0.022 s** | 0.057 s | 0.274 s | 0.738 s | 34.3 s |
| 512 MB | **0.046 s** | 0.081 s | 0.413 s | 1.457 s | n/a |
| 1 GB | **0.085 s** | 0.156 s | 0.749 s | 2.924 s | n/a |
| 2 GB | **0.149 s** | 0.281 s | 1.291 s | 5.973 s | n/a |
| 1 GB, reserved arena¹ | **0.020 s** | 0.131 s | ~0.75 s² | 2.900 s | n/a |

Throughput at 1 GB: **cescan ~12 GB/s**, CE 7.7 ~6.6 GB/s, gdb ~1.4 GB/s,
scanmem ~0.34 GB/s, radare2 ~0.03 GB/s.

cescan speedup at 1 GB: **1.8x** vs CE 7.7, 8.8x vs gdb, 34x vs scanmem,
~1000x vs radare2.

¹ A region the process reserved but mostly never touched (common in game engines
that pre-allocate large arenas). cescan reads only the resident pages via
`/proc/pid/pagemap`; the others read all of it.
² gdb and radare2 have no resident-page skipping, so reserved is about the same
as touched for them.

## Next scan: narrowing a result set

Only the stateful scanners do this (gdb/radare2 do not). Re-scanning the previous
matches, best of 5.

| Result set | **cescan** | CE 7.7 | scanmem / GC |
|---|---:|---:|---:|
| Dense, 4.19 M matches (array-like) | **0.071 s** | 0.199 s (2.8x) | ~2.49 s (35x) |
| Scattered, 1.05 M matches | **0.098 s** | 0.157 s (1.6x) | n/a |

Our lead is largest when matches are packed (struct-array fields), where the
next-scan reads coalesce into large transfers; it narrows to ~1.6x vs CE on
widely-scattered matches.

## Value types: first scan, 1 GB

All tools find matching counts unless noted.

| Type | **cescan** | CE 7.7 | scanmem / GC |
|---|---:|---:|---:|
| Float, bit-exact | **0.073 s** | n/a (no bit-exact mode) | 2.906 s (40x) |
| Float, rounded (CE default) | **0.050 s** | 0.648 s (**13x**) | n/a (exact only) |
| String | **0.076 s** | 0.634 s (8.3x) | 2.890 s (38x) |
| Array-of-bytes / pattern | **0.071 s** | 0.610 s (8.6x) | 3.004 s (42x) |

Byte-pattern (string / AOB) scans show the biggest lead over CE 7.7 (~8 to 9x):
they are compute-bound (every unaligned offset), and cescan rejects 16 offsets
per step with SIMD before the full compare.

## Why it's faster

The wins are in the memory pipeline, not clever arithmetic:

- **Cache-blocked reads:** memory is read in L2-sized chunks so the scan runs
  from cache, not RAM (~3x on the read itself).
- **All cores on one region:** a single large mapping is split across threads.
- **Skip untouched pages:** resident-only reads via pagemap for reserved space.
- **Coalesced next-scan reads:** contiguous/near-contiguous matches become one
  large `process_vm_readv` instead of millions of tiny ones.
- **SIMD only where it pays:** exact/rounded numeric and byte-pattern scans;
  most numeric scans are memory-bound, where it is free.

Full changelog under "Performance" in [CHANGELOG.md](CHANGELOG.md).

## Caveats

- One machine, one synthetic workload. Real games have varied region layouts and
  match densities; your ratios will differ. The **relative ordering** (cescan >
  CE 7.7 > gdb > scanmem/GameConqueror/PINCE > radare2) is the durable result.
- "Up to" figures are best cases (rounded-float, reserved memory). The typical
  first-scan lead over CE 7.7 is ~2x.
- CE 7.7 was timed excluding its GUI startup, i.e. in CE's favor.
- Tool versions matter (CE 7.7, scanmem 0.17, gdb 15.1, radare2 5.5.0). scanmem
  0.17 is the current release.

## Reproduce it

The target used above:

```c
// target.c  (gcc -O2 target.c -o target ;  ./target <MB> <reserved 0|1> <dense_stride>)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
int main(int argc, char** argv) {
    size_t mb = argc > 1 ? atol(argv[1]) : 512;
    int reserved = argc > 2 ? atoi(argv[2]) : 0;
    size_t stride = argc > 3 ? atol(argv[3]) : 0;  // >0: value every `stride` bytes
    size_t N = mb * 1024 * 1024;
    uint32_t* buf = mmap(0, N, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | (reserved ? MAP_NORESERVE : 0), -1, 0);
    const uint32_t SENT = 0x5A5A1234u;
    if (!reserved) {
        uint64_t x = 88172645463325252ull;
        for (size_t i = 0; i < N / 4; i++) { x ^= x<<13; x ^= x>>7; x ^= x<<17;
            buf[i] = (uint32_t)x & 0x0FFFFFFFu; }               // never == SENT
    }
    if (stride) for (size_t o = 0; o + 4 <= N; o += stride) buf[o/4] = SENT;
    else        for (int k = 0; k < 64; k++) buf[((N/65)*(k+1))/4] = SENT;
    printf("PID=%d SENT=%u\n", getpid(), SENT); fflush(stdout);
    pause(); return 0;
}
```

Then, against its printed `PID` and `SENT` (`0x5A5A1234` = 1515852340):

```bash
# ours
cescan scan  $PID --type i32 --value $SENT

# scanmem (the GameConqueror / PINCE engine)
printf 'option scan_data_type int32\noption region_scan_level 3\n%s\nexit\n' $SENT | scanmem -p $PID

# gdb (point it at the region from /proc/$PID/maps)
gdb -p $PID -batch -ex "find /w $START, $END, $SENT" -ex detach -ex quit

# radare2
r2 -q -n -e search.in=dbg.maps -c "/v4 0x5A5A1234; q" -d $PID
```

Cheat Engine 7.7 was driven by an `autorun` Lua script doing `openProcess`,
`createMemScan`, `firstScan(soExactValue, vtDword, rtRounded, tostring(SENT),
"", 0, 0xffffffffffffffff, "", fsmAligned, "4", ...)`, `waitTillDone`, timed
with `getTickCount`.
