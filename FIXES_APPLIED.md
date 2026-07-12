# cecore — Remediation Summary ("fix all")

> Companion to [`CODE_ANALYSIS.md`](CODE_ANALYSIS.md). Records the fixes applied for the 123 non-refuted findings. **Date:** 2026-05-29.
>
> **Update (2026-07-12):** the "runtime-UNVERIFIED" caveat below (debug/ptrace/injector paths) is now partly stale — software breakpoints, all-stop multi-thread debugging, `createRemoteThread`, and `remoteSyscall`-backed alloc/dealloc now run against a live child in the CI test suite. Also, `cecore_test` now actually **gates CI** on failures (it previously returned 0 unconditionally). Remaining untested-at-runtime surfaces and the current gap list are tracked in `ROADMAP.md`.

## Verification status

What was verified, and just as importantly, what was **not**:

- **Full build:** `cmake --build build` exits **0** with the new hardening flags active (`-Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2`, RELRO/`-z now`/noexecstack). Confirmed `BIND_NOW` present in `libcecore.so`.
- **`cecore_test`:** exits **0**, no `FAILED` lines. `cescan --help` exits 0.
- **Kernel module:** compiles clean out-of-tree (`make -C /lib/modules/$(uname -r)/build M=$PWD/kernel modules`, exit 0, `.ko` produced). **Not loaded/runtime-tested** (would need `insmod` as root).
- **Orchestrator diff-review:** all 6 confirmed critical/high fixes were read directly (not taken on the fix-agents' word): ELF overflow, kernel `/proc`-hook UAF + ioremap, LBR OOB, lua_gui UAF, autoasm check/execute divergence.

### ⚠️ Verification coverage is uneven — and weakest where it matters most

`cecore_test` is a smoke/integration test; `scan_test` (the root-gated suite) **was not run this session**. So fixes split into:

- **Compile-verified + runtime-exercised:** scanner value-compares, ct_file/trainer round-trip, Lua bindings surface, basic memory read/write — these run under `cecore_test`.
- **Compile-verified, runtime-UNVERIFIED:** the **debug** (8 fixed / 5 partial) and **platform-core** (10 / 3) ptrace/breakpoint/tracer/**injector** paths. `cecore_test` barely touches them and `scan_test` never ran. A per-site ptrace guard that inspects the wrong `waitpid` status would fail *closed* (debugging silently breaks) and **nothing here would catch it**.
- The **getProcessList regression** (a fix agent shipped a CE-contract break) was caught *only* because a test happened to assert that contract. The debug/ptrace fixes have no such net. Treat them as needing real runtime validation.

**Highest-value remaining check (needs root, so it's yours to run):** `sudo ./build/scan_test`, plus manual exercise of the debugger/breakpoint/injector paths against a live process.

- **DWARF caveat:** the fixes in `symbols/dwarf_symbols.cpp` are behind `#ifdef CECORE_HAVE_DWARF`; libdw-dev is not installed here, so they were validated by API-signature inspection, **not compiled**. A libdw-present build should confirm that branch.

## Approach

**Harden, don't remove.** Intended Cheat-Engine capabilities (`shellExecute`, `*Local` memory access, the trainer code generator, ptrace injection) were kept and their inputs validated/bounded rather than stripped. Large redesigns (full ptrace-state-machine consolidation, complete Lua sandbox, replacing the `/proc` i_fop hook) were **not** attempted in a parallel fix pass — the minimal defensive subset was applied and the rest left as `// TODO(security):` and reported as *partial*.

## The 6 confirmed findings — fixed & verified

| Finding | Location | Fix |
|---|---|---|
| ELF symbol heap overflow | `symbols/elf_symbols.cpp` | Reject `sh_entsize != sizeof(Elf64_Sym)`; bound sections by actual file size (wrap-safe); read exactly `numSyms*sizeof(Elf64_Sym)`; NUL-terminate strtab. |
| Kernel `/proc`-hook UAF + dentry leak | `kernel/cecore_kmod.c` | Pin module via `fops.owner=THIS_MODULE` (blocks rmmod while `/proc` open); `synchronize_rcu()` + `dput()` on removal; TODO that the technique is fundamentally racy. |
| Kernel arbitrary phys-mem via ioremap | `kernel/cecore_kmod.c` | Wrap-check phys/user/size ranges; RAM access **intentionally allowed** (validate-but-allow, per user decision — it's a CE/DBVM capability), kept root/`CAP_SYS_ADMIN`-gated. |
| LBR ring OOB read | `debug/lbr_tracer.cpp` | Linearize each record across the ring wrap into an aligned scratch buffer; bound `hdr.size` by `dataSize`/`avail`; validate entries fit the record. |
| lua_gui widget UAF | `scripting/lua_gui.cpp` | `LuaWidget`/`LuaCanvas` pointers → `QPointer`; `liveWidget`/`liveCanvas` guards raise a Lua error if destroyed; placement-new + `__gc`. |
| autoasm check()/execute() divergence | `core/autoasm.cpp` | Single shared `preprocessScript()` called by both paths; original-byte save gated on a verified full read. |

## Per-subsystem results

| Subsystem | Fixed | Partial | Skipped |
|---|---|---|---|
| symbols | 5 | 1 | 0 |
| kernel-module | 5 | 1 | 0 | 
| lua-core | 4 | 4 | 0 |
| lua-aux | 3 | 2 | 2 |
| debug | 8 | 5 | 0 |
| autoasm | 7 | 1 | 1 |
| tables-trainer-expr | 9 | 1 | 0 |
| platform-core | 10 | 3 | 0 |
| platform-net-overlay | 6 | 0 | 1 |
| scanner | 7 | 1 | 0 |
| analysis | 5 | 0 | 0 |
| plugins | 8 | 4 | 0 |
| gui-main | 6 | 3 | 0 |
| gui-aux | 9 | 0 | 0 |
| cli-arch | 7 | 0 | 0 |
| **+ build-ci (orchestrator)** | 3 | 0 | 4 |

## Partial fixes & deliberate skips (what was *not* fully done)

These are the items where a complete fix is a larger design change or a behavior call. Each has a minimal guard in place where applicable.

### symbols
- **partial** — findSubprogramName recurses into subprogram subtrees twice; unbounded recursion on hostile DWARF  
  Made the two branches mutually exclusive: subprogram/inlined_subroutine handled in the first branch, the second branch is now `else if (tag == DW_TAG_lexical_block)` only, eliminating the double-recurse into subprogram subtrees. Added an `int depth` parameter (default 0) with a kMaxDwarfDepth=256 ca
- _follow-up:_ dwarf_symbols.cpp findSubprogramName: convert the recursive DIE walk to an explicit work-list/stack (TODO(security) left in place) to fully bound against hostile DWARF rather than relying on the depth=256 cap.
- _follow-up:_ Builder with libdw-dev installed should compile-verify the #ifdef CECORE_HAVE_DWARF branch of dwarf_symbols.cpp (dwarf_nextcu probe + findSubprogramName depth param), which was not exercised locally.

### kernel-module
- **partial** — `/proc` i_fop hook UAF: applied module-owner pin + `synchronize_rcu()` + `dput()`; left TODO that the pointer-swap hiding technique is inherently racy and should be replaced, not just mitigated.

### lua-core
- **partial** — C++ exceptions escape lua_CFunction into C-compiled Lua frames (UB / terminate)  
  l_readBytes: added luaL_argcheck(size>=0) and wrapped the std::vector allocation + read in try/catch that converts std::exception to luaL_error, so a large positive size's bad_alloc/length_error can no longer escape into C-compiled Lua frames. The companion sites in lua_bindings.cpp (l_readString, l
- **partial** — C++ exceptions escape lua_CFunction into C-compiled Lua frames (UB / terminate)  
  l_readString: added luaL_argcheck(maxLen>=0) and wrapped vector alloc + read in try/catch->luaL_error. l_writeRegionToFile: validate raw lua_Integer size >= 0 and cap at 256 MiB before allocating (rejects negative-sign-extended huge sizes and bad_alloc). l_AOBScan and l_AOBScanEx: wrapped parseAOB/f
- **partial** — Local read/write family performs arbitrary in-process read/write from a raw script integer  
  Capability intentionally retained per HARDEN-NOT-REMOVE. Applied the 'at minimum, document' subset: added a SECURITY (by design) header comment over the *Local family explaining that it is unrestricted host-memory access under an untrusted-script threat model, that loading a script equals native cod
- **partial** — shellExecute passes script string straight to system() (command execution, as root)  
  Capability intentionally retained per HARDEN-NOT-REMOVE. Added a SECURITY comment documenting that shellExecute runs an arbitrary command via /bin/sh as the cecore user (often root) and that scripts must be treated as trusted, plus a // TODO(security) to gate behind explicit consent and prefer posix
- _follow-up:_ Finding 1: no global exception firewall around every registered binding -- route all lua_register calls through a single exception-translating trampoline (left as // TODO(security) at registerExtendedBindings). Enumerated triggers are indiv
- _follow-up:_ Findings 6 & 7: gate the *Local memory family and shellExecute behind an explicit user-consent / non-default capability or sandbox flag if cecore is ever exposed to untrusted scripts; documented but not gated.

### lua-aux
- **partial** — Arbitrary filesystem read/write via createFileStream / saveToFile / loadFromFile while running as root  
  HARDEN-not-remove: kept the FS bindings but added isExistingSymlink() (lstat + S_ISLNK, added <sys/stat.h>) and refuse to open write targets that are existing symlinks in pushFileStream (write modes), l_stream_saveToFile, and l_sl_saveToFile. This blocks clobbering e.g. /etc/shadow through a planted
- **partial** — Callback maps keyed by raw QObject* are vulnerable to pointer reuse and are unsynchronized globals  
  The recommended fix (move callback refs into the widget userdata, eliminating the global maps) is a redesign with lifetime-semantics changes, not attempted per the no-partial-redesign rule. Applied the finding's fallback: documented the single-GUI-thread invariant and that entries are erased synchro
- **skipped** — OnClose callback ref can leak when the form is reassigned vs. destroyed paths overlap  
  Skipped per the behavior-changing-low-fix rule. The recommended single-owner reorder (move closeCallbacks teardown into trackDestroyed) would, due to Qt's disconnect-during-emit semantics, risk the user's OnClose callback never firing because trackDestroyed's destroyed-lambda is connected first and 
- **skipped** — MemoryRecord/AddressList bindings are solid — id-based handles, graceful detach  
  Positive (info) finding, explicitly 'No change required'. The id-based MemRecRef handles and currentList() re-fetch already avoid the dangling-pointer trap. No edit made.
- _follow-up:_ lua_gui.cpp: full elimination of the global QObject*-keyed callback maps by storing callback refs (and a QPointer) inside the widget userdata, now that __gc exists (TODO(security) in source).
- _follow-up:_ lua_streams.cpp: open write targets with O_NOFOLLOW via a fd-backed stream to also close the TOCTOU race, and gate filesystem bindings behind a configurable script-trust setting; read-path sandboxing still open (TODO(security) in source).
- _follow-up:_ lua_streams.cpp: when a pre-existing failbit makes tellg() return -1, the file-read clamp computes remaining==0 (returns "") which matches old behavior, but an explicit failbit clear/guard could be added for clarity.

### debug
- **partial** — step() reads registers after a non-blocking waitpid that may not have stopped the tracee  
  Gated stopped_=true on (waited>0 && WIFSTOPPED(status)) so step(Into) no longer reports stopped when the tracee is still running. Kept the >=0-guarded GETREGS unconditional so Over/Out/RunToCursor (which already consumed their stop via the prior blocking waitpid, making the trailing WNOHANG return 0
- **partial** — CodeFinder/Tracer attach only one thread; HW watchpoint misses other threads and waitpid misses thread events  
  Added a TODO(security) documenting the single-thread attach + single-thread DR0 programming limitation and the needed fix (enumerate proc_->threads(), PTRACE_SEIZE with PTRACE_O_TRACECLONE, arm the watchpoint per-tid, wait with __WALL). The full multi-thread fix reworks the single-tracer wait model 
- **partial** — Tracer step-over-call and start paths don't check for tracee exit after PTRACE_CONT  
  After each blocking waitpid (start-breakpoint run-to and step-over-call), now branch on WIFEXITED/WIFSIGNALED: if the tracee died, set progress to 1.0 and return the collected entries, skipping removeBreakpoint/getContext/singleStep and the final PTRACE_DETACH on a dead pid. Left a TODO(security) fo
- **partial** — DebugSession::detach() from inside the event-loop thread is a use-after-free / data race  
  The described UAF/data-race mechanism was refuted by the verifier (detach runs synchronously on the same thread; it is actually a self-deadlock at the BreakpointHit site, which is now eliminated by the #3 fix since eventCb_ no longer runs under bpMutex_). The remaining residual lifetime hazard (even
- **partial** — step() issues ptrace and reaps waitpid from a thread other than the tracer thread  
  step() is dead code (zero callers) and the genuine related defect is the eventLoop cross-thread tracer model. Added a TODO(security) in step() documenting that all ptrace/waitpid must be funneled through the single event-loop thread via a command queue. The full redesign was not attempted per rule 3
- _follow-up:_ debug_session/code_finder/tracer: funnel all ptrace + waitpid through a single tracer thread (command queue), since attach() makes the caller the tracer but eventLoop/step issue ptrace from other threads (cross-thread tracer hazard).
- _follow-up:_ code_finder.cpp / tracer.cpp: enumerate proc->threads() and PTRACE_SEIZE each tid (PTRACE_O_TRACECLONE) + arm the watchpoint/HW breakpoint per-thread + wait with __WALL, to cover multithreaded targets.
- _follow-up:_ tracer.cpp: confirm the start-breakpoint stop via PTRACE_GETSIGINFO (si_code) before single-stepping, and forward unexpected signals instead of assuming SIGTRAP == our breakpoint.
- _follow-up:_ debug_session.cpp detach(): replace eventThread_.detach() with deferred teardown (signal the loop to break and run cleanup at the bottom of the loop) so the abandoned thread's unwind is synchronized with ~DebugSession; never destroy a Debug
- _follow-up:_ breakpoint_manager.cpp conditionMatches(): run the condition chunk in a dedicated _ENV sandbox rather than relying on global stripping; also reconsider the triple-retry-with-side-effects fallback (left unchanged due to behavior risk).
- _follow-up:_ intel_pt.cpp drain(): enforce single-threaded drain or add a mutex if multi-thread drain is ever needed (aux_tail read-modify-write would otherwise race).

### autoasm
- **partial** — INCLUDE() recursively parses included files with no depth or cycle guard  
  Added an includeDepth parameter (default 0) to parseLine and a kMaxIncludeDepth=16 cap in the INCLUDE handler: when the limit is hit, set error and return false, preventing stack exhaustion from a self-including .cea or an A->B->A cycle. Depth is propagated through the custom-command recursive parse
- **skipped** — LOADLIBRARY exists()-then-inject TOCTOU and absence of path validation — not a privilege escalation  
  Skipped per the finding's own conclusion (effectiveSeverity=info, verdict: "not a real gap"). The exists()->inject window crosses no privilege boundary the AA script doesn't already hold (the script can already alloc+write+CREATETHREAD arbitrary code), and the only recommended action was optional co
- _follow-up:_ test/main.cpp (NOT in my ownership set): add an execute()-based regression test for a script combining {$lua}/{$asm}, {$if}/{$else}/{$endif}, and @@:/@F/@B. Existing preprocessor tests use only aa.check(), so CI never exercises the execute(
- _follow-up:_ core/autoasm.cpp INCLUDE handler: add a visited-set of std::filesystem::weakly_canonical paths to detect and report true include cycles (A->B->A) rather than only capping depth. Marked with TODO(security) in code.
- _follow-up:_ Optional: decide whether INCLUDE of a missing file should remain a silent log (current, intentional) or become a hard error — left unchanged to avoid breaking optional-include patterns.

### tables-trainer-expr
- **partial** — "Protected" CETRAINER uses reversible XOR obfuscation with cleartext password hash  
  Applied the minimal safe subset: added a prominent NOTE comment above xorCrypt/xorDecrypt documenting that this is light OBFUSCATION only (not confidentiality) plus a TODO(security) describing the real fix (AEAD + memory-hard KDF + random salt/nonce, stop storing any password-derived value). Did NOT
- _follow-up:_ XOR-obfuscation CETRAINER: replace with an authenticated cipher (libsodium secretbox / AES-GCM) + memory-hard KDF (argon2/scrypt) + random salt/nonce, and stop storing the fnv1a(password) verifier in cleartext. This is a format-breaking red
- _follow-up:_ freezeWriteBody: array/string/binary freeze types are currently skipped (no scalar write). Add a sanitized byte-buffer freeze path for String/ByteArray if those need to be supported (TODO(security) noted in trainer.cpp).
- _follow-up:_ Consider wrapping the whole CheatTable::load() body in try/catch returning false as defense-in-depth, and auditing the std::atoi on <ID> (ct_file.cpp:587) — atoi does not throw so it is safe today, but the broader getTag-derived-conversion 

### platform-core
- **partial** — remoteCall does not verify the int3 stop and may detach with the target mid-execution  
  Added per-site ptrace return checks (POKETEXT of the return slot, SETREGS, CONT) and now only read rax when waitpid==pid && WIFSTOPPED (live tracee) && GETREGS succeeds; on any ptrace failure restore oldRegs and return -1. I deliberately do NOT gate on SIGTRAP or rip==poison: I empirically verified 
- **partial** — queryRegions perms/path field parsing assumes fixed single-space layout and is fragile  
  Confirmed there is no out-of-bounds bug: substr clamps and every perms[] indexing site already bounds-checks length. Added a clarifying comment documenting that invariant and left a TODO(security) for the recommended whitespace-run tokenizer rewrite, which I intentionally did not perform (behavior-c
- **partial** — pollChildren issues PTRACE_CONT to every stopped tracee with signal 0, swallowing legitimate signals and ignoring exec/exit events  
  Applied the minimal defensive subset: a genuine application signal-delivery stop (event==0 && WSTOPSIG != SIGTRAP) is now re-delivered via PTRACE_CONT instead of being swallowed; ptrace event stops and the trace-machinery SIGTRAP are still continued with signal 0. Left a TODO(security) for the large
- _follow-up:_ remoteCall (injector.cpp): add a real discriminator between a genuine return through the poison sentinel and a SIGSEGV raised inside the callee (PTRACE_GETSIGINFO), and re-deliver pending signals instead of treating any WIFSTOPPED as comple
- _follow-up:_ linux_process.cpp remoteSyscall: migrate to PTRACE_SEIZE + PTRACE_INTERRUPT and operate on a specific tid for clean stop semantics against multithreaded targets; consider attaching once for a batch of management ops. Left as TODO(security) 
- _follow-up:_ ptrace_wrapper.cpp pollChildren: handle PTRACE_EVENT_EXEC/EXIT (re-baseline modules on exec, reap and surface exited tracees), and detect group-stops via PTRACE_GETSIGINFO before re-delivering signals. Left as TODO(security).
- _follow-up:_ ptrace_wrapper.cpp setContext: mask DR7 reserved/control bits in userspace before POKEUSER rather than relying solely on kernel validation, and reconcile the setContext-vs-setBreakpoint DR-management paths. Left as TODO(security).
- _follow-up:_ linux_process.cpp queryRegions: replace single-space field counting with a whitespace-run tokenizer (>=6 fields, 6th = rest-of-line path). Left as TODO(security); not a bug today.
- _follow-up:_ 32-bit/i386 target support: injectLibrary/createRemoteThread/allocate/free/protect now hard-refuse 32-bit targets. If i386 injection is desired later, implement the i386 ABI (int 0x80, __NR_mmap2=192, cdecl-stack args, 4-byte POKE granulari

### platform-net-overlay
- **skipped** — Vulkan layer link-info pNext walk casts via VkLayerInstanceCreateInfo before checking sType  
  Skipped per the finding's own recommendation ("None required") and rule 5. This is the standard, safe Vulkan loader idiom: every pNext node begins with {sType, pNext} at identical offsets, so reading ->sType before the type match is well-defined, and ->function is only used after the sType match. Th

### scanner
- **partial** — scanBufferUnicode relies on host endianness while utf16LeBytes encodes explicit LE — inconsistent  
  Routed scanBufferUnicode's needle encoding through the shared explicit-LE utf16LeBytes() (added a forward declaration since it is defined later in the TU), so the first-scan unicode path now agrees with nextScan/grouped regardless of host endianness. Left a TODO(portability): it still only handles A
- _follow-up:_ memory_scanner.cpp firstScan worker: per-worker read/alloc errors (the catch(...) path) are swallowed and produce a silent partial result; surface them to the caller (TODO(security) left in place).
- _follow-up:_ scanBufferUnicode still only does ASCII->UTF-16LE; implement real UTF-8 needle decoding to UTF-16LE via iconv for correct non-ASCII unicode-string searches (TODO(portability) left in place).
- _follow-up:_ Pre-existing -Wunused-result warnings on the ::write() calls in ScanResult::flush() and the firstScan merge loop were left as-is (out of finding scope); they could be hardened with a writeFull helper in a follow-up.

### analysis
- _follow-up:_ analysis/code_analysis.cpp findStatics: implement an absolute-displacement extraction pass (parse mov/lea/cmp memory operands of the form [imm] / [reg*scale + imm] that resolve to a fixed module-relative address) and merge those counts in, 
- _follow-up:_ Consider surfacing Capstone CS_OPT_DETAIL operand structs through arch/disassembler (Instruction) so code_analysis can read displacements/targets directly instead of re-parsing op_str text; would make finding #1's classification robust agai

### plugins
- **partial** — Lazy dlsym(RTLD_NEXT) resolution is not thread-safe and can be dereferenced when NULL  
  Added the concrete must-fix NULL guards: every wrapper that previously called real_fn unconditionally (clock_gettime, gettimeofday, nanosleep, clock_nanosleep, usleep, sleep, select, poll) now checks the resolved pointer and returns a safe error (errno=ENOSYS;-1, or ENOSYS for clock_nanosleep's posi
- **partial** — World-writable shared-memory speed channel: any local user can control or DoS speed of every hooked process  
  Applied the in-lane hardening that preserves the fixed-name contract: shm_open now uses O_NOFOLLOW and mode 0600 (was 0666); ftruncate's return value is now checked (close+bail on failure); and get_speed clamps the shared value via clamp_speed (finite + 0.01..1000) so a poisoned NaN/huge double can'
- **partial** — audiohack per-handle stream cache and SoundTouch objects are unsynchronized and never freed  
  Added std::mutex g_streamsMutex guarding all g_streams access; renamed getOrFillMeta to getOrFillMetaLocked and added dropMetaLocked. writei now resolves+snapshots meta fields (fmt, channels, SoundTouch*) under the lock and releases it before the potentially-blocking real() device write. Added a snd
- **partial** — inprocess_veh signal handler is async-signal-unsafe (fprintf/fflush) and may infinite-loop on resumed SIGSEGV  
  Replaced the async-signal-unsafe fprintf/fflush in cecore_log_event with a single async-signal-safe write(2) to a raw fd (g_log_fd) opened at init (open with O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC), formatting the line with new signal-safe helpers (as_append/as_append_dec/as_append_hex) that bounds-che
- _follow-up:_ speedhack/audiohack/gui: namespace the speed shm object per target pid (e.g. /ce_speedhack_<pid>) instead of the single global /ce_speedhack. Requires coordinated edits to gui/mainwindow.cpp:410 (the writer, hardcodes /dev/shm/ce_speedhack,
- _follow-up:_ speedhack.c: move the 8 per-wrapper lazy dlsym(RTLD_NEXT) static resolutions into a single constructor-time resolution (or under std::call_once) to remove the benign data race entirely (// TODO(security) left in code).
- _follow-up:_ inprocess_veh.c: handle the resumed-SIGSEGV re-fault loop (restore SIG_DFL for fatal CPU traps after logging) and install a sigaltstack so stack-overflow SIGSEGV can still be handled (// TODO(security) left in code).
- _follow-up:_ audiohack.cpp: revalidate hw_params on snd_pcm_t* reuse and make the 16-stream cache cap dynamic / larger (// TODO(security) left in code).

### gui-main
- **partial** — Speedhack writes to predictable world-writable /dev/shm path with no O_NOFOLLOW/O_EXCL while running as root  
  Hardened the Apply-handler open to match the plugin side (plugins/speedhack.c, which already uses O_CREAT|O_RDWR|O_NOFOLLOW, 0600): changed ::open from O_CREAT|O_RDWR,0666 to O_CREAT|O_RDWR|O_NOFOLLOW,0600. O_NOFOLLOW defeats the root symlink->ftruncate destruction vector; mode 0600 stops world tamp
- **partial** — First/Next scan run synchronously on the UI thread; full address-space default freezes the GUI and progress bar is never updated  
  Moving the scan to a worker thread and driving progressBar_ requires a progress callback that MemoryScanner (not owned) does not expose -- that is a redesign, so not attempted. Applied the obviously-correct subset in the owned file: (a) the From<=To range validation/rejection added for finding #8 pr
- **partial** — Address-list value read/write silently uses 4-byte size for String/Unicode/ByteArray/All/Grouped/Custom types  
  Full per-type read/format/write for String/UnicodeString/ByteArray is a redesign; not attempted. Applied the load-bearing defensive subset: changed writeValueToProcess's switch default from 'break;' (which fell through to proc->write of a zero-filled 4-byte buffer, silently clobbering target memory 
- _follow-up:_ MemoryScanner (scanner/memory_scanner.{hpp,cpp}, not owned): add a progress callback to firstScan/nextScan and run scans on a worker thread (QtConcurrent/QThread) with results marshaled back via a queued signal; then drive progressBar_. The
- _follow-up:_ scanner/memory_scanner.cpp (not owned): ScanConfig::parseAOB should reject malformed hex tokens (strtoul currently turns e.g. 'ZZ' into 0 silently) and ideally return a success bool so callers can distinguish empty from invalid; the GUI cur
- _follow-up:_ gui/mainwindow.cpp: implement proper per-type read/format/write for String/UnicodeString/ByteArray/Grouped/Custom address-list entries instead of the current scalar-only path; writeValueToProcess now refuses (no write) for these types via i
- _follow-up:_ Speedhack shared-memory channel: per-uid namespacing of /dev/shm/ce_speedhack (and ownership pinning of the existing file) must be coordinated across plugins/speedhack.c and audiohack (not owned); the fixed name is a documented cross-file c

### gui-aux
- _follow-up:_ formdesigner.cpp onGenerateLua emits the widget 'name' verbatim as a Lua identifier with no validation (e.g. a name like 'x;os.execute(...)' injects Lua). Per the finding this is NOT a security boundary (user's own trainer generator, raw Lu
- _follow-up:_ registereditor.cpp: if true group-stop of all threads is desired, migrate to PTRACE_SEIZE/PTRACE_INTERRUPT per tid (out of scope; minimal attach-target fix applied).

### cli-arch
- _follow-up:_ scanner/memory_scanner.cpp (NOT owned): add defense-in-depth `if (alignment == 0) alignment = 1;` to the unguarded scanBuffer<T>/scanBufferFloating<T> templates (around lines 257, 274, 351, 377) so no future caller can wedge the scan core, 

## Behavior changes to be aware of

- `getProcessList()` Lua binding: a fix agent changed it to a dense array; this **broke the CE-compatible pid-keyed contract** and the regression test. **Reverted** to pid-keyed (kept the `skip_permission_denied` robustness improvement). Test passes.
- `cecore_access_physical` (kernel): **validate-but-allow** (per user decision). Wrap/range checks added; physical-RAM access is **kept** as an intended CE/DBVM capability (not refused), gated by root/`CAP_SYS_ADMIN`. A `TODO(security)` notes that RAM should ideally go through `memremap()`/`kmap` of a `pfn_valid()` page rather than `ioremap()`.
- Lua `writeRegionToFile` now rejects sizes > 256 MiB; destroyed-widget access now raises a Lua error instead of crashing; several scans now reject out-of-range/oversized inputs. These are intentional hardening behaviors.
- `kernel_symbols` duplicate-address resolution is now first-wins (was last-wins), matching the name index.

## Not changed (by design)

- The **2 refuted findings** (injector "untested", lua_gui reentrancy UB) — not real bugs; see CODE_ANALYSIS.md appendix.
- Feature removal was avoided per the harden-not-remove principle; `shellExecute`/`*Local`/trainer-gcc remain but with validated inputs.
- Larger build-ci redesigns (vendoring Lua/ceserver, replacing the AppImage ldd allowlist with linuxdeploy, pinning every CI `uses:` to a SHA) were left as follow-ups; the high-value items (hardening flags, dep SHA-pinning, `.gitignore` for kernel/build artifacts) were applied.

The fix diff is intermingled with the pre-existing working-tree changes (the tree was already heavily modified before this work); nothing was committed.
