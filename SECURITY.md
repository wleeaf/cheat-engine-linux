# Security Policy

## The important warning: untrusted cheat tables run code

This tool inspects and modifies other processes' memory. It is frequently run
with elevated privileges (`ptrace`, often under `sudo`), and its cheat-table
format is scriptable.

**Do not open `.CT` / `.CETRAINER` files from sources you do not trust.** A cheat
table can embed Lua that runs automatically. Opening a malicious table can
execute arbitrary code on your machine, typically with whatever privileges you
launched the tool with (i.e. root, if you used `sudo`). Treat a shared table like
a shared executable.

The dangerous parts of the Lua surface are **denied by default** and only
enabled by an out-of-band opt-in that a table's own script cannot set: the
environment variable `CECORE_LUA_ALLOW_UNSAFE=1`, set when Cheat Engine starts.
Without it, scripts get:

- no shell: `shellExecute`, `os.execute` and `io.popen` are gone;
- no native code or interpreter internals: no `package` (`loadlib`,
  `require`), no `debug` library, no `dofile`/`loadfile`, `string.dump`, and
  `load` accepts source text only (binary chunks are not verified by Lua);
- no file writes: `io.open` opens for reading only, and `writeToFile`,
  `saveTable`, `generateTrainer`, `readRegionToFile`, `writeRegionToFile`,
  `createFileStream` in a write mode and the `saveToFile` methods refuse;
- no writes to cecore's own memory: the `write*Local` functions refuse.

`os` keeps only the clock (`clock`, `date`, `difftime`, `time`). Reading files
and the rest of the target-memory API stay available, so the operational rule
still holds: only load tables you authored or trust.

A table never runs anything just by being opened: its records load switched
off (enabling an Auto Assembler record runs its script, `{$lua}` included),
its `<LuaScript>` runs only after you answer Yes, and checking a script in the
editor does not evaluate its `{$lua}` blocks. Every native binding is
additionally routed through a central exception firewall, so a C++ exception
escaping a binding becomes a Lua error instead of unwinding through liblua's C
frames.

## Your processes only

The `.deb` gives `cheatengine` and `cescan` the `cap_sys_ptrace` capability so
they can read your own games under the default Yama `ptrace_scope=1`. That
capability would reach every user's processes, so the tools refuse any process
whose user and group ids differ from yours, unless they really run as root.

Started with the capability, the program is a secure-exec process: before Qt
or any other library starts, it drops the environment variables that would
make a library load code from a path the user picks (Qt and QML plugin paths,
GTK and GIO modules, GL, VA-API and Vulkan driver and layer paths, ALSA
configuration), and the Lua `CECORE_LUA_ALLOW_UNSAFE` opt-in is ignored. glibc
already ignores `LD_PRELOAD` and `LD_LIBRARY_PATH` there. Otherwise any user on
the computer could run their own code with the capability, past these checks.
`cescan ceserver` listens on 127.0.0.1 only and accepts connections only from
programs of the user who started it: its protocol has no authentication.

## Running with least privilege

- Prefer running as your normal user with `/proc/sys/kernel/yama/ptrace_scope`
  set appropriately, or `PR_SET_PTRACER`, rather than blanket `sudo`, when the
  target permits it.
- The optional kernel module (`kernel/cecore_kmod.c`) only reads physical
  System RAM, for root with `CAP_SYS_ADMIN` and `CAP_SYS_RAWIO`, and refuses
  under kernel lockdown. It never writes physical memory, and process memory
  and address translation go through `/proc/<pid>/mem` and
  `/proc/<pid>/pagemap`, so ptrace, Yama and LSM checks always apply. Build
  it for the running kernel right before loading it (`make -C kernel clean
  all`, then `sudo insmod kernel/cecore_kmod.ko`); never load a `.ko` left
  from an older checkout or built elsewhere. Load it only if you need it, and
  unload it (`sudo rmmod cecore_kmod`) when done.

## Supported versions

Only the latest release and `main` receive fixes. This is pre-1.0 software.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:
open a GitHub **Security Advisory** on the repository
(`Security → Report a vulnerability`), or email the maintainer. Include a
description, affected version/commit, and a reproduction if possible. We aim to
acknowledge within a few days.
