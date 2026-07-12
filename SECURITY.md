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

The two most dangerous parts of the Lua surface are **denied by default** and
only enabled by an out-of-band opt-in that a table's own script cannot set — the
environment variable `CECORE_LUA_ALLOW_UNSAFE=1`, launched with the process:

- `shellExecute` — runs arbitrary shell commands.
- the `write*Local` functions — write cecore's *own* address space, which a
  malicious table could use to patch cecore's code/GOT and hijack the process.

The `read*Local` functions (host-memory read / info disclosure) and the rest of
the target-memory API stay available, so the operational rule still holds: only
load tables you authored or trust. A central Lua exception firewall is tracked in
`ROADMAP.md`.

## Running with least privilege

- Prefer running as your normal user with `/proc/sys/kernel/yama/ptrace_scope`
  set appropriately, or `PR_SET_PTRACER`, rather than blanket `sudo`, when the
  target permits it.
- The optional kernel module (`kernel/cecore_kmod.ko`) exposes a privileged
  memory-access device; only load it if you need it, and unload it when done.

## Supported versions

Only the latest release and `main` receive fixes. This is pre-1.0 software.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:
open a GitHub **Security Advisory** on the repository
(`Security → Report a vulnerability`), or email the maintainer. Include a
description, affected version/commit, and a reproduction if possible. We aim to
acknowledge within a few days.
