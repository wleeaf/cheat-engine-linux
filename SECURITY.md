# Security Policy

## The important warning: untrusted cheat tables run code

This tool inspects and modifies other processes' memory. It is frequently run
with elevated privileges (`ptrace`, often under `sudo`), and its cheat-table
format is scriptable.

**Do not open `.CT` / `.CETRAINER` files from sources you do not trust.** A cheat
table can embed Lua that runs automatically, and the Lua surface includes
arbitrary command execution (`shellExecute`) and arbitrary host-memory read/write
(the `*Local` functions). Opening a malicious table can therefore execute
arbitrary code on your machine, typically with whatever privileges you launched
the tool with (i.e. root, if you used `sudo`). Treat a shared table like a shared
executable.

Hardening of this surface (an opt-in trust/consent gate and a central Lua
exception firewall) is tracked in `ROADMAP.md` (P1). Until then, the mitigation
is operational: only load tables you authored or trust.

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
