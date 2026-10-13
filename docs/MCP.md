# AI agents (MCP)

`cescan mcp` lets an AI agent drive Cheat Engine for you: find a value, narrow
it down as it changes in the game, freeze it, find the code that changes it,
write an Auto Assembler script that changes that code, and save a cheat table
you can open in the app. It speaks the Model Context Protocol over
stdin/stdout, so any MCP client can use it, with the model of your choice.

## Connect

Claude Code:

```bash
claude mcp add cheat-engine -- cescan mcp --allow-writes
```

Claude Desktop and other clients take the same command in their MCP server
settings, for example:

```json
{ "mcpServers": { "cheat-engine": { "command": "cescan", "args": ["mcp", "--allow-writes"] } } }
```

Without `--allow-writes` the agent can look but not touch: scanning, reading
and disassembling work, while writing values and freezing are refused. The
server only talks to the client that started it; it opens no network port.

## Tools

| Tool | What it does |
|---|---|
| `list_processes`, `attach`, `target_info` | Find and open the game |
| `first_scan`, `next_scan`, `undo_scan`, `scan_results` | Scan for a value and narrow the results (including increased or decreased by an amount) |
| `read`, `write` | Read or change a typed value |
| `disassemble` | Show the code at an address, with symbols |
| `find_what_writes` | Watch an address and report the instructions that write to it, with the pointer each one followed |
| `find_accessed_addresses` | Watch one instruction and list every address it touches (code shared by player and enemies) |
| `compare_structures` | Dissect structures side by side and find the field that tells two groups apart, such as a team |
| `pointer_scan`, `pointer_rescan` | Find pointer paths to a value the game moves, and keep the ones that still work after it moves |
| `aa_template` | Build a code-injection script for an instruction |
| `aa_check` | Check a script by assembling it against the game without changing anything |
| `aa_enable`, `aa_disable`, `aa_list` | Apply a script to the game and undo it |
| `add_record`, `list_records`, `set_frozen`, `save_table` | Build, freeze and save a cheat table, including pointer paths (followed on every freeze) and scripts |

Results are short summaries (counts and the first candidates), never memory
dumps. Scripts are checked by assembling them against the live game with every
change kept aside, so a misspelled instruction or an `assert` that no longer
matches is reported before anything is patched. Agent scripts cannot run
embedded Lua (`{$lua}`), and when the session ends every script the agent
enabled is disabled, restoring the original code. Addresses in saved tables are module-relative (`game+0x301C`), so the
table keeps working after the game restarts.

## Example

> **You:** My health is 100 in the game window. Find it and keep it at 100.
>
> The agent attaches, scans for 100, asks you to take some damage, scans for
> the new value, confirms the address, freezes it at 100, and offers to save
> `game.CT`.
>
> **You:** Make health never go down instead.
>
> The agent watches what writes health while you take damage, builds an
> injection at that instruction, removes the store, checks and enables the
> script, asks you to confirm, and saves it to the table as "Infinite health".

## Try it on the tutorials

`cetutorial` and `cegtutorial` (also in the app's Help menu) are games made to
be changed. Ask the agent to finish a step, for example "Do step 9 of the
tutorial". `test/tutorial_gate.py` plays every step and level through these
tools the way an agent would, and runs in CI.

Use it on single-player games and software you are allowed to analyze.
