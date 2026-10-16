# AI agents

An AI model can drive Cheat Engine for you: find a value, narrow it down as it
changes in the game, freeze it, follow pointers, find the code that changes it,
write an Auto Assembler script that changes that code, and save a cheat table.
Use it from the app (the AI Assistant) or from another AI app over MCP; both
use the same tools.

## In the app: the AI Assistant

Open **Tools > AI Assistant** (Ctrl+Shift+I) and describe what you want, for
example "My health shows 100. Find it and keep it at 100." The assistant works
on the process you have open.

- **Your model, your key.** In **Settings > AI Assistant**, pick Anthropic
  (Claude) or any OpenAI-compatible API: OpenAI, or a model on your own
  computer with Ollama (`http://localhost:11434/v1`) or LM Studio. Paste your
  API key there; local servers usually need none.
- **Keys stay in your keyring.** The key is saved in the system keyring
  (GNOME Keyring, KWallet or any Secret Service), never in Cheat Engine's
  settings file. `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in the environment
  takes precedence, but only for that provider's own API: it is never sent to
  another server you enter as the API address. A saved key belongs to the API
  address it was entered for: change the address and it is not sent until you
  enter it again, and it is never sent over plain http except to this
  machine. Without a keyring the key lasts until Cheat Engine closes.
- **You approve every change.** Scanning, reading and disassembling run on
  their own; writing a value, freezing, enabling or disabling a script,
  watching which addresses an instruction accesses (a breakpoint in the game's
  code), saving a file and opening any process other than yours wait for your
  Allow in the panel. Allow for this chat covers only the process it was given
  for, and never opening another process or overwriting a file. Stop ends a
  turn at any time.
- **What leaves your computer.** Your messages and what the tools find in the
  game (process names, addresses, values, code) are sent to the provider you
  chose, and nothing else. With a local model nothing leaves your computer.
- **Keep the results.** Add to address list copies the values, pointer paths
  and scripts the assistant saved into your table. Scripts it enabled are
  undone when you close Cheat Engine or open another process.

## From another app: MCP

`cescan mcp` speaks the Model Context Protocol over stdin/stdout, so any MCP
client can drive Cheat Engine with the model of your choice.

### Connect

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
and disassembling work, while writing values, freezing, enabling and
disabling scripts, and `find_accessed_addresses` (which puts a breakpoint in
the game's code) are refused. Turning writes off ends any freeze. Scripts
checked or enabled by the agent cannot load libraries or binaries, include
local files, start threads or compile C code; both their [ENABLE] and
[DISABLE] sections are dry-run first. When the session ends or the agent
attaches elsewhere, its scripts are undone by restoring the saved bytes, not by
running their [DISABLE] sections. The server only talks to the
client that started it; it opens no network port.

### Tools

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

### Example

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
