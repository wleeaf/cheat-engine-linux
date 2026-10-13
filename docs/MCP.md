# AI agents (MCP)

`cescan mcp` lets an AI agent drive Cheat Engine for you: find a value, narrow
it down as it changes in the game, confirm it, freeze it, and save a cheat
table you can open in the app. It speaks the Model Context Protocol over
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
| `first_scan`, `next_scan`, `undo_scan`, `scan_results` | Scan for a value and narrow the results |
| `read`, `write` | Read or change a typed value |
| `disassemble` | Show the code at an address, with symbols |
| `add_record`, `list_records`, `set_frozen`, `save_table` | Build, freeze and save a cheat table |

Results are short summaries (counts and the first candidates), never memory
dumps. Addresses in saved tables are module-relative (`game+0x301C`), so the
table keeps working after the game restarts.

## Example

> **You:** My health is 100 in the game window. Find it and keep it at 100.
>
> The agent attaches, scans for 100, asks you to take some damage, scans for
> the new value, confirms the address, freezes it at 100, and offers to save
> `game.CT`.

Use it on single-player games and software you are allowed to analyze.
