# @eldinbiz/mcp-server-command-runner

> A cross-platform MCP server enabling AI agents to autonomously execute terminal commands on workstations with strict execution policies.

---

## Setup

### Option 1: Run with `npx` (Public Package)
Add directly to your IDE's MCP configuration (e.g., `mcp_config.json`):

```json
{
  "mcpServers": {
    "command-runner": {
      "command": "npx",
      "args": ["-y", "@eldinbiz/mcp-server-command-runner"]
    }
  }
}
```

### Option 2: Local Installation (Development)
1. Clone the repository and install dependencies:
   ```bash
   git clone https://github.com/eldinbiz/mcp-server-command-runner.git
   cd mcp-server-command-runner
   npm install
   ```

2. Register the local script in your MCP configuration (`mcp_config.json`):
   ```json
   {
     "mcpServers": {
       "command-runner": {
         "command": "node",
         "args": [
           "c:/Users/Public/Downloads/projects/mcp-direct-cli-command/mcp-command-run/index.js"
         ]
       }
     }
   }
   ```

---

## Configuration Details

### 1. Interactive UI Toggles in Antigravity IDE
Open **Manage MCP servers** in Antigravity IDE to toggle individual capabilities ON or OFF:

- **`execute_readonly_command`** `[ON/OFF]`: Safe inspection commands (`git status`, `dir`, `ls`, tests, `cat`, `grep`).
- **`execute_mutating_command`** `[ON/OFF]`: Project build and modifying commands (`npm install`, `composer`, `git commit`).
- **`execute_destructive_command`** `[ON/OFF]`: High-risk operations (`rm -rf`, `git reset --hard`, `del /f /q`).
- **`execute_command`** `[ON/OFF]`: General runner with built-in safety classifier.
- **`get_terminal_info`** `[ON/OFF]`: Introspects host platform, detected engines, and active rules.

> [!TIP]
> Toggling **`execute_destructive_command`** OFF in the UI ensures the AI agent is physically incapable of running destructive deletion or repository wipe commands.

### 2. Command-Line Arguments (`args` in `mcp_config.json`)
You can pass optional arguments to enforce process-level constraints:

```json
{
  "mcpServers": {
    "command-runner": {
      "command": "node",
      "args": [
        "c:/Users/Public/Downloads/projects/mcp-direct-cli-command/mcp-command-run/index.js",
        "--allow-destructive=false",
        "--allowed-paths=C:/Users/Public/Downloads/projects"
      ]
    }
  }
}
```

- `--allow-destructive=<boolean>`: Globally permits or forbids destructive commands. Default: `false`.
- `--allowed-paths=<paths>`: Comma-separated whitelist of allowed working directory roots. Commands targeting outside directories are rejected. Default: unrestricted.

---

## License

MIT © [eldinbiz](https://github.com/eldinbiz)
