#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec, execSync } from "child_process";
import path from "path";
import fs from "fs";

// -------------------------------------------------------------
// CLI Arguments & Configuration Parsing
// -------------------------------------------------------------
function parseArgs() {
  const args = process.argv.slice(2);
  const config = {
    allowDestructive: false,
    allowedPaths: [],
  };

  for (const arg of args) {
    if (arg.startsWith("--allow-destructive=")) {
      config.allowDestructive = arg.replace("--allow-destructive=", "").toLowerCase() === "true";
    } else if (arg.startsWith("--allowed-paths=")) {
      const paths = arg.replace("--allowed-paths=", "").split(",").map((p) => path.resolve(p.trim()));
      config.allowedPaths = paths;
    }
  }

  return config;
}

const SERVER_CONFIG = parseArgs();

// -------------------------------------------------------------
// Command Classification & Safety Patterns
// -------------------------------------------------------------
const PROHIBITED_PATTERNS = [
  /\bformat\s+[a-z]:/i,                   // format c:
  /\b(del|rm|rmdir)\s+.*[\\\/]Windows\b/i, // targets system directory
  /\breg\s+(add|delete|restore)/i,         // registry modification
  /\bnet\s+user\b/i,                       // user account modification
  /\bshutdown\b/i,                         // system shutdown
  /\bchmod\s+(-R\s+)?777\s+\//i,           // dangerous root chmod
  /\b(mkfs|dd\s+if=)/i,                    // raw disk tampering
];

const DESTRUCTIVE_PATTERNS = [
  /\brm\s+-[rf]{1,2}\b/i,                  // rm -rf
  /\brmdir\s+\/s\b/i,                      // rmdir /s
  /\bdel\s+\/[fq]\s+\*/i,                  // del /f /q *
  /\bgit\s+reset\s+--hard\b/i,             // git reset --hard
  /\bgit\s+clean\s+-[fdx]{2,4}\b/i,        // git clean -fdx
];

const READONLY_PATTERNS = [
  /^(git\s+(status|log|diff|show|branch|remote))/i,
  /^(dir|ls|cat|type|head|tail|more|less|grep|findstr|which|where)\b/i,
  /^(node|npm|composer|php|python|git|tsc)\s+(-v|--version|-h|--help)\b/i,
  /^(npm\s+test|composer\s+test|php\s+artisan\s+test)\b/i,
];

function classifyCommand(cmd) {
  const trimmed = cmd.trim();

  for (const pattern of PROHIBITED_PATTERNS) {
    if (pattern.test(trimmed)) return "prohibited";
  }
  for (const pattern of DESTRUCTIVE_PATTERNS) {
    if (pattern.test(trimmed)) return "destructive";
  }
  for (const pattern of READONLY_PATTERNS) {
    if (pattern.test(trimmed)) return "read-only";
  }
  return "mutating";
}

// -------------------------------------------------------------
// Terminal Engine Discovery & Priority Resolution
// -------------------------------------------------------------
function detectEngines() {
  const platform = process.platform;
  const engines = {};

  if (platform === "win32") {
    // 1. Check Git Bash common locations & PATH
    const gitBashCandidates = [
      "C:\\Program Files\\Git\\bin\\bash.exe",
      "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
      path.join(process.env.LOCALAPPDATA || "", "Programs", "Git", "bin", "bash.exe"),
      path.join(process.env.USERPROFILE || "", "scoop", "apps", "git", "current", "bin", "bash.exe"),
    ];

    for (const candidate of gitBashCandidates) {
      if (candidate && fs.existsSync(candidate)) {
        engines["git-bash"] = candidate;
        break;
      }
    }

    if (!engines["git-bash"]) {
      try {
        const whereBash = execSync("where bash", { stdio: ["ignore", "pipe", "ignore"] })
          .toString()
          .split(/\r?\n/)[0]
          ?.trim();
        if (whereBash && fs.existsSync(whereBash)) {
          engines["git-bash"] = whereBash;
        }
      } catch {}
    }

    // 2. Check cmd.exe (Primary built-in on Windows)
    const comSpec = process.env.ComSpec || "C:\\Windows\\System32\\cmd.exe";
    if (fs.existsSync(comSpec)) {
      engines["cmd"] = comSpec;
    } else {
      engines["cmd"] = "cmd.exe";
    }

    // 3. Check PowerShell
    const powershellPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    if (fs.existsSync(powershellPath)) {
      engines["powershell"] = powershellPath;
    }
  } else if (platform === "darwin") {
    // macOS
    if (fs.existsSync("/bin/bash")) engines["bash"] = "/bin/bash";
    if (fs.existsSync("/opt/homebrew/bin/bash")) engines["bash"] = "/opt/homebrew/bin/bash";
    if (fs.existsSync("/usr/local/bin/bash")) engines["bash"] = "/usr/local/bin/bash";
    if (fs.existsSync("/bin/zsh")) engines["zsh"] = "/bin/zsh";
    if (fs.existsSync("/bin/sh")) engines["sh"] = "/bin/sh";
  } else {
    // Linux / other POSIX
    if (fs.existsSync("/bin/bash")) engines["bash"] = "/bin/bash";
    if (fs.existsSync("/usr/bin/bash")) engines["bash"] = "/usr/bin/bash";
    if (fs.existsSync("/bin/zsh")) engines["zsh"] = "/bin/zsh";
    if (fs.existsSync("/bin/sh")) engines["sh"] = "/bin/sh";
  }

  return engines;
}

function resolveEngine(requestedEngine, engines) {
  const platform = process.platform;

  if (requestedEngine && engines[requestedEngine]) {
    return { name: requestedEngine, path: engines[requestedEngine] };
  }

  // Priority 1: Git-Bash / Bash
  if (platform === "win32") {
    if (engines["git-bash"]) return { name: "git-bash", path: engines["git-bash"] };
    if (engines["cmd"]) return { name: "cmd", path: engines["cmd"] };
    if (engines["powershell"]) return { name: "powershell", path: engines["powershell"] };
  } else if (platform === "darwin") {
    if (engines["bash"]) return { name: "bash", path: engines["bash"] };
    if (engines["zsh"]) return { name: "zsh", path: engines["zsh"] };
    if (engines["sh"]) return { name: "sh", path: engines["sh"] };
  } else {
    if (engines["bash"]) return { name: "bash", path: engines["bash"] };
    if (engines["sh"]) return { name: "sh", path: engines["sh"] };
    if (engines["zsh"]) return { name: "zsh", path: engines["zsh"] };
  }

  return { name: "default", path: true };
}

// -------------------------------------------------------------
// Execution Core
// -------------------------------------------------------------
function executeCommand(command, workingDir, selectedEngine, timeout) {
  const startTime = Date.now();

  return new Promise((resolve) => {
    let resolved = false;

    const safeResolve = (payload, isError = false) => {
      if (resolved) return;
      resolved = true;
      resolve({
        content: [
          {
            type: "text",
            text: JSON.stringify(payload, null, 2),
          },
        ],
        isError,
      });
    };

    try {
      const child = exec(
        command,
        {
          cwd: workingDir,
          shell: selectedEngine.path,
          maxBuffer: 10 * 1024 * 1024, // 10MB buffer
          timeout: timeout,
          windowsHide: true,
        },
        (error, stdout, stderr) => {
          const durationMs = Date.now() - startTime;
          const isTimeout = Boolean(error && error.killed && error.signal === "SIGTERM");

          const result = {
            success: !error,
            exitCode: error && error.code !== undefined ? error.code : (error ? 1 : 0),
            engineUsed: selectedEngine.name,
            cwd: workingDir,
            durationMs,
            stdout: stdout ? stdout.trim() : "",
            stderr: stderr ? stderr.trim() : "",
            timedOut: isTimeout,
          };

          if (isTimeout) {
            result.diagnostic = `Command timed out after ${timeout}ms. Check if it was waiting for interactive input.`;
          }

          safeResolve(result, result.exitCode !== 0);
        }
      );

      // Intercept OS-level process blocking (AppLocker / WDAC spawn failures)
      child.on("error", (spawnError) => {
        safeResolve(
          {
            success: false,
            exitCode: 1,
            error: "EngineSpawnFailed",
            engineUsed: selectedEngine.name,
            message: `Failed to launch shell engine '${selectedEngine.name}': ${spawnError.message}. The executable is likely blocked by workstation security policy (AppLocker/WDAC) or does not exist.`,
          },
          true
        );
      });
    } catch (err) {
      safeResolve(
        {
          success: false,
          exitCode: 1,
          error: "EngineExecutionFailed",
          engineUsed: selectedEngine.name,
          message: `Unexpected error starting command: ${err.message}`,
        },
        true
      );
    }
  });
}

function validateWorkingDir(cwd) {
  const workingDir = cwd ? path.resolve(cwd) : process.cwd();
  if (!fs.existsSync(workingDir)) {
    throw new Error(`Specified working directory does not exist: ${workingDir}`);
  }

  if (SERVER_CONFIG.allowedPaths.length > 0) {
    const isAllowed = SERVER_CONFIG.allowedPaths.some((allowed) => workingDir.startsWith(allowed));
    if (!isAllowed) {
      throw new Error(`Working directory '${workingDir}' is outside whitelisted paths: [${SERVER_CONFIG.allowedPaths.join(", ")}]`);
    }
  }

  return workingDir;
}

// -------------------------------------------------------------
// MCP Server Initialization
// -------------------------------------------------------------
const server = new Server(
  {
    name: "command-runner",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  const engines = detectEngines();
  const availableEngineList = Object.keys(engines).join(", ");

  return {
    tools: [
      {
        name: "execute_readonly_command",
        description:
          "Execute safe, read-only terminal commands (e.g. git status, git log, dir, ls, cat, grep, npm test). " +
          `Available shell engines: [${availableEngineList}]. Git Bash prioritized by default.`,
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "The read-only shell command to execute" },
            cwd: { type: "string", description: "Optional working directory" },
            engine: { type: "string", description: "Optional engine preference ('git-bash', 'cmd', 'bash', 'zsh', 'sh')" },
            timeout: { type: "number", description: "Optional timeout in ms (default: 120000)" },
          },
          required: ["command"],
        },
      },
      {
        name: "execute_mutating_command",
        description:
          "Execute project build and development commands that modify workspace files (e.g. npm install, composer, git commit, build). " +
          `Available shell engines: [${availableEngineList}]. Git Bash prioritized by default.`,
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "The mutating dev shell command to execute" },
            cwd: { type: "string", description: "Optional working directory" },
            engine: { type: "string", description: "Optional engine preference ('git-bash', 'cmd', 'bash', 'zsh', 'sh')" },
            timeout: { type: "number", description: "Optional timeout in ms (default: 120000)" },
          },
          required: ["command"],
        },
      },
      {
        name: "execute_destructive_command",
        description:
          "Execute potentially destructive commands (e.g. rm -rf, rmdir /s, git reset --hard, del /f /q). " +
          "Can be toggled ON or OFF in Antigravity's 'Manage MCP servers' menu.",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "The destructive shell command to execute" },
            cwd: { type: "string", description: "Optional working directory" },
            confirm: { type: "boolean", description: "Must be true to confirm deliberate destructive execution" },
            engine: { type: "string", description: "Optional engine preference ('git-bash', 'cmd', 'bash', 'zsh', 'sh')" },
            timeout: { type: "number", description: "Optional timeout in ms (default: 120000)" },
          },
          required: ["command", "confirm"],
        },
      },
      {
        name: "execute_command",
        description:
          "General unified terminal runner. Executes commands across Windows, macOS, and Linux, " +
          "automatically routing to Git Bash (priority 1) or OS built-in shell. Destructive commands will be rejected.",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "The shell command to execute" },
            cwd: { type: "string", description: "Optional working directory" },
            engine: { type: "string", description: "Optional engine preference ('git-bash', 'cmd', 'bash', 'zsh', 'sh')" },
            timeout: { type: "number", description: "Optional timeout in ms (default: 120000)" },
          },
          required: ["command"],
        },
      },
      {
        name: "get_terminal_info",
        description: "Returns host platform, available terminal engines, active security rules, and whitelisted directories.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const engines = detectEngines();

  // 1. Info Tool
  if (name === "get_terminal_info") {
    const selectedDefault = resolveEngine(null, engines);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              platform: process.platform,
              arch: process.arch,
              detectedEngines: engines,
              defaultSelectedEngine: selectedDefault,
              serverConfiguration: {
                allowDestructive: SERVER_CONFIG.allowDestructive,
                allowedPaths: SERVER_CONFIG.allowedPaths,
              },
            },
            null,
            2
          ),
        },
      ],
      isError: false,
    };
  }

  // 2. Command Execution Handlers
  const { command, cwd, engine: requestedEngine, timeout = 120000, confirm } = args || {};

  if (!command || typeof command !== "string") {
    throw new Error("Missing or invalid 'command' parameter");
  }

  const classification = classifyCommand(command);

  // Prohibited commands are unconditionally blocked
  if (classification === "prohibited") {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              success: false,
              exitCode: 1,
              error: "SecurityViolation",
              classification,
              message: "Command blocked: Matches prohibited system pattern (formatting, registry modification, or system root tampering).",
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }

  let workingDir;
  try {
    workingDir = validateWorkingDir(cwd);
  } catch (err) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ success: false, exitCode: 1, error: "InvalidWorkingDirectory", message: err.message }, null, 2),
        },
      ],
      isError: true,
    };
  }

  const selectedEngine = resolveEngine(requestedEngine, engines);

  // Tool 1: execute_readonly_command
  if (name === "execute_readonly_command") {
    if (classification === "destructive") {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                success: false,
                exitCode: 1,
                error: "TierMismatch",
                message: "Command is destructive. You must use 'execute_destructive_command'.",
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
    return executeCommand(command, workingDir, selectedEngine, timeout);
  }

  // Tool 2: execute_mutating_command
  if (name === "execute_mutating_command") {
    if (classification === "destructive") {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                success: false,
                exitCode: 1,
                error: "TierMismatch",
                message: "Command is destructive. You must use 'execute_destructive_command'.",
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
    return executeCommand(command, workingDir, selectedEngine, timeout);
  }

  // Tool 3: execute_destructive_command
  if (name === "execute_destructive_command") {
    if (!confirm) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                success: false,
                exitCode: 1,
                error: "ConfirmationRequired",
                message: "Destructive command execution requires 'confirm: true' in tool arguments.",
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
    return executeCommand(command, workingDir, selectedEngine, timeout);
  }

  // Tool 4: execute_command (General unified)
  if (name === "execute_command") {
    if (classification === "destructive") {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                success: false,
                exitCode: 1,
                error: "DestructiveCommandBlocked",
                classification,
                message: "Command blocked: Appears potentially destructive. To execute, call 'execute_destructive_command' with 'confirm: true'.",
              },
              null,
              2
            ),
          },
        ],
        isError: true,
      };
    }
    return executeCommand(command, workingDir, selectedEngine, timeout);
  }

  throw new Error(`Tool not found: ${name}`);
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal error starting command-runner MCP server:", err);
  process.exit(1);
});
