#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

function candidates() {
  const configured = process.env.CLOVERSEC_CTF_PYTHON || process.env.PYTHON;
  const items = [];
  if (configured) {
    const parts = configured.split(/\s+/).filter(Boolean);
    if (parts.length > 0) {
      items.push(parts);
    }
  }
  items.push(["python3"], ["python"], ["py", "-3"]);
  return items;
}

function findPython() {
  for (const item of candidates()) {
    const result = spawnSync(item[0], [...item.slice(1), "--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.status === 0) {
      return item;
    }
  }
  return null;
}

const target = process.argv[2];
if (!target) {
  console.error("usage: mcp_python_launcher.mjs <python-script> [args...]");
  process.exit(2);
}

const scriptPath = path.resolve(process.cwd(), target);
if (!existsSync(scriptPath)) {
  console.error(`MCP script not found: ${scriptPath}`);
  process.exit(2);
}

const python = findPython();
if (!python) {
  console.error("Python runtime not found. Tried CLOVERSEC_CTF_PYTHON, PYTHON, python3, python, and py -3.");
  process.exit(127);
}

const env = {
  ...process.env,
  PYTHONUNBUFFERED: "1",
  PYTHONUTF8: "1",
  PYTHONIOENCODING: "utf-8",
};

const child = spawnSync(python[0], [...python.slice(1), scriptPath, ...process.argv.slice(3)], {
  cwd: process.cwd(),
  env,
  stdio: "inherit",
});

if (child.error) {
  console.error(child.error.message);
  process.exit(1);
}
process.exit(child.status ?? 1);
