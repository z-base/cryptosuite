import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { readdirSync } from "node:fs";
import process from "node:process";

const c8Bin = resolve("node_modules/c8/bin/c8.js");

function collectTests(dir) {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...collectTests(full));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".test.mjs")) {
      files.push(full);
    }
  }
  return files;
}

const testFiles = [
  ...collectTests(resolve("test/unit")),
  ...collectTests(resolve("test/integration")),
].sort();

if (testFiles.length === 0) {
  console.error("No test files found under test/unit or test/integration.");
  process.exit(1);
}

const args = [
  "--check-coverage",
  "--100",
  "--reporter=text",
  "--reporter=lcov",
  "--reporter=json-summary",
  "--all",
  "--include=dist/**/*.js",
  "--exclude=dist/**/*.d.ts",
  "--exclude=dist/**/*.map",
  "--exclude=test/**",
  "--exclude=benchmark/**",
  "--exclude=coverage/**",
  "--exclude=node_modules/**",
  process.execPath,
  "--test",
  ...testFiles,
];

const child = spawn(process.execPath, [c8Bin, ...args], {
  stdio: "inherit",
});
child.on("exit", (code) => {
  process.exit(code ?? 1);
});
