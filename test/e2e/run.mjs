import { spawn } from "node:child_process";
import { resolve } from "node:path";
import process from "node:process";

const cli = resolve("node_modules/playwright/cli.js");
const child = spawn(process.execPath, [cli, "test"], { stdio: "inherit" });
child.on("exit", (code) => {
  process.exit(code ?? 1);
});
