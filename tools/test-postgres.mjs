import { spawn } from "node:child_process";
if (!process.env.TEST_POSTGRES_URL) {
  console.error(
    "Set TEST_POSTGRES_URL to a local synthetic sv_test database before running this suite.",
  );
  process.exit(1);
}
const child = spawn(process.execPath, ["--test", "tests/security.test.mjs"], {
  env: process.env,
  stdio: "inherit",
});
child.on("error", () => {
  console.error("Could not start Postgres verification");
  process.exitCode = 1;
});
child.on("exit", (code) => (process.exitCode = code ?? 1));
