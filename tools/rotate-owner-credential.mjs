import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { postgresPool } from "../server/postgres.mjs";
const file = resolve(".env.owner"),
  temporary = resolve(".env.owner.next");
let pool, check;
const quote = (s) => "'" + s.replaceAll("'", "''") + "'";
try {
  if (
    !process.argv.includes("--confirm-owner-rotation") ||
    existsSync(temporary)
  )
    throw Error("Explicit confirmation and a new temporary path are required");
  process.loadEnvFile(file);
  const original = process.env.DATABASE_MIGRATION_URL,
    url = new URL(original),
    oldPassword = decodeURIComponent(url.password),
    role = decodeURIComponent(url.username);
  if (role !== "neondb_owner") throw Error("Unexpected owner role");
  const runtime = new URL(
    readFileSync(".env.runtime-production", "utf8")
      .trim()
      .slice("DATABASE_URL=".length),
  );
  if (runtime.username === url.username)
    throw Error("Runtime still uses the owner role");
  const password = randomBytes(32).toString("base64url");
  url.password = password;
  writeFileSync(temporary, "DATABASE_MIGRATION_URL=" + url.toString() + "\n", {
    flag: "wx",
    mode: 0o600,
  });
  if (
    process.platform === "win32" &&
    spawnSync(
      "icacls.exe",
      [
        temporary,
        "/inheritance:r",
        "/grant:r",
        process.env.USERDOMAIN + "\\" + process.env.USERNAME + ":(F)",
        "*S-1-5-18:(F)",
      ],
      { stdio: "ignore", windowsHide: true },
    ).status !== 0
  )
    throw Error("Could not protect new owner connection");
  pool = postgresPool(original);
  const operator = await pool.connect();
  try {
    await operator.query(
      'ALTER ROLE "neondb_owner" PASSWORD ' + quote(password),
    );
    check = postgresPool(url.toString());
    try {
      await check.query("SELECT 1");
    } catch {
      await operator.query(
        'ALTER ROLE "neondb_owner" PASSWORD ' + quote(oldPassword),
      );
      throw Error("New connection did not verify; original password restored");
    }
    renameSync(temporary, file);
  } finally {
    operator.release();
  }
  console.log(
    JSON.stringify({
      rotated: true,
      newOwnerConnectionVerified: true,
      protectedOwnerFile: file,
      runtimeConnectionUnchanged: true,
      storageEncryptionKeyUnchanged: true,
    }),
  );
} catch {
  console.error(
    JSON.stringify({
      rotated: false,
      message:
        "Owner rotation did not finish. Review the protected owner files before another attempt; no secrets were logged.",
    }),
  );
  process.exitCode = 1;
} finally {
  await pool?.end();
  await check?.end();
}
