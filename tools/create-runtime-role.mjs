import { randomBytes } from "node:crypto";
import { writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { postgresDatabase } from "../server/database.mjs";
import { postgresPool } from "../server/postgres.mjs";
const flag = (name) => process.argv[process.argv.indexOf(name) + 1];
let db;
try {
  if (
    !process.argv.includes("--confirm-create-role") ||
    !process.argv.includes("--output")
  )
    throw Error(
      "Explicit role creation confirmation and protected output path are required",
    );
  const output = resolve(flag("--output"));
  if (existsSync(output)) throw Error("Output exists");
  const source = process.env.DATABASE_MIGRATION_URL;
  if (!source)
    throw Error("An owner connection is required in DATABASE_MIGRATION_URL");
  db = postgresDatabase(postgresPool(source));
  const name = "sv_runtime_" + randomBytes(6).toString("hex"),
    password = randomBytes(32).toString("hex");
  const database = (await db.one("SELECT current_database() AS name")).name;
  const quote = (s) => '"' + s.replaceAll('"', '""') + '"';
  await db.transaction(async () => {
    await db.exec(
      `CREATE ROLE ${quote(name)} LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`,
    );
    await db.exec(
      `GRANT CONNECT ON DATABASE ${quote(database)} TO ${quote(name)}`,
    );
    await db.exec(`GRANT USAGE ON SCHEMA streamlined_vault TO ${quote(name)}`);
    await db.exec(
      `GRANT SELECT ON ALL TABLES IN SCHEMA streamlined_vault TO ${quote(name)}`,
    );
    const mutable = [
      "tenants",
      "members",
      "sessions",
      "clerk_identities",
      "files",
      "parts",
      "automations",
      "tokens",
      "notices",
      "devices",
      "enrollments",
      "device_runs",
      "workspace_storage",
      "storage_requests",
      "service_settings",
      "workspace_plans",
      "transfer_events",
      "provider_inventory",
      "upload_part_grants",
      "security_state",
      "security_alerts",
      "security_checks",
    ];
    for (const table of mutable)
      await db.exec(
        `GRANT INSERT,UPDATE,DELETE ON streamlined_vault.${quote(table)} TO ${quote(name)}`,
      );
    for (const table of ["audit", "security_events", "audit_archives"])
      await db.exec(
        `GRANT INSERT ON streamlined_vault.${quote(table)} TO ${quote(name)}`,
      );
    await db.exec(
      `GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA streamlined_vault TO ${quote(name)}`,
    );
    const url = new URL(source);
    url.username = name;
    url.password = password;
    writeFileSync(output, "DATABASE_URL=" + url.toString() + "\n", {
      flag: "wx",
      mode: 0o600,
    });
    if (process.platform === "win32") {
      const owner = process.env.USERDOMAIN + "\\" + process.env.USERNAME;
      if (
        spawnSync(
          "icacls.exe",
          [
            output,
            "/inheritance:r",
            "/grant:r",
            owner + ":(F)",
            "*S-1-5-18:(F)",
          ],
          { stdio: "ignore", windowsHide: true },
        ).status !== 0
      )
        throw Error("Could not restrict output permissions");
    }
  });
  console.log(
    JSON.stringify({
      ok: true,
      role: name,
      output,
      action:
        "Set production DATABASE_URL from the protected file, keep the owner credential outside the runtime, redeploy and rerun the database security check. Run future migrations separately using the owner credential.",
    }),
  );
} catch {
  console.error(
    JSON.stringify({
      event: "runtime_role_setup_failed",
      message:
        "Check the owner environment, explicit confirmation and new protected output path. No credentials were logged.",
    }),
  );
  process.exitCode = 1;
} finally {
  await db?.close();
}
