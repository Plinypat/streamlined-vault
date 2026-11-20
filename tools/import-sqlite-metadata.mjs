import { DatabaseSync } from "node:sqlite";
import { resolve } from "node:path";
import { postgresPool } from "../server/postgres.mjs";
import { postgresDatabase, migratePostgres } from "../server/database.mjs";

// Explicit offline import only. Never silently merge local data into a live DB.
const sourceIndex = process.argv.indexOf("--source");
if (
  sourceIndex < 0 ||
  !process.argv[sourceIndex + 1] ||
  !process.argv.includes("--confirm-empty-target")
) {
  console.error(
    "Usage: node --env-file=.env tools/import-sqlite-metadata.mjs --source <backup.sqlite> --confirm-empty-target",
  );
  process.exit(1);
}
const order = [
  "tenants",
  "members",
  "clerk_identities",
  "tokens",
  "devices",
  "enrollments",
  "device_runs",
  "workspace_storage",
  "storage_requests",
  "files",
  "parts",
  "audit",
  "automations",
  "notices",
];
let source, db;
try {
  source = new DatabaseSync(resolve(process.argv[sourceIndex + 1]), {
    readOnly: true,
  });
  db = postgresDatabase(
    postgresPool(
      process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL,
      {
        allowLocalTest:
          process.env.NODE_ENV === "test" &&
          process.env.TEST_DATABASE_LOCAL === "true",
      },
    ),
  );
  await migratePostgres(db);
  const counts = {};
  await db.transaction(async () => {
    await db.lock("metadata:offline-import");
    for (const table of [...order, "sessions"])
      if (
        Number(
          (await db.one(`SELECT COUNT(*) AS total FROM ${table}`)).total,
        ) !== 0
      )
        throw Error("TARGET_NOT_EMPTY");
    for (const table of order) {
      if (
        !source
          .prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
          )
          .get(table)
      ) {
        counts[table] = 0;
        continue;
      }
      const rows = source
        .prepare(
          `SELECT * FROM ${table}${table === "audit" ? " ORDER BY rowid" : ""}`,
        )
        .all();
      counts[table] = rows.length;
      const columns = (
        await db.q(
          "SELECT column_name FROM information_schema.columns WHERE table_schema=? AND table_name=? ORDER BY ordinal_position",
          "streamlined_vault",
          table,
        )
      )
        .map((x) => x.column_name)
        .filter((x) => x !== "seq");
      for (const row of rows) {
        const present = columns.filter((c) => Object.hasOwn(row, c));
        await db.run(
          `INSERT INTO ${table}(${present.map((c) => '"' + c + '"').join(",")}) VALUES(${present.map(() => "?").join(",")})`,
          ...present.map((c) => row[c]),
        );
      }
    }
  });
  console.log(
    JSON.stringify({
      imported: counts,
      sessions: "Not imported; sign in again",
      fileObjects: "Unchanged; original storage remains required",
    }),
  );
} catch (e) {
  console.error(
    JSON.stringify({
      event: "metadata_import_failed",
      code:
        e.message === "TARGET_NOT_EMPTY"
          ? "TARGET_NOT_EMPTY"
          : /^[A-Z0-9_]+$/.test(e.code || "")
            ? e.code
            : "IMPORT_CONFIGURATION",
    }),
  );
  process.exitCode = 1;
} finally {
  source?.close();
  if (db) await db.close();
}
