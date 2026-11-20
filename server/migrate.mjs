import { postgresDatabase, migratePostgres } from "./database.mjs";
import { postgresPool } from "./postgres.mjs";
const db = postgresDatabase(
  postgresPool(process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL),
);
try {
  await migratePostgres(db);
  console.log(
    "Postgres metadata schema is current. No file objects or existing SQLite records were changed.",
  );
} catch (e) {
  console.error(
    JSON.stringify({
      event: "metadata_migration_failed",
      code: /^[A-Z0-9_]+$/.test(e.code || "")
        ? e.code
        : "DATABASE_CONFIGURATION",
    }),
  );
  process.exitCode = 1;
} finally {
  await db.close();
}
