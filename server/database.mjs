import { AsyncLocalStorage } from "node:async_hooks";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { postgresPool } from "./postgres.mjs";

const tables = [
  "tenants",
  "members",
  "sessions",
  "clerk_identities",
  "files",
  "parts",
  "audit",
  "automations",
  "tokens",
  "notices",
  "devices",
  "enrollments",
  "device_runs",
  "workspace_storage",
  "storage_requests",
  "schema_migrations",
  "service_settings",
  "workspace_plans",
  "transfer_events",
  "provider_inventory",
  "upload_part_grants",
];
export function postgresSql(sql) {
  let n = 0;
  const names = tables.join("|");
  return (sql.match(/'(?:''|[^'])*'|"(?:""|[^"])*"|[^'"]+/g) || [])
    .map((part) => {
      if (part.startsWith("'") || part.startsWith('"')) return part;
      return part
        .replace(/\?/g, () => "$" + ++n)
        .replace(/\browid\b/g, "seq")
        .replace(
          new RegExp(
            "\\b(FROM|JOIN|INTO|UPDATE|REFERENCES|TABLE(?: IF NOT EXISTS)?)\\s+(" +
              names +
              ")\\b",
            "gi",
          ),
          (_, prefix, name) => prefix + " streamlined_vault." + name,
        );
    })
    .join("");
}

// All operations share an async API. A transaction always retains one connection.
export function sqliteDatabase(raw) {
  if (raw.kind) return raw;
  const context = new AsyncLocalStorage();
  let queue = Promise.resolve();
  async function exclusive(fn) {
    const previous = queue;
    let release;
    queue = new Promise((r) => (release = r));
    await previous;
    try {
      return await fn();
    } finally {
      release();
    }
  }
  const execute = (fn) =>
    context.getStore() ? Promise.resolve().then(fn) : exclusive(fn);
  const db = {
    kind: "sqlite",
    raw,
    q: (sql, ...args) => execute(() => raw.prepare(sql).all(...args)),
    one: (sql, ...args) => execute(() => raw.prepare(sql).get(...args)),
    run: (sql, ...args) => execute(() => raw.prepare(sql).run(...args)),
    exec: (sql) => execute(() => raw.exec(sql)),
    hasColumn: async (table, column) =>
      (await db.q(`PRAGMA table_info(${table})`)).some(
        (c) => c.name === column,
      ),
    transaction: async (fn) => {
      if (context.getStore()) return fn();
      return exclusive(() =>
        context.run(true, async () => {
          raw.exec("BEGIN IMMEDIATE");
          try {
            const result = await fn();
            raw.exec("COMMIT");
            return result;
          } catch (e) {
            raw.exec("ROLLBACK");
            throw e;
          }
        }),
      );
    },
    lock: async () => {
      if (!context.getStore())
        throw Error("A database lock requires a transaction");
    },
    close: () => execute(() => raw.close()),
  };
  return db;
}

export function postgresDatabase(pool) {
  const context = new AsyncLocalStorage();
  const query = (sql, args = []) =>
    (context.getStore() || pool).query(postgresSql(sql), args);
  const db = {
    kind: "postgres",
    pool,
    q: async (sql, ...args) => (await query(sql, args)).rows,
    one: async (sql, ...args) => (await query(sql, args)).rows[0],
    run: async (sql, ...args) => ({
      changes: (await query(sql, args)).rowCount,
    }),
    exec: async (sql) => {
      await query(sql);
    },
    hasColumn: async (table, column) =>
      !!(
        await pool.query(
          "SELECT 1 FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 AND column_name=$3",
          ["streamlined_vault", table, column],
        )
      ).rows[0],
    transaction: async (fn) => {
      if (context.getStore()) return fn();
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        return await context.run(client, async () => {
          try {
            const result = await fn();
            await client.query("COMMIT");
            return result;
          } catch (e) {
            await client.query("ROLLBACK");
            throw e;
          }
        });
      } finally {
        client.release();
      }
    },
    lock: async (key) => {
      if (!context.getStore())
        throw Error("A database lock requires a transaction");
      await query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", [
        key,
      ]);
    },
    close: () => pool.end(),
  };
  return db;
}

const localSchema = `
CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT NOT NULL,quota INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'active');
CREATE TABLE IF NOT EXISTS members(tenant TEXT NOT NULL,email TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(tenant,email));
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,user TEXT NOT NULL,expires INTEGER NOT NULL,csrf TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS clerk_identities(clerk_id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,name TEXT NOT NULL,folder TEXT NOT NULL,size INTEGER NOT NULL,key TEXT NOT NULL,version TEXT NOT NULL DEFAULT '',status TEXT NOT NULL,upload TEXT,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS parts(file TEXT NOT NULL,number INTEGER NOT NULL,etag TEXT NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(file,number));
CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,resource TEXT NOT NULL,created TEXT NOT NULL,previous TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS automations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL,interval INTEGER NOT NULL,enabled INTEGER NOT NULL,next INTEGER NOT NULL,last TEXT NOT NULL DEFAULT 'Never',result TEXT NOT NULL DEFAULT 'Not run');
CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,label TEXT NOT NULL,hash TEXT NOT NULL,scope TEXT NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,last TEXT);
CREATE TABLE IF NOT EXISTS notices(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,title TEXT NOT NULL,created TEXT NOT NULL);`;

const migrations = [
  { version: 1, file: "001-metadata.sql" },
  { version: 2, file: "002-msp-console.sql" },
  { version: 3, file: "003-direct-transfers.sql" },
];
export async function migratePostgres(db) {
  try {
    if (
      (await db.one("SELECT MAX(version) AS version FROM schema_migrations"))
        ?.version >= migrations.at(-1).version
    )
      return;
  } catch (e) {
    if (!["42P01", "3F000"].includes(e.code)) throw e;
  }
  await db.transaction(async () => {
    await db.lock("streamlined-vault:schema");
    await db.exec("CREATE SCHEMA IF NOT EXISTS streamlined_vault");
    await db.exec(
      "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied TEXT NOT NULL)",
    );
    for (const migration of migrations)
      if (
        !(await db.one(
          "SELECT version FROM schema_migrations WHERE version=?",
          migration.version,
        ))
      ) {
        await db.exec(
          readFileSync(
            new URL("./migrations/" + migration.file, import.meta.url),
            "utf8",
          ),
        );
        await db.run(
          "INSERT INTO schema_migrations VALUES(?,?)",
          migration.version,
          new Date().toISOString(),
        );
      }
  });
}
export async function openDatabase({ env, demo, data }) {
  let db;
  if (!demo || env.METADATA_DRIVER === "postgres") {
    const allowLocalTest =
      demo && env.NODE_ENV === "test" && env.TEST_DATABASE_LOCAL === "true";
    db = postgresDatabase(postgresPool(env.DATABASE_URL, { allowLocalTest }));
    try {
      await migratePostgres(db);
    } catch (e) {
      await db.close();
      throw e;
    }
  } else {
    mkdirSync(data, { recursive: true });
    db = sqliteDatabase(new DatabaseSync(join(data, "portal.sqlite")));
    await db.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;");
    await db.exec(localSchema);
    if (!(await db.hasColumn("files", "requestid")))
      await db.exec("ALTER TABLE files ADD COLUMN requestid TEXT");
    await db.exec(
      "CREATE UNIQUE INDEX IF NOT EXISTS upload_request_id ON files(tenant,requestid)",
    );
    if (!(await db.hasColumn("tenants", "kind")))
      await db.exec(
        "ALTER TABLE tenants ADD COLUMN kind TEXT NOT NULL DEFAULT 'client'",
      );
    if (!(await db.hasColumn("tenants", "owner_email")))
      await db.exec("ALTER TABLE tenants ADD COLUMN owner_email TEXT");
    const consoleSchema = readFileSync(
      new URL("./migrations/002-msp-console.sql", import.meta.url),
      "utf8",
    )
      .replace(/^ALTER TABLE[^;]+;\s*/gm, "")
      .replaceAll("streamlined_vault.", "");
    await db.exec(consoleSchema);
    await db.exec(
      readFileSync(
        new URL("./migrations/003-direct-transfers.sql", import.meta.url),
        "utf8",
      ).replaceAll("streamlined_vault.", ""),
    );
  }
  return db;
}
