import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { sqliteDatabase, postgresSql } from "../server/database.mjs";
import { postgresPool } from "../server/postgres.mjs";

test("Postgres parameters and table namespace do not alter quoted values", () => {
  assert.equal(
    postgresSql(
      "SELECT 'FROM tenants rowid ?' AS literal FROM tenants WHERE id=?",
    ),
    "SELECT 'FROM tenants rowid ?' AS literal FROM streamlined_vault.tenants WHERE id=$1",
  );
  assert.equal(
    postgresSql("SELECT * FROM audit ORDER BY rowid DESC LIMIT ?"),
    "SELECT * FROM streamlined_vault.audit ORDER BY seq DESC LIMIT $1",
  );
});
test("local transaction rollback cannot include another asynchronous request", async () => {
  const raw = new DatabaseSync(":memory:");
  raw.exec("CREATE TABLE tenants(id TEXT PRIMARY KEY)");
  const db = sqliteDatabase(raw);
  let started, release;
  const ready = new Promise((r) => (started = r)),
    barrier = new Promise((r) => (release = r));
  const transaction = db.transaction(async () => {
    await db.run("INSERT INTO tenants VALUES(?)", "rolled-back");
    started();
    await barrier;
    throw Error("Synthetic rollback");
  });
  await ready;
  const outside = db.run("INSERT INTO tenants VALUES(?)", "outside");
  release();
  await assert.rejects(transaction, /Synthetic rollback/);
  await outside;
  assert.equal(
    await db.one("SELECT * FROM tenants WHERE id=?", "rolled-back"),
    undefined,
  );
  assert.equal(
    (await db.one("SELECT * FROM tenants WHERE id=?", "outside")).id,
    "outside",
  );
  await db.close();
});
test("Postgres always verifies TLS except explicit loopback test connections", async () => {
  const live = postgresPool(
    "postgresql://synthetic:synthetic@db.example.test/test?sslmode=disable",
  );
  assert.equal(live.options.ssl.rejectUnauthorized, true);
  await live.end();
  const remote = postgresPool(
    "postgresql://synthetic:synthetic@db.example.test/test",
    { allowLocalTest: true },
  );
  assert.equal(remote.options.ssl.rejectUnauthorized, true);
  await remote.end();
  const local = postgresPool(
    "postgresql://synthetic:synthetic@127.0.0.1/test",
    { allowLocalTest: true },
  );
  assert.equal(local.options.ssl, false);
  await local.end();
});
