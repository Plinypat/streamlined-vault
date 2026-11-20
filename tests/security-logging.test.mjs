import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import { openDatabase } from "../server/database.mjs";
import {
  createSecurityLog,
  digest,
  auditValue,
  routeClass,
} from "../server/security-log.mjs";
import { createAuditArchive } from "../server/audit-archive.mjs";
import {
  createWorkspaceStorage,
  sealCredentials,
  openCredentials,
} from "../server/workspace-storage.mjs";
import { createDevices } from "../server/devices.mjs";
import { LocalStorage } from "../server/storage.mjs";
import { runStorageCanary } from "../server/security-console.mjs";
import {
  encryptedBackup,
  decryptBackup,
  restoreBackup,
} from "../server/metadata-recovery.mjs";
async function fixture(t) {
  const data = mkdtempSync(join(tmpdir(), "sv-security-")),
    db = await openDatabase({ env: {}, demo: true, data });
  await createWorkspaceStorage({ db, env: {}, demo: true, data });
  await createDevices({ db });
  t.after(async () => {
    await db.close();
    rmSync(data, { recursive: true, force: true });
  });
  return { db, data, log: createSecurityLog({ db }) };
}
async function audit(db, action = "Synthetic action") {
  const row = {
    id: randomUUID(),
    tenant: "practice",
    actor: "staff@example.test",
    action,
    resource: "opaque-object",
    created: new Date().toISOString(),
    previous:
      (await db.one("SELECT digest FROM audit ORDER BY rowid DESC LIMIT 1"))
        ?.digest || "",
  };
  await db.run(
    "INSERT INTO audit(id,tenant,actor,action,resource,created,previous,digest) VALUES(?,?,?,?,?,?,?,?)",
    ...Object.values(row),
    digest(row),
  );
  return row;
}
function lockedProvider() {
  let bucket;
  const calls = [];
  return {
    calls,
    checkProvisioning: async () => ({
      accountId: "synthetic-account",
      endpoint: "https://s3.us-west-004.backblazeb2.com",
      region: "us-west-004",
      allowed: {
        capabilities: [
          "readBucketRetentions",
          "writeBucketRetentions",
          "readFileRetentions",
          "writeFileRetentions",
        ],
      },
    }),
    verify: async () => bucket,
    call: async (auth, method, input) => {
      calls.push({ method, input });
      if (method === "b2_list_buckets")
        return { buckets: bucket ? [bucket] : [] };
      if (method === "b2_create_bucket") {
        bucket = {
          ...input,
          bucketId: "synthetic-audit",
          fileLockConfiguration: {
            value: {
              isFileLockEnabled: true,
              defaultRetention: { mode: null },
            },
          },
        };
        return bucket;
      }
      if (method === "b2_update_bucket") {
        bucket.fileLockConfiguration.value.defaultRetention =
          input.defaultRetention;
        return bucket;
      }
      if (method === "b2_create_key")
        return {
          applicationKeyId: "synthetic-key",
          applicationKey: "synthetic-private-key",
        };
      throw Error("Unexpected provider call");
    },
  };
}
function archiveStore() {
  const objects = new Map();
  return {
    objects,
    putLocked: async (key, bytes, until) => {
      objects.set(key, { bytes: Buffer.from(bytes), until });
      return "version-1";
    },
    get: async (key) => ({ body: Readable.from(objects.get(key).bytes) }),
    retention: async (key) => ({
      mode: "COMPLIANCE",
      until: objects.get(key).until,
    }),
  };
}

test("security events are append-only, hash chained and do not collect URLs, credentials or supplied payloads", async (t) => {
  const { db, log } = await fixture(t);
  await log.event("authentication_failed", {
    actor: "staff@example.test",
    requestId: randomUUID(),
    route: "authentication",
    status: 401,
    severity: "warning",
    authorization: "Bearer synthetic-secret",
    url: "https://example.test/?token=synthetic-secret",
    body: { filename: "sensitive-name" },
  });
  const rows = await db.q("SELECT * FROM security_events");
  const encoded = JSON.stringify(rows);
  assert.ok(!encoded.includes("synthetic-secret"));
  assert.ok(!encoded.includes("staff@example.test"));
  assert.ok(!encoded.includes("sensitive-name"));
  assert.equal((await log.verify("security_events")).ok, true);
  await assert.rejects(
    () => db.run("UPDATE security_events SET event='changed'"),
    /append only/,
  );
  await assert.rejects(
    () => db.run("DELETE FROM security_events"),
    /append only/,
  );
  const a = await audit(db);
  assert.equal((await log.verify("audit")).ok, true);
  await assert.rejects(() => db.run("DELETE FROM audit"), /append only/);
  const original = db.q;
  db.q = async (...args) => {
    const values = await original(...args);
    if (args[0].includes("FROM audit WHERE"))
      return values.map((r) => ({ ...r, action: "tampered" }));
    return values;
  };
  assert.equal((await log.verify("audit")).ok, false);
  assert.equal(
    (
      await db.one(
        "SELECT code FROM security_alerts WHERE code='integrity_failed'",
      )
    ).code,
    "integrity_failed",
  );
  db.q = original;
  assert.equal(
    routeClass("/api/tenants/id/files/opaque/download?token=secret"),
    "file",
  );
  assert.equal(auditValue({ ...a, seq: 1 }).id, a.id);
});

test("approved archive creates a separate private locked bucket and verifies encrypted off-host copies before checkpointing", async (t) => {
  const { db, log, data } = await fixture(t),
    provider = lockedProvider(),
    store = archiveStore();
  const archive = createAuditArchive({
    db,
    log,
    data,
    demo: false,
    env: {
      APP_ORIGIN: "https://www.streamlinedvault.com",
      STORAGE_CREDENTIAL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    },
    provider,
    cloudFactory: () => store,
  });
  await audit(db);
  await log.event("request_denied", { status: 403 });
  const result = await archive.flush();
  assert.equal(result.archivedBatches, 2);
  assert.equal(
    provider.calls.find((c) => c.method === "b2_create_bucket").input
      .fileLockEnabled,
    true,
  );
  assert.deepEqual(
    provider.calls.find((c) => c.method === "b2_update_bucket").input
      .defaultRetention,
    { mode: "compliance", period: { duration: 365, unit: "days" } },
  );
  const caps = provider.calls.find((c) => c.method === "b2_create_key").input
    .capabilities;
  assert.ok(!caps.includes("deleteFiles"));
  assert.ok(!caps.includes("bypassGovernance"));
  assert.ok(
    [...store.objects.values()].every(
      (o) => !o.bytes.toString().includes("staff@example.test"),
    ),
  );
  const expected = await archive.environment();
  provider.authorize = async () => ({
    accountId: "synthetic-account",
    endpoint: "https://s3.us-west-004.backblazeb2.com",
    region: "us-west-004",
    allowed: {
      buckets: [{ id: "synthetic-audit" }],
      capabilities: [
        "listBuckets",
        "readBuckets",
        "readBucketEncryption",
        "readBucketRetentions",
        "listFiles",
        "readFiles",
        "writeFiles",
        "readFileRetentions",
        "writeFileRetentions",
      ],
    },
  });
  assert.equal(
    (
      await archive.connect({
        bucket: expected.expectedBucket,
        keyId: "rotated",
        applicationKey: "synthetic-rotated-key",
      })
    ).configured,
    true,
  );
  const authorized = provider.authorize;
  provider.authorize = async () => ({
    ...(await authorized()),
    accountId: "other-account",
  });
  await assert.rejects(
    () =>
      archive.connect({
        bucket: expected.expectedBucket,
        keyId: "foreign",
        applicationKey: "synthetic",
      }),
    /different account/,
  );
  provider.authorize = authorized;
  assert.equal((await archive.verifyLatest()).ok, true);
  assert.equal((await archive.flush()).archivedBatches, 0);
  const first = await db.one(
    "SELECT * FROM audit_archives ORDER BY rowid DESC LIMIT 1",
  );
  assert.ok(Date.parse(first.retain_until) > Date.now() + 364 * 86400000);
  await assert.rejects(
    () => db.run("DELETE FROM audit_archives"),
    /append only/,
  );
  const entry = store.objects.get(first.object_key);
  entry.bytes[20] ^= 1;
  await assert.rejects(() => archive.verifyLatest());
});

test("archive failures retain queued logs and never report a completed archive", async (t) => {
  const { db, log, data } = await fixture(t),
    provider = lockedProvider(),
    store = archiveStore();
  store.putLocked = async () => {
    throw Error("Synthetic provider outage");
  };
  const archive = createAuditArchive({
    db,
    log,
    data,
    demo: false,
    env: {
      APP_ORIGIN: "https://www.streamlinedvault.com",
      STORAGE_CREDENTIAL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    },
    provider,
    cloudFactory: () => store,
  });
  await audit(db);
  await assert.rejects(() => archive.flush(), /Synthetic provider outage/);
  assert.equal(
    (await db.one("SELECT COUNT(*) AS count FROM audit_archives")).count,
    0,
  );
  assert.equal((await db.one("SELECT COUNT(*) AS count FROM audit")).count, 1);
  assert.equal((await archive.status()).lastSuccess, null);
});

test("synthetic storage assurance verifies multipart/range restore and removes only its canary", async (t) => {
  const { data } = await fixture(t),
    storage = new LocalStorage(join(data, "objects"));
  const report = await runStorageCanary(storage);
  assert.equal(report.bytes, 17 * 1024 * 1024);
  assert.equal(report.rangeVerified, true);
  assert.equal(report.crossBucketVerified, false);
  await assert.rejects(
    () => storage.removeCanary("tenants/practice/client-file"),
    /prefix rejected/,
  );
});

test("encrypted metadata recovery authenticates the bundle, preserves file bindings and revokes restored device access", async (t) => {
  const source = await fixture(t),
    target = await fixture(t),
    storageKey = randomBytes(32).toString("base64"),
    backupKey = randomBytes(32).toString("base64");
  await source.db.run(
    "INSERT INTO tenants(id,name,quota,status) VALUES('practice','Synthetic practice',4000000000000,'active')",
  );
  const credential = sealCredentials(
    {
      keyId: "synthetic-bucket-key",
      applicationKey: "synthetic-bucket-secret",
    },
    Buffer.from(storageKey, "base64"),
    "practice",
  );
  await source.db.run(
    "INSERT INTO workspace_storage(tenant,bucket,bucket_id,endpoint,region,credential,mode,status,created) VALUES('practice','synthetic-bucket','synthetic-id','https://s3.us-west-004.backblazeb2.com','us-west-004',?,'connect','ready','2026-11-20')",
    credential,
  );
  await source.db.run(
    "INSERT INTO tokens(id,tenant,label,hash,scope,expires) VALUES('token','practice','Synthetic','hashed-token','upload',9999999999999)",
  );
  await source.db.run(
    "INSERT INTO devices(id,tenant,label,token,policy,created) VALUES('device','practice','Synthetic device','token','{}','2026-11-20')",
  );
  await source.db.run(
    "INSERT INTO files(id,tenant,name,folder,size,key,status,created) VALUES('file','practice','sensitive-synthetic-name.dcm','General',42,'opaque-key','ready','2026-11-20')",
  );
  await source.db.run(
    "UPDATE files SET storage_tenant='practice' WHERE id='file'",
  );
  await audit(source.db);
  await source.log.event("request_denied", { status: 403 });
  const encrypted = await encryptedBackup(source.db, storageKey, backupKey);
  assert.ok(!encrypted.toString().includes("sensitive-synthetic-name"));
  assert.ok(!encrypted.toString().includes(storageKey));
  const damaged = Buffer.from(encrypted);
  damaged[40] ^= 1;
  assert.throws(() => decryptBackup(damaged, backupKey));
  assert.throws(() =>
    decryptBackup(encrypted, randomBytes(32).toString("base64")),
  );
  const payload = decryptBackup(encrypted, backupKey),
    result = await restoreBackup(target.db, payload);
  assert.equal(result.counts.files, 1);
  assert.equal(
    (await target.db.one("SELECT storage_tenant FROM files WHERE id='file'"))
      .storage_tenant,
    "practice",
  );
  const recovered = await target.db.one(
    "SELECT credential FROM workspace_storage WHERE tenant='practice'",
  );
  assert.equal(
    openCredentials(
      recovered.credential,
      Buffer.from(payload.storageKey, "base64"),
      "practice",
    ).applicationKey,
    "synthetic-bucket-secret",
  );
  assert.equal(
    (await target.db.one("SELECT key FROM files WHERE id='file'")).key,
    "opaque-key",
  );
  assert.equal(
    (await target.db.one("SELECT revoked FROM tokens WHERE id='token'"))
      .revoked,
    1,
  );
  assert.equal(
    (await target.db.one("SELECT revoked FROM devices WHERE id='device'"))
      .revoked,
    1,
  );
  assert.equal((await target.log.verify("audit")).ok, true);
  assert.equal((await target.log.verify("security_events")).ok, true);
  assert.ok(
    await target.db.one(
      "SELECT value FROM security_state WHERE id='recovery_review_required'",
    ),
  );
  await assert.rejects(() => restoreBackup(target.db, payload), /not empty/);
});
