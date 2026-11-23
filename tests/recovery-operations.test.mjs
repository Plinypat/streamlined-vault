import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, generateKeyPairSync } from "node:crypto";
import { Readable } from "node:stream";
import { openDatabase } from "../server/database.mjs";
import { createWorkspaceStorage } from "../server/workspace-storage.mjs";
import { createDevices } from "../server/devices.mjs";
import { createSecurityLog } from "../server/security-log.mjs";
import {
  envelopeBackup,
  decryptBackup,
  backupManifest,
  restoreBackup,
} from "../server/metadata-recovery.mjs";
import { createMetadataBackups } from "../server/metadata-backups.mjs";
import { createNotifications, heartbeat } from "../server/notifications.mjs";
import { createSecurityConsole } from "../server/security-console.mjs";
const keys = generateKeyPairSync("rsa", {
  modulusLength: 3072,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
async function fixture(t) {
  const data = mkdtempSync(join(tmpdir(), "sv-recovery-")),
    db = await openDatabase({ env: {}, demo: true, data });
  await createWorkspaceStorage({ db, env: {}, demo: true, data });
  await createDevices({ db });
  t.after(async () => {
    await db.close();
    rmSync(data, { recursive: true, force: true });
  });
  return {
    db,
    data,
    log: createSecurityLog({ db }),
    env: {
      STORAGE_CREDENTIAL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    },
  };
}
function memoryStorage() {
  const objects = new Map();
  return {
    objects,
    put: async (k, b) => objects.set(k, Buffer.from(b)),
    get: async (k) => ({ body: Readable.from(objects.get(k)) }),
    head: async (k) => ({ size: objects.get(k).length, encryption: "AES256" }),
  };
}
test("public-key backup authenticates metadata, rejects wrong key and corruption, restores into an empty target only", async (t) => {
  const f = await fixture(t),
    target = await fixture(t);
  await f.db.run(
    "INSERT INTO tenants(id,name,quota,status) VALUES('practice','Synthetic',4000000000000,'active')",
  );
  const bytes = await envelopeBackup(
    f.db,
    f.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY,
    keys.publicKey,
  );
  assert.equal(backupManifest(bytes).header.format, 2);
  assert.ok(
    !bytes.includes(Buffer.from(f.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY)),
  );
  const payload = decryptBackup(bytes, keys.privateKey);
  assert.equal(payload.tables.tenants[0].id, "practice");
  const bad = Buffer.from(bytes);
  bad[bad.length - 17] ^= 1;
  assert.throws(() => decryptBackup(bad, keys.privateKey));
  assert.throws(() => decryptBackup(bytes, keys.publicKey));
  await restoreBackup(target.db, payload);
  assert.ok(
    await target.db.one(
      "SELECT id FROM security_state WHERE id='recovery_review_required'",
    ),
  );
  await assert.rejects(() => restoreBackup(target.db, payload), /not empty/);
});
test("hourly backup verifies remote bytes and daily retained copy, manual runs never ping, storage corruption cannot report success", async (t) => {
  const f = await fixture(t),
    storage = memoryStorage(),
    calls = [];
  const backups = createMetadataBackups({
    ...f,
    publicKey: keys.publicKey,
    storage,
    env: {
      ...f.env,
      HEALTHCHECKS_BACKUP_URL:
        "https://hc-ping.com/11111111-1111-1111-1111-111111111111",
    },
    fetcher: async (...args) => {
      calls.push(args);
      return { ok: true };
    },
  });
  await backups.run();
  assert.equal(calls.length, 0);
  await backups.run({ scheduled: true });
  assert.equal(calls.length, 1);
  assert.equal((await backups.status()).stale, false);
  const originalGet = storage.get;
  storage.get = async () => ({ body: Readable.from(Buffer.from("damaged")) });
  await assert.rejects(() => backups.run({ scheduled: true }));
  assert.ok(calls.at(-1)[0].endsWith("/fail"));
  assert.equal(
    (
      await f.db.one(
        "SELECT COUNT(*) AS n FROM backup_history WHERE status='verified'",
      )
    ).n,
    2,
  );
  storage.get = originalGet;
});
test("backup lease prevents overlapping jobs and metadata cap prevents any upload", async (t) => {
  const f = await fixture(t),
    storage = memoryStorage(),
    backups = createMetadataBackups({
      ...f,
      storage,
      publicKey: keys.publicKey,
    });
  await f.db.run(
    "INSERT INTO security_state(id,value,updated) VALUES('metadata_backup_lease',?,?)",
    JSON.stringify({ owner: "other", until: Date.now() + 60000 }),
    new Date().toISOString(),
  );
  assert.equal((await backups.run()).busy, true);
  assert.equal(storage.objects.size, 0);
  await f.db.run("DELETE FROM security_state WHERE id='metadata_backup_lease'");
  const oversized = {
    ...f.db,
    q: async (sql, ...args) =>
      sql.startsWith("SELECT * FROM tenants")
        ? [{ id: "large", content: "x".repeat(65 * 1024 * 1024) }]
        : f.db.q(sql, ...args),
  };
  await assert.rejects(
    () =>
      envelopeBackup(
        oversized,
        f.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY,
        keys.publicKey,
      ),
    /64 MiB/,
  );
  assert.equal(storage.objects.size, 0);
});
test("notification outbox deduplicates open incidents, retries safely, and reopening queues a new message without sensitive content", async (t) => {
  const f = await fixture(t),
    captured = [];
  let fail = true;
  const notifications = createNotifications({
    ...f,
    env: {
      RESEND_API_KEY: "synthetic",
      ALERT_EMAIL_FROM: "alerts@example.test",
      ALERT_EMAIL_TO: "operator@example.test",
      APP_ORIGIN: "https://portal.example.test",
    },
    fetcher: async (url, opts) => {
      captured.push({ url, ...opts });
      return fail
        ? { ok: false }
        : { ok: true, json: async () => ({ id: "accepted-id" }) };
    },
  });
  await f.log.alert("uploader_offline_secret-device-id");
  await f.log.alert("uploader_offline_secret-device-id");
  assert.equal((await notifications.status()).deliveries.length, 1);
  await notifications.drain();
  assert.equal((await notifications.status()).deliveries[0].attempts, 1);
  assert.ok(!captured[0].body.includes("secret-device-id"));
  fail = false;
  await f.db.run("UPDATE alert_deliveries SET next_attempt=0");
  await notifications.drain();
  assert.equal((await notifications.status()).deliveries[0].status, "accepted");
  assert.equal(
    captured[0].headers["Idempotency-Key"],
    captured[1].headers["Idempotency-Key"],
  );
  await f.db.run("UPDATE security_alerts SET status='acknowledged'");
  await f.log.alert("uploader_offline_secret-device-id");
  assert.equal((await notifications.status()).deliveries.length, 2);
});
test("monitor URL cannot redirect or send operational payloads to arbitrary hosts", async () => {
  let called = false;
  await assert.rejects(() =>
    heartbeat("https://example.test/private", "success", {
      fetcher: async () => {
        called = true;
      },
    }),
  );
  assert.equal(called, false);
  await heartbeat(
    "https://hc-ping.com/11111111-1111-1111-1111-111111111111",
    "success",
    {
      fetcher: async (u, o) => {
        assert.equal(o.body, "");
        assert.equal(o.redirect, "error");
        return { ok: true };
      },
    },
  );
});
test("readiness is not granted by recording activation or a synthetic review", async (t) => {
  const f = await fixture(t);
  const s = createSecurityConsole({
    ...f,
    demo: true,
    workspaceStorage: {},
    audit: async () => {},
  });
  await assert.rejects(
    () =>
      s.recordEvidence("operator", {
        kind: "activation_review",
        reference: "test-123",
      }),
    /Complete technical checks/,
  );
  await s.recordEvidence("operator", {
    kind: "key_custody",
    reference: "test-123",
  });
  const state = await s.status();
  assert.equal(state.technicalApproval, false);
  assert.equal(state.gates.keyCustody, true);
  assert.equal(state.gates.mfa, false);
});

test("acknowledged high alerts still block readiness; resolving requires verification evidence and recurrence reopens", async (t) => {
  const f = await fixture(t),
    security = createSecurityConsole({
      ...f,
      demo: true,
      workspaceStorage: {},
      audit: async () => {},
    });
  const id = await f.log.alert("request_failed", "high");
  await security.acknowledge(id, "operator");
  assert.equal((await security.status()).gates.criticalAlerts, false);
  await assert.rejects(
    () => security.resolveAlert("operator", { id, reference: "" }),
    /reference/,
  );
  await security.resolveAlert("operator", {
    id,
    reference: "verified-inventory-fix",
  });
  assert.equal((await security.status()).gates.criticalAlerts, true);
  assert.ok(
    await f.db.one(
      "SELECT value FROM security_state WHERE id=?",
      "alert_resolution:" + id,
    ),
  );
  await f.log.alert("request_failed", "high");
  assert.equal((await security.status()).gates.criticalAlerts, false);
});
test("production approvals require explicit true values and remain separate from technical approval", async () => {
  const { productionApprovals, productionAuthorized } = await import(
    "../server/activation.mjs"
  );
  const env = {};
  assert.equal(productionAuthorized(env), false);
  for (const p of productionApprovals(env)) env[p.setting] = "true";
  assert.equal(productionAuthorized(env), true);
  env.NEON_BAA_CONFIRMED = "false";
  assert.equal(productionAuthorized(env), false);
});
