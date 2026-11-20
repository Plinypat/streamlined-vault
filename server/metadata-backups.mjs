import { randomUUID, createHash } from "node:crypto";
import {
  envelopeBackup,
  backupManifest,
  recoveryKeyId,
} from "./metadata-recovery.mjs";
import { CloudStorage } from "./storage.mjs";
import { openCredentials } from "./workspace-storage.mjs";
import { readBounded } from "./audit-archive.mjs";
import { heartbeat } from "./notifications.mjs";
const hash = (b) => createHash("sha256").update(b).digest("hex");
export function createMetadataBackups({
  db,
  env,
  log,
  notifications,
  storage: providedStorage,
  publicKey: providedPublicKey,
  fetcher = fetch,
}) {
  async function config() {
    const row = await db.one(
      "SELECT value FROM security_state WHERE id='metadata_backup_config'",
    );
    return row ? JSON.parse(row.value) : null;
  }
  async function adapter() {
    const c = await config();
    if (providedStorage)
      return { storage: providedStorage, publicKey: providedPublicKey };
    if (!c) throw Error("Backup is not configured");
    if (
      c.purpose !== "metadata-recovery" ||
      c.retentionDays !== 30 ||
      !c.bucket.startsWith("sv-recovery-")
    )
      throw Error("Invalid backup destination");
    const secret = openCredentials(
      c.credential,
      Buffer.from(env.STORAGE_CREDENTIAL_ENCRYPTION_KEY, "base64"),
      "metadata-backup-credential",
    );
    recoveryKeyId(c.publicKey);
    return {
      publicKey: c.publicKey,
      storage: new CloudStorage({
        STORAGE_BUCKET: c.bucket,
        STORAGE_ENDPOINT: c.endpoint,
        STORAGE_REGION: c.region,
        STORAGE_KEY_ID: secret.keyId,
        STORAGE_APPLICATION_KEY: secret.applicationKey,
      }),
    };
  }
  async function verifyCopy(storage, row) {
    const bytes = await readBounded(
        (await storage.get(row.object_key)).body,
        70 * 1024 * 1024,
      ),
      head = await storage.head(row.object_key);
    if (
      hash(bytes) !== row.digest ||
      bytes.length !== Number(row.bytes) ||
      head.encryption !== "AES256" ||
      backupManifest(bytes).header.keyId !== row.key_id
    )
      throw Error("Backup read-back failed");
    return true;
  }
  async function status() {
    const c = await config(),
      last = await db.one(
        "SELECT id,created,verified,bytes,plaintext_bytes,key_id,trigger FROM backup_history WHERE status='verified' ORDER BY created DESC LIMIT 1",
      ),
      scheduled = await db.one(
        "SELECT created FROM backup_history WHERE status='verified' AND trigger='scheduled' ORDER BY created DESC LIMIT 1",
      ),
      failure = await db.one(
        "SELECT created,error_code FROM backup_history WHERE status='failed' ORDER BY created DESC LIMIT 1",
      );
    const review = await db.one(
      "SELECT created,expires FROM readiness_evidence WHERE id='restore_drill'",
    );
    return {
      configured: !!c || !!providedStorage,
      retentionDays: 30,
      lastSuccess: last,
      lastScheduledSuccess: scheduled,
      nextExpected: scheduled
        ? new Date(Date.parse(scheduled.created) + 3600000).toISOString()
        : null,
      stale:
        !scheduled || Date.now() - Date.parse(scheduled.created) > 75 * 60000,
      lastFailure: failure,
      restoreReview: review,
      restoreReviewDue: !review || Date.parse(review.expires) < Date.now(),
      capacityLimitBytes: 64 * 1024 * 1024,
    };
  }
  async function run({ scheduled = false } = {}) {
    const owner = randomUUID(),
      now = new Date().toISOString();
    let claimed = false,
      row;
    await db.transaction(async () => {
      await db.lock("operations:metadata-backup");
      const lease = await db.one(
        "SELECT value FROM security_state WHERE id='metadata_backup_lease'",
      );
      if (lease && JSON.parse(lease.value).until > Date.now()) return;
      await db.run(
        "INSERT INTO security_state(id,value,updated) VALUES('metadata_backup_lease',?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
        JSON.stringify({ owner, until: Date.now() + 10 * 60000 }),
        now,
      );
      claimed = true;
    });
    if (!claimed) return { ok: true, busy: true };
    try {
      if (
        await db.one(
          "SELECT id FROM security_state WHERE id='recovery_review_required'",
        )
      )
        throw Error("Recovered environment requires operator review");
      const { storage, publicKey } = await adapter(),
        bytes = await envelopeBackup(
          db,
          env.STORAGE_CREDENTIAL_ENCRYPTION_KEY,
          publicKey,
        ),
        manifest = backupManifest(bytes).header;
      row = {
        id: randomUUID(),
        object_key: "metadata/" + randomUUID() + ".svbackup",
        digest: hash(bytes),
        key_id: manifest.keyId,
        bytes: bytes.length,
      };
      await db.run(
        "INSERT INTO backup_history(id,object_key,digest,key_id,bytes,plaintext_bytes,status,trigger,created) VALUES(?,?,?,?,?,?,'uploading',?,?)",
        row.id,
        row.object_key,
        row.digest,
        row.key_id,
        row.bytes,
        manifest.plaintextBytes,
        scheduled ? "scheduled" : "manual",
        now,
      );
      if (manifest.plaintextBytes >= 48 * 1024 * 1024)
        await log.alert("metadata_backup_capacity", "warning");
      await storage.put(row.object_key, bytes);
      await verifyCopy(storage, row);
      const daily = await db.one(
        "SELECT value FROM security_state WHERE id='metadata_backup_daily_verified'",
      );
      if (
        !daily ||
        Date.now() - Date.parse(JSON.parse(daily.value).at) > 86400000
      ) {
        const prior = await db.one(
          "SELECT * FROM backup_history WHERE status='verified' AND created>? ORDER BY created LIMIT 1",
          new Date(Date.now() - 29 * 86400000).toISOString(),
        );
        if (prior) await verifyCopy(storage, prior);
        await db.run(
          "INSERT INTO security_state(id,value,updated) VALUES('metadata_backup_daily_verified',?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
          JSON.stringify({ at: now }),
          now,
        );
      }
      const failedBefore = await db.one(
        "SELECT id FROM security_alerts WHERE code='metadata_backup_failed' AND status='open'",
      );
      await db.run(
        "UPDATE backup_history SET status='verified',verified=? WHERE id=?",
        new Date().toISOString(),
        row.id,
      );
      if (failedBefore) {
        await db.run(
          "UPDATE security_alerts SET status='resolved' WHERE id=?",
          failedBefore.id,
        );
        await db.run(
          "UPDATE security_alerts SET status='resolved' WHERE code='backup_recovered'",
        );
        await log.alert("backup_recovered", "info");
      }
      if (scheduled)
        await heartbeat(env.HEALTHCHECKS_BACKUP_URL, "success", { fetcher });
      return {
        ok: true,
        id: row.id,
        bytes: row.bytes,
        verified: true,
        scheduled,
      };
    } catch {
      if (row)
        await db.run(
          "UPDATE backup_history SET status='failed',error_code='BACKUP_FAILED' WHERE id=?",
          row.id,
        );
      else
        await db.run(
          "INSERT INTO backup_history(id,object_key,digest,key_id,bytes,plaintext_bytes,status,trigger,created,error_code) VALUES(?,?,?,'',0,0,'failed',?,?,'BACKUP_CONFIGURATION_OR_CAPACITY')",
          randomUUID(),
          "not-uploaded/" + randomUUID(),
          "",
          scheduled ? "scheduled" : "manual",
          now,
        );
      await log.alert("metadata_backup_failed", "high");
      if (scheduled)
        await heartbeat(env.HEALTHCHECKS_BACKUP_URL, "failure", {
          fetcher,
        }).catch(() => {});
      throw Object.assign(
        Error(
          "Metadata backup failed; review configuration and protected diagnostics",
        ),
        { status: 503 },
      );
    } finally {
      await db.transaction(async () => {
        await db.lock("operations:metadata-backup");
        const lease = await db.one(
          "SELECT value FROM security_state WHERE id='metadata_backup_lease'",
        );
        if (lease && JSON.parse(lease.value).owner === owner)
          await db.run(
            "DELETE FROM security_state WHERE id='metadata_backup_lease'",
          );
      });
      await notifications?.drain();
    }
  }
  return { run, status };
}
