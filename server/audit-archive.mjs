import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  BucketProvisioner,
  encryptionKey,
  sealCredentials,
  openCredentials,
} from "./workspace-storage.mjs";
import { CloudStorage, LocalStorage } from "./storage.mjs";
import { join } from "node:path";
import { digest, auditValue, eventValue } from "./security-log.mjs";
const policy = JSON.parse(
  readFileSync(new URL("./security-policy.json", import.meta.url), "utf8"),
);
const need = (v, message) => {
  if (!v)
    throw Object.assign(Error(message), {
      status: 503,
      code: "ARCHIVE_CONFIGURATION",
    });
};
export async function readBounded(body, limit = 4 * 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of body) {
    size += chunk.length;
    need(size <= limit, "Archive exceeds verification limit");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
export function createAuditArchive({
  db,
  env,
  demo,
  data,
  log,
  provider = new BucketProvisioner(),
  cloudFactory = (e) => new CloudStorage(e),
}) {
  async function setting(id) {
    const row = await db.one("SELECT value FROM security_state WHERE id=?", id);
    return row ? JSON.parse(row.value) : null;
  }
  async function save(id, value) {
    await db.run(
      "INSERT INTO security_state(id,value,updated) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
      id,
      JSON.stringify(value),
      new Date().toISOString(),
    );
  }
  async function storage() {
    const config = await setting("archive_config");
    need(config, "Protected audit archive is not configured");
    if (demo) return new LocalStorage(join(data, "audit-archive"));
    const creds = openCredentials(
      config.credential,
      encryptionKey(env),
      "audit-archive-credential",
    );
    return cloudFactory({
      ...env,
      STORAGE_BUCKET: config.bucket,
      STORAGE_ENDPOINT: config.endpoint,
      STORAGE_REGION: config.region,
      STORAGE_KEY_ID: creds.keyId,
      STORAGE_APPLICATION_KEY: creds.applicationKey,
    });
  }
  async function setup() {
    need(
      policy.archiveApproved &&
        policy.retentionDays === 365 &&
        policy.retentionMode === "compliance",
      "Archive retention is not approved",
    );
    return await db.transaction(async () => {
      await db.lock("security:archive-setup");
      const existing = await setting("archive_config");
      if (existing)
        return { configured: true, retentionDays: 365, synthetic: demo };
      if (demo) {
        await save("archive_config", {
          synthetic: true,
          bucket: "local-security-archive",
        });
        return { configured: true, synthetic: true };
      }
      const key = encryptionKey(env),
        auth = await provider.checkProvisioning(env);
      need(
        [
          "readBucketRetentions",
          "writeBucketRetentions",
          "readFileRetentions",
          "writeFileRetentions",
        ].every((c) => auth.allowed.capabilities.includes(c)),
        "Provisioning credential needs readBucketRetentions, writeBucketRetentions, readFileRetentions and writeFileRetentions for the approved audit archive",
      );
      const suffix = createHash("sha256")
          .update(new URL(env.APP_ORIGIN).origin)
          .digest("hex")
          .slice(0, 24),
        bucket = "sv-audit-" + suffix;
      const listed = await provider.call(auth, "b2_list_buckets", {
        bucketName: bucket,
      });
      let b = listed.buckets?.find((b) => b.bucketName === bucket);
      if (!b)
        b = await provider.call(auth, "b2_create_bucket", {
          bucketName: bucket,
          bucketType: "allPrivate",
          bucketInfo: { "sv-purpose": "security-audit", "sv-origin": suffix },
          fileLockEnabled: true,
          defaultServerSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
          corsRules: [],
          lifecycleRules: [],
        });
      need(
        b.bucketInfo?.["sv-purpose"] === "security-audit" &&
          b.bucketInfo?.["sv-origin"] === suffix,
        "Audit bucket ownership marker does not match",
      );
      need(
        b.fileLockConfiguration?.value?.isFileLockEnabled === true,
        "Audit bucket Object Lock could not be verified",
      );
      const retention = b.fileLockConfiguration?.value?.defaultRetention;
      if (
        retention?.mode !== "compliance" ||
        retention.period?.duration !== 365 ||
        retention.period?.unit !== "days"
      )
        await provider.call(auth, "b2_update_bucket", {
          bucketId: b.bucketId,
          defaultRetention: {
            mode: "compliance",
            period: { duration: 365, unit: "days" },
          },
        });
      b = await provider.verify(auth, bucket);
      const actual = b.fileLockConfiguration?.value;
      need(
        actual?.isFileLockEnabled &&
          actual.defaultRetention?.mode === "compliance" &&
          actual.defaultRetention.period?.duration === 365 &&
          actual.defaultRetention.period.unit === "days",
        "Audit bucket 365-day retention verification failed",
      );
      const credential = await provider.call(auth, "b2_create_key", {
        keyName: "sv-audit-" + suffix,
        bucketIds: [b.bucketId],
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
      });
      need(
        credential.applicationKeyId && credential.applicationKey,
        "Archive credential creation failed",
      );
      await save("archive_config", {
        bucket,
        endpoint: auth.endpoint,
        region: auth.region,
        credential: sealCredentials(
          {
            keyId: credential.applicationKeyId,
            applicationKey: credential.applicationKey,
          },
          key,
          "audit-archive-credential",
        ),
        created: new Date().toISOString(),
        retentionDays: 365,
        mode: "compliance",
      });
      return { configured: true, retentionDays: 365 };
    });
  }
  async function write(source, payload, checkpoint = {}) {
    const s = await storage(),
      id = randomUUID(),
      key = "security-archive/" + id + ".enc",
      context = "audit-archive:" + id;
    const bytes = Buffer.from(
      demo
        ? JSON.stringify({ synthetic: true, payload })
        : sealCredentials(payload, encryptionKey(env), context),
    );
    need(bytes.length <= 4 * 1024 * 1024, "Archive batch exceeds limit");
    const until = new Date(Date.now() + 365 * 86400000).toISOString();
    let version = "";
    if (demo) await s.put(key, bytes);
    else version = await s.putLocked(key, bytes, until);
    const recovered = await readBounded((await s.get(key, version)).body);
    need(
      digest(recovered.toString()) === digest(bytes.toString()),
      "Archive round-trip checksum failed",
    );
    if (!demo) {
      need(version, "Archive version was not returned");
      const retention = await s.retention(key, version);
      need(
        retention.mode === "COMPLIANCE" &&
          Date.parse(retention.until) >= Date.parse(until) - 60000,
        "Archived object retention could not be verified",
      );
      openCredentials(recovered.toString(), encryptionKey(env), context);
    }
    await db.run(
      "INSERT INTO audit_archives(id,object_key,version,digest,source,first_id,last_id,source_digest,previous_archive,retain_until,created) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
      id,
      key,
      version,
      digest(bytes.toString()),
      source,
      checkpoint.first || "",
      checkpoint.last || "",
      checkpoint.tip || "",
      checkpoint.previous || "",
      until,
      new Date().toISOString(),
    );
    return {
      id,
      objectKey: key,
      version,
      digest: digest(bytes.toString()),
      until,
    };
  }
  async function flush() {
    return await db.transaction(async () => {
      await db.lock("security:archive-flush");
      await setup();
      const results = [];
      for (const source of ["audit", "security_events"]) {
        const prior = await db.one(
          "SELECT * FROM audit_archives WHERE source=? ORDER BY rowid DESC LIMIT 1",
          source,
        );
        let position = 0,
          previous = "";
        if (prior) {
          const anchor = await db.one(
            `SELECT rowid AS position,digest FROM ${source} WHERE id=?`,
            prior.last_id,
          );
          need(
            anchor?.digest === prior.source_digest,
            "Archived log checkpoint does not match database",
          );
          position = Number(anchor.position);
          previous = anchor.digest;
        }
        const rows = await db.q(
          `SELECT rowid AS position,* FROM ${source} WHERE rowid>? ORDER BY rowid LIMIT 500`,
          position,
        );
        if (!rows.length) continue;
        for (const row of rows) {
          need(
            row.previous === previous &&
              row.digest ===
                digest(source === "audit" ? auditValue(row) : eventValue(row)),
            "Log integrity verification failed before archive",
          );
          previous = row.digest;
        }
        const value = {
          format: 1,
          source,
          created: new Date().toISOString(),
          previousArchive: prior?.digest || "",
          previousTip: prior?.source_digest || "",
          records: rows.map((r) =>
            source === "audit"
              ? { ...auditValue(r), digest: r.digest }
              : { ...eventValue(r), digest: r.digest },
          ),
        };
        results.push(
          await write(source, value, {
            first: rows[0].id,
            last: rows.at(-1).id,
            tip: previous,
            previous: prior?.digest || "",
          }),
        );
      }
      await save("archive_last_success", {
        at: new Date().toISOString(),
        synthetic: demo,
      });
      return { ok: true, archivedBatches: results.length, synthetic: demo };
    });
  }
  async function status() {
    const c = await setting("archive_config");
    return {
      configured: !!c,
      synthetic: demo,
      retentionDays: 365,
      mode: "COMPLIANCE",
      lastSuccess: await setting("archive_last_success"),
      lastArchive: await db.one(
        "SELECT id,source,retain_until,created FROM audit_archives ORDER BY rowid DESC LIMIT 1",
      ),
    };
  }
  async function verifyLatest() {
    const row = await db.one(
      "SELECT * FROM audit_archives ORDER BY rowid DESC LIMIT 1",
    );
    need(row, "No archive exists to verify");
    const s = await storage(),
      bytes = await readBounded(
        (await s.get(row.object_key, row.version)).body,
      );
    need(
      digest(bytes.toString()) === row.digest,
      "Archived ciphertext was modified",
    );
    const payload = demo
      ? JSON.parse(bytes.toString()).payload
      : openCredentials(
          bytes.toString(),
          encryptionKey(env),
          "audit-archive:" + row.id,
        );
    need(
      Array.isArray(payload.records) && payload.records.length > 0,
      "Archive contents are invalid",
    );
    let previous = payload.previousTip;
    for (const r of payload.records) {
      need(
        r.previous === previous &&
          r.digest ===
            digest(payload.source === "audit" ? auditValue(r) : eventValue(r)),
        "Archived chain is invalid",
      );
      previous = r.digest;
    }
    if (!demo) {
      const r = await s.retention(row.object_key, row.version);
      need(
        r.mode === "COMPLIANCE" &&
          Date.parse(r.until) >= Date.parse(row.retain_until) - 60000,
        "Archived retention no longer matches",
      );
    }
    return {
      ok: true,
      archive: row.id,
      source: row.source,
      records: payload.records.length,
      synthetic: demo,
    };
  }
  async function environment() {
    const auth = await provider.checkProvisioning(env);
    return {
      accountFingerprint: digest(auth.accountId),
      region: auth.region,
      origin: new URL(env.APP_ORIGIN).origin,
      expectedBucket:
        "sv-audit-" +
        createHash("sha256")
          .update(new URL(env.APP_ORIGIN).origin)
          .digest("hex")
          .slice(0, 24),
    };
  }
  async function connect(input) {
    need(
      !demo && policy.archiveApproved,
      "Live archive connection is not approved",
    );
    const expected = await environment();
    need(
      input &&
        input.bucket === expected.expectedBucket &&
        typeof input.keyId === "string" &&
        typeof input.applicationKey === "string",
      "Use the approved audit bucket and its restricted credential",
    );
    const auth = await provider.authorize(input.keyId, input.applicationKey);
    need(
      digest(auth.accountId) === expected.accountFingerprint,
      "Archive credential belongs to a different account",
    );
    need(
      auth.allowed?.buckets?.length === 1 && !auth.allowed.namePrefix,
      "Archive credential must be restricted to one whole bucket",
    );
    const allowed = [
      "listBuckets",
      "readBuckets",
      "readBucketEncryption",
      "readBucketRetentions",
      "listFiles",
      "readFiles",
      "writeFiles",
      "readFileRetentions",
      "writeFileRetentions",
    ];
    need(
      allowed.every((c) => auth.allowed.capabilities.includes(c)) &&
        auth.allowed.capabilities.every((c) => allowed.includes(c)),
      "Use only the documented archive read/write/retention capabilities, with no deletion or account management",
    );
    const b = await provider.verify(auth, input.bucket),
      lock = b.fileLockConfiguration?.value;
    need(
      auth.allowed.buckets[0].id === b.bucketId &&
        b.bucketInfo?.["sv-purpose"] === "security-audit" &&
        b.bucketInfo?.["sv-origin"] === input.bucket.slice("sv-audit-".length),
      "Audit bucket ownership or scope did not match",
    );
    need(
      lock?.isFileLockEnabled &&
        lock.defaultRetention?.mode === "compliance" &&
        lock.defaultRetention.period?.duration === 365 &&
        lock.defaultRetention.period.unit === "days",
      "Approved archive retention was not verified",
    );
    await db.transaction(async () => {
      await db.lock("security:archive-setup");
      const old = await setting("archive_config");
      need(
        !old || old.bucket === input.bucket,
        "Archive history cannot be moved to another bucket",
      );
      await save("archive_config", {
        bucket: input.bucket,
        endpoint: auth.endpoint,
        region: auth.region,
        credential: sealCredentials(
          { keyId: input.keyId, applicationKey: input.applicationKey },
          encryptionKey(env),
          "audit-archive-credential",
        ),
        created: new Date().toISOString(),
        retentionDays: 365,
        mode: "compliance",
      });
    });
    return { configured: true, retentionDays: 365 };
  }
  return {
    setup,
    flush,
    status,
    verifyLatest,
    write,
    setting,
    save,
    environment,
    connect,
    probeAdapter: storage,
  };
}
