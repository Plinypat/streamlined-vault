import { openCredentials } from "./workspace-storage.mjs";
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
} from "node:crypto";
export const recoveryTables = [
  "tenants",
  "members",
  "clerk_identities",
  "tokens",
  "devices",
  "device_runs",
  "workspace_storage",
  "storage_requests",
  "files",
  "parts",
  "audit",
  "automations",
  "notices",
  "service_settings",
  "workspace_plans",
  "transfer_events",
  "provider_inventory",
  "upload_part_grants",
  "security_events",
  "security_state",
  "security_alerts",
  "security_checks",
  "audit_archives",
];
const need = (v, m) => {
  if (!v) throw Error(m);
};
const key = (s) => {
  need(
    typeof s === "string" && /^[A-Za-z0-9+/]{43}=$/.test(s),
    "A 32-byte base64 recovery key is required",
  );
  return Buffer.from(s, "base64");
};
export async function encryptedBackup(db, storageKey, backupKey) {
  key(storageKey);
  const cryptoKey = key(backupKey);
  need(
    storageKey !== backupKey,
    "Use a recovery key independent of the storage credential key",
  );
  const ordering = {
    members: "tenant,email",
    clerk_identities: "clerk_id",
    workspace_storage: "tenant",
    storage_requests: "request_id",
    parts: "file,number",
    upload_part_grants: "file,number",
    audit: "rowid",
    workspace_plans: "tenant",
    security_events: "rowid",
    audit_archives: "rowid",
  };
  const payload = {
    format: 1,
    created: new Date().toISOString(),
    storageKey,
    tables: {},
    sessions: "Excluded; all device credentials are revoked during recovery",
  };
  await db.transaction(async () => {
    if (db.kind === "postgres")
      await db.exec(
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
      );
    let length = 0;
    for (const table of recoveryTables) {
      payload.tables[table] = [];
      let offset = 0;
      for (;;) {
        const rows = await db.q(
          `SELECT * FROM ${table} ORDER BY ${ordering[table] || "id"} LIMIT 500 OFFSET ?`,
          offset,
        );
        if (!rows.length) break;
        length += Buffer.byteLength(JSON.stringify(rows));
        need(
          length <= 64 * 1024 * 1024,
          "Metadata backup exceeds the supported 64 MiB tool limit",
        );
        payload.tables[table].push(...rows);
        offset += rows.length;
      }
    }
  });
  for (const row of payload.tables.workspace_storage)
    if (row.credential)
      openCredentials(row.credential, key(storageKey), row.tenant);
  const archived = payload.tables.security_state.find(
    (r) => r.id === "archive_config",
  );
  if (archived) {
    const c = JSON.parse(archived.value);
    if (c.credential)
      openCredentials(
        c.credential,
        key(storageKey),
        "audit-archive-credential",
      );
  }
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", cryptoKey, iv);
  cipher.setAAD(Buffer.from("Streamlined Vault metadata recovery v1"));
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(payload)),
    cipher.final(),
  ]);
  return Buffer.concat([
    Buffer.from("SVB1"),
    iv,
    cipher.getAuthTag(),
    encrypted,
  ]);
}
export function decryptBackup(bytes, backupKey) {
  need(
    bytes.length >= 32 &&
      bytes.length <= 70 * 1024 * 1024 &&
      bytes.subarray(0, 4).toString() === "SVB1",
    "Invalid recovery bundle",
  );
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key(backupKey),
    bytes.subarray(4, 16),
  );
  decipher.setAAD(Buffer.from("Streamlined Vault metadata recovery v1"));
  decipher.setAuthTag(bytes.subarray(16, 32));
  const payload = JSON.parse(
    Buffer.concat([
      decipher.update(bytes.subarray(32)),
      decipher.final(),
    ]).toString(),
  );
  need(
    payload.format === 1 &&
      payload.tables &&
      typeof payload.created === "string",
    "Invalid recovery manifest",
  );
  key(payload.storageKey);
  need(
    Object.keys(payload.tables).length === recoveryTables.length &&
      recoveryTables.every((t) => Array.isArray(payload.tables[t])),
    "Recovery tables do not match this application version",
  );
  return payload;
}
export async function restoreBackup(db, payload) {
  const counts = {};
  await db.transaction(async () => {
    await db.lock("security:isolated-recovery");
    for (const table of [...recoveryTables, "sessions", "enrollments"])
      need(
        Number(
          (await db.one(`SELECT COUNT(*) AS count FROM ${table}`)).count,
        ) === 0,
        "Recovery target is not empty",
      );
    for (const table of recoveryTables) {
      const columns =
        db.kind === "postgres"
          ? (
              await db.q(
                "SELECT column_name FROM information_schema.columns WHERE table_schema='streamlined_vault' AND table_name=?",
                table,
              )
            ).map((c) => c.column_name)
          : (await db.q(`PRAGMA table_info(${table})`)).map((c) => c.name);
      for (const row of payload.tables[table]) {
        const names = Object.keys(row).filter((c) => c !== "seq");
        need(
          names.length > 0 && names.every((n) => columns.includes(n)),
          "Recovery contains an unexpected column",
        );
        const value = { ...row };
        if (table === "tokens") value.revoked = 1;
        if (table === "devices") {
          value.revoked = 1;
          value.status = "revoked";
        }
        await db.run(
          `INSERT INTO ${table}(${names.map((n) => '"' + n + '"').join(",")}) VALUES(${names.map(() => "?").join(",")})`,
          ...names.map((n) => value[n]),
        );
      }
      counts[table] = payload.tables[table].length;
    }
    await db.run(
      "INSERT INTO security_state(id,value,updated) VALUES('recovery_review_required',?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
      JSON.stringify({
        sourceCreated: payload.created,
        restored: new Date().toISOString(),
        deviceCredentialsRevoked: true,
      }),
      new Date().toISOString(),
    );
  });
  return {
    counts,
    sourceCreated: payload.created,
    storageKeyFingerprint: createHash("sha256")
      .update(Buffer.from(payload.storageKey, "base64"))
      .digest("hex"),
    deviceCredentialsRevoked: true,
    productionActivation: "Blocked pending recovery review",
  };
}
