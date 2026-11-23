import { createSecurityLog } from "../server/security-log.mjs";
import { readFileSync } from "node:fs";
import { resolve, basename } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { postgresPool } from "../server/postgres.mjs";
import { postgresDatabase } from "../server/database.mjs";
import { CloudStorage } from "../server/storage.mjs";
import { openCredentials } from "../server/workspace-storage.mjs";
import { decryptBackup } from "../server/metadata-recovery.mjs";
import { readBounded } from "../server/audit-archive.mjs";
let db;
try {
  const filename = resolve(".env.recovery-from-bitwarden.pem");
  if (
    process.platform === "win32" &&
    spawnSync(
      "icacls.exe",
      [
        filename,
        "/inheritance:r",
        "/grant:r",
        process.env.USERDOMAIN + "\\" + process.env.USERNAME + ":(F)",
        "*S-1-5-18:(F)",
      ],
      { stdio: "ignore", windowsHide: true },
    ).status !== 0
  )
    throw Error("Key file protection failed");
  process.loadEnvFile(".env.storage-secrets");
  db = postgresDatabase(
    postgresPool(
      readFileSync(".env.runtime-production", "utf8")
        .trim()
        .slice("DATABASE_URL=".length),
    ),
  );
  const config = JSON.parse(
      (
        await db.one(
          "SELECT value FROM security_state WHERE id='metadata_backup_config'",
        )
      ).value,
    ),
    row = await db.one(
      "SELECT * FROM backup_history WHERE status='verified' ORDER BY created DESC LIMIT 1",
    );
  if (!row) throw Error("No verified backup");
  const credential = openCredentials(
    config.credential,
    Buffer.from(process.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY, "base64"),
    "metadata-backup-credential",
  );
  const storage = new CloudStorage({
    STORAGE_BUCKET: config.bucket,
    STORAGE_ENDPOINT: config.endpoint,
    STORAGE_REGION: config.region,
    STORAGE_KEY_ID: credential.keyId,
    STORAGE_APPLICATION_KEY: credential.applicationKey,
  });
  const bytes = await readBounded(
    (await storage.get(row.object_key)).body,
    70 * 1024 * 1024,
  );
  if (createHash("sha256").update(bytes).digest("hex") !== row.digest)
    throw Error("Stored digest mismatch");
  const payload = decryptBackup(bytes, readFileSync(filename, "utf8"));
  if (payload.storageKey !== process.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY)
    throw Error("Recovered storage key mismatch");
  for (const r of payload.tables.workspace_storage)
    if (r.credential)
      openCredentials(
        r.credential,
        Buffer.from(payload.storageKey, "base64"),
        r.tenant,
      );
  const at = new Date().toISOString(),
    report = {
      verifiedAt: at,
      backupId: row.id,
      vaultExportFile: basename(filename),
      offsiteDecryptionVerified: true,
      storageCredentialRecoveryVerified: true,
    };
  await db.run(
    "INSERT INTO security_state(id,value,updated) VALUES('vault_key_readback',?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
    JSON.stringify(report),
    at,
  );
  await createSecurityLog({ db }).event("recovery_verified", {
    actor: "patrick@streamlinedconsulting.online",
  });
  console.log(JSON.stringify(report));
} catch {
  console.error(
    JSON.stringify({
      verified: false,
      message:
        "Vault-export key verification did not complete; check the protected export file and off-site backup access. No key contents were logged.",
    }),
  );
  process.exitCode = 1;
} finally {
  await db?.close();
}
