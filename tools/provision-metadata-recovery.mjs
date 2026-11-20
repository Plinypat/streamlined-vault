import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, isAbsolute } from "node:path";
import { generateKeyPairSync, createHash, createPublicKey } from "node:crypto";
import {
  BucketProvisioner,
  sealCredentials,
} from "../server/workspace-storage.mjs";
import { postgresPool } from "../server/postgres.mjs";
import { postgresDatabase, migratePostgres } from "../server/database.mjs";
import { recoveryKeyId } from "../server/metadata-recovery.mjs";
const arg = (n) => process.argv[process.argv.indexOf(n) + 1];
const need = (v) => {
  if (!v) throw Error("Recovery configuration validation failed");
};
const hash = (s) => createHash("sha256").update(s).digest("hex");
function protect(path, data) {
  writeFileSync(path, data, { flag: "wx", mode: 0o600 });
  if (process.platform === "win32")
    need(
      spawnSync(
        "icacls.exe",
        [
          path,
          "/inheritance:r",
          "/grant:r",
          process.env.USERDOMAIN + "\\" + process.env.USERNAME + ":(F)",
          "*S-1-5-18:(F)",
        ],
        { stdio: "ignore", windowsHide: true },
      ).status === 0,
    );
}
let db;
try {
  need(process.argv.includes("--confirm-30-day-recovery"));
  const cli = arg("--b2-cli"),
    expected = arg("--expected-account-fingerprint"),
    origin = new URL(arg("--origin")).origin;
  need(
    isAbsolute(cli) &&
      /^[a-f0-9]{64}$/.test(expected) &&
      origin.startsWith("https://"),
  );
  db = postgresDatabase(postgresPool(process.env.DATABASE_MIGRATION_URL));
  await migratePostgres(db);
  const local = spawnSync(cli, ["account", "get"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 15000,
  });
  need(local.status === 0);
  const account = JSON.parse(local.stdout),
    provider = new BucketProvisioner(),
    auth = await provider.authorize(
      account.applicationKeyId,
      account.applicationKey,
      true,
    );
  need(hash(auth.accountId) === expected && auth.region === "us-west-004");
  const suffix = hash(origin).slice(0, 24),
    name = "sv-recovery-" + suffix;
  const rules = [
    {
      fileNamePrefix: "metadata/",
      daysFromUploadingToHiding: 30,
      daysFromHidingToDeleting: 1,
      daysFromStartingToCancelingUnfinishedLargeFiles: 1,
    },
  ];
  let bucket = (
    await provider.call(auth, "b2_list_buckets", { bucketName: name })
  ).buckets?.find((b) => b.bucketName === name);
  if (!bucket)
    bucket = await provider.call(auth, "b2_create_bucket", {
      bucketName: name,
      bucketType: "allPrivate",
      bucketInfo: { "sv-purpose": "metadata-recovery", "sv-origin": suffix },
      fileLockEnabled: false,
      defaultServerSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
      corsRules: [],
      lifecycleRules: rules,
    });
  need(
    bucket.bucketInfo?.["sv-purpose"] === "metadata-recovery" &&
      bucket.bucketInfo?.["sv-origin"] === suffix &&
      !bucket.fileLockConfiguration?.value?.isFileLockEnabled,
  );
  await provider.call(auth, "b2_update_bucket", {
    bucketId: bucket.bucketId,
    bucketType: "allPrivate",
    defaultServerSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
    corsRules: [],
    lifecycleRules: rules,
  });
  bucket = await provider.verify(auth, name);
  need(
    bucket.bucketType === "allPrivate" &&
      bucket.defaultServerSideEncryption?.value?.algorithm === "AES256" &&
      bucket.lifecycleRules?.length === 1 &&
      Object.entries(rules[0]).every(
        ([k, v]) => bucket.lifecycleRules[0][k] === v,
      ),
  );
  let configRow = await db.one(
    "SELECT value FROM security_state WHERE id='metadata_backup_config'",
  );
  if (!configRow) {
    const privatePath = resolve(".env.recovery-private.pem"),
      publicPath = resolve(".env.recovery-public.pem");
    need(!existsSync(privatePath) && !existsSync(publicPath));
    const keys = generateKeyPairSync("rsa", {
      modulusLength: 3072,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    protect(privatePath, keys.privateKey);
    protect(publicPath, keys.publicKey);
    const key = await provider.call(auth, "b2_create_key", {
      keyName: "sv-recovery-writer-" + suffix,
      bucketIds: [bucket.bucketId],
      capabilities: [
        "listBuckets",
        "readBuckets",
        "readBucketEncryption",
        "listFiles",
        "readFiles",
        "writeFiles",
      ],
    });
    need(key.applicationKeyId && key.applicationKey);
    const config = {
      purpose: "metadata-recovery",
      retentionDays: 30,
      bucket: name,
      bucketId: bucket.bucketId,
      endpoint: auth.endpoint,
      region: auth.region,
      publicKey: keys.publicKey,
      keyId: recoveryKeyId(keys.publicKey),
      credential: sealCredentials(
        { keyId: key.applicationKeyId, applicationKey: key.applicationKey },
        Buffer.from(process.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY, "base64"),
        "metadata-backup-credential",
      ),
    };
    await db.run(
      "INSERT INTO security_state(id,value,updated) VALUES('metadata_backup_config',?,?)",
      JSON.stringify(config),
      new Date().toISOString(),
    );
  }
  const runtime = new URL(process.env.RUNTIME_DATABASE_URL).username;
  need(/^sv_runtime_[a-f0-9]+$/.test(runtime));
  await db.exec(
    'GRANT SELECT,INSERT,UPDATE,DELETE ON streamlined_vault.backup_history,streamlined_vault.alert_deliveries,streamlined_vault.readiness_evidence TO "' +
      runtime +
      '"',
  );
  console.log(
    JSON.stringify({
      ok: true,
      bucket: name,
      retentionDays: 30,
      deleteAfterHiddenDays: 1,
      objectLock: false,
      privateKeyFile: resolve(".env.recovery-private.pem"),
      schemaVersion: 5,
      runtimeGrants: true,
    }),
  );
} catch {
  console.error(
    JSON.stringify({
      ok: false,
      event: "recovery_setup_failed",
      message:
        "Check protected environment, CLI authorization, account match and output files. No secrets logged.",
    }),
  );
  process.exitCode = 1;
} finally {
  await db?.close();
}
