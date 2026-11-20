import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { postgresPool } from "../server/postgres.mjs";
import { postgresDatabase, migratePostgres } from "../server/database.mjs";
import {
  encryptedBackup,
  decryptBackup,
  restoreBackup,
} from "../server/metadata-recovery.mjs";
const value = (name) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
};
function protectedFile(path, bytes) {
  if (existsSync(path))
    throw Error("Output exists; choose a new protected filename");
  writeFileSync(path, bytes, { flag: "wx", mode: 0o600 });
  if (process.platform === "win32") {
    const account = process.env.USERDOMAIN + "\\" + process.env.USERNAME;
    const result = spawnSync(
      "icacls.exe",
      [path, "/inheritance:r", "/grant:r", account + ":(F)", "*S-1-5-18:(F)"],
      { stdio: "ignore", windowsHide: true },
    );
    if (result.status !== 0)
      throw Error("Could not restrict output file permissions");
  }
}
let db;
try {
  const mode = process.argv[2],
    file = value("--file");
  if (!["backup", "restore"].includes(mode) || !file)
    throw Error(
      "Use backup --file <new.svbackup> or restore --file <bundle> --confirm-isolated-target --key-output <new.env>",
    );
  const local =
    process.env.NODE_ENV === "test" &&
    process.env.TEST_DATABASE_LOCAL === "true";
  if (mode === "backup") {
    db = postgresDatabase(
      postgresPool(process.env.DATABASE_URL, { allowLocalTest: local }),
    );
    const bytes = await encryptedBackup(
      db,
      process.env.STORAGE_CREDENTIAL_ENCRYPTION_KEY,
      process.env.RECOVERY_BACKUP_KEY,
    );
    protectedFile(resolve(file), bytes);
    console.log(
      JSON.stringify({
        ok: true,
        encrypted: true,
        bytes: bytes.length,
        output: resolve(file),
      }),
    );
  } else {
    if (
      !process.argv.includes("--confirm-isolated-target") ||
      !value("--key-output") ||
      !process.env.RESTORE_DATABASE_URL
    )
      throw Error(
        "Explicit isolated-target confirmation, RESTORE_DATABASE_URL and key output are required",
      );
    const target = new URL(process.env.RESTORE_DATABASE_URL),
      source = process.env.DATABASE_URL
        ? new URL(process.env.DATABASE_URL)
        : null;
    if (
      source &&
      target.hostname === source.hostname &&
      target.pathname === source.pathname
    )
      throw Error("Restore target must differ from the source database");
    const payload = decryptBackup(
      readFileSync(resolve(file)),
      process.env.RECOVERY_PRIVATE_KEY_FILE
        ? readFileSync(resolve(process.env.RECOVERY_PRIVATE_KEY_FILE), "utf8")
        : process.env.RECOVERY_BACKUP_KEY,
    );
    const keyPath = resolve(value("--key-output"));
    if (existsSync(keyPath)) throw Error("Recovered key output already exists");
    db = postgresDatabase(
      postgresPool(process.env.RESTORE_DATABASE_URL, { allowLocalTest: local }),
    );
    await migratePostgres(db);
    protectedFile(
      keyPath,
      "STORAGE_CREDENTIAL_ENCRYPTION_KEY=" + payload.storageKey + "\n",
    );
    const result = await restoreBackup(db, payload);
    console.log(JSON.stringify({ ok: true, ...result, keyOutput: keyPath }));
  }
} catch (e) {
  console.error(
    JSON.stringify({
      event: "metadata_recovery_failed",
      code: /^[A-Z0-9_]+$/.test(e.code || "")
        ? e.code
        : "RECOVERY_CONFIGURATION",
      message:
        "Recovery operation did not complete. Check protected environment, tool options and isolated target; no credentials or row contents were logged.",
    }),
  );
  process.exitCode = 1;
} finally {
  await db?.close();
}
