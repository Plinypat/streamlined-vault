import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { BucketProvisioner } from "../server/workspace-storage.mjs";
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : null;
};
const hash = (s) => createHash("sha256").update(s).digest("hex");
const need = (v, m) => {
  if (!v) throw Error(m);
};
try {
  need(
    process.argv.includes("--confirm-365-day-lock"),
    "Explicit approved retention confirmation required",
  );
  const origin = new URL(arg("--origin")).origin,
    output = resolve(arg("--output") || ".env.audit-archive.json"),
    cli = arg("--b2-cli"),
    expected = arg("--expected-account-fingerprint");
  need(
    origin.startsWith("https://") &&
      cli &&
      isAbsolute(cli) &&
      /^[a-f0-9]{64}$/.test(expected),
    "Use an HTTPS origin, absolute CLI path and verified account fingerprint",
  );
  const local = spawnSync(cli, ["account", "get"], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 15000,
  });
  need(local.status === 0, "CLI authorization is unavailable");
  const account = JSON.parse(local.stdout),
    provider = new BucketProvisioner(),
    auth = await provider.authorize(
      account.applicationKeyId,
      account.applicationKey,
      true,
    );
  need(
    hash(auth.accountId) === expected,
    "CLI account does not match production",
  );
  const suffix = hash(origin).slice(0, 24),
    bucket = "sv-audit-" + suffix;
  let b = (
    await provider.call(auth, "b2_list_buckets", { bucketName: bucket })
  ).buckets?.find((b) => b.bucketName === bucket);
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
    "Bucket ownership marker does not match",
  );
  need(
    b.fileLockConfiguration?.value?.isFileLockEnabled,
    "Object Lock was not verified",
  );
  const retention = b.fileLockConfiguration.value.defaultRetention;
  if (
    retention?.mode !== "compliance" ||
    retention.period?.duration !== 365 ||
    retention.period.unit !== "days"
  )
    await provider.call(auth, "b2_update_bucket", {
      bucketId: b.bucketId,
      defaultRetention: {
        mode: "compliance",
        period: { duration: 365, unit: "days" },
      },
    });
  b = await provider.verify(auth, bucket);
  const lock = b.fileLockConfiguration?.value;
  need(
    lock?.isFileLockEnabled &&
      lock.defaultRetention.mode === "compliance" &&
      lock.defaultRetention.period.duration === 365 &&
      lock.defaultRetention.period.unit === "days",
    "Retention verification failed",
  );
  if (!existsSync(output)) {
    const caps = [
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
    const credential = await provider.call(auth, "b2_create_key", {
      keyName: "sv-audit-writer-" + suffix,
      bucketIds: [b.bucketId],
      capabilities: caps,
    });
    need(
      credential.applicationKeyId && credential.applicationKey,
      "Archive credential was not returned",
    );
    writeFileSync(
      output,
      JSON.stringify({
        bucket,
        keyId: credential.applicationKeyId,
        applicationKey: credential.applicationKey,
      }),
      { flag: "wx", mode: 0o600 },
    );
    if (process.platform === "win32") {
      const owner = process.env.USERDOMAIN + "\\" + process.env.USERNAME;
      need(
        spawnSync(
          "icacls.exe",
          [
            output,
            "/inheritance:r",
            "/grant:r",
            owner + ":(F)",
            "*S-1-5-18:(F)",
          ],
          { stdio: "ignore", windowsHide: true },
        ).status === 0,
        "Could not restrict credential file permissions",
      );
    }
  } else
    need(
      JSON.parse(readFileSync(output, "utf8")).bucket === bucket,
      "Existing credential file belongs to another bucket",
    );
  console.log(
    JSON.stringify({
      ok: true,
      bucket,
      retentionDays: 365,
      mode: "COMPLIANCE",
      accountVerified: true,
      credentialFile: output,
    }),
  );
} catch (e) {
  console.error(
    JSON.stringify({
      event: "archive_provisioning_failed",
      code: e.providerCode || "ARCHIVE_SETUP",
      message:
        "Archive provisioning did not complete. No secret values were logged; check account matching, explicit approval and provider permissions.",
    }),
  );
  process.exitCode = 1;
}
