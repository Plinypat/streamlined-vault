import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { join } from "node:path";
import { CloudStorage, LocalStorage } from "./storage.mjs";
import { sqliteDatabase } from "./database.mjs";

const fail = (status, message) => Object.assign(Error(message), { status });
const requireValue = (test, status, message) => {
  if (!test) throw fail(status, message);
};
export const FILE_CAPABILITIES = [
  "listBuckets",
  "readBuckets",
  "readBucketEncryption",
  "listFiles",
  "readFiles",
  "writeFiles",
  "deleteFiles",
];
const ADMIN_CAPABILITIES = [
  "listBuckets",
  "writeBuckets",
  "writeBucketEncryption",
  "readBucketEncryption",
  "writeKeys",
  ...FILE_CAPABILITIES,
];
export function encryptionKey(env) {
  const value = env.STORAGE_CREDENTIAL_ENCRYPTION_KEY || "";
  requireValue(
    /^[A-Za-z0-9+/]{43}=$/.test(value),
    503,
    "Dedicated storage requires the server credential-encryption key",
  );
  return Buffer.from(value, "base64");
}
export function sealCredentials(value, key, context) {
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(context));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  return JSON.stringify({
    v: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: ciphertext.toString("base64"),
  });
}
export function openCredentials(value, key, context) {
  const v = JSON.parse(value);
  requireValue(
    v.v === 1,
    503,
    "Storage credentials need administrator attention",
  );
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(v.iv, "base64"),
  );
  decipher.setAAD(Buffer.from(context));
  decipher.setAuthTag(Buffer.from(v.tag, "base64"));
  return JSON.parse(
    Buffer.concat([
      decipher.update(Buffer.from(v.data, "base64")),
      decipher.final(),
    ]).toString("utf8"),
  );
}
export function storageEndpoint(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw fail(400, "Enter a valid storage S3 endpoint");
  }
  requireValue(
    url.protocol === "https:" &&
      /^s3\.[a-z]+-[a-z]+-\d{3}\.backblazeb2\.com$/.test(url.hostname) &&
      !url.port &&
      !url.username &&
      !url.password &&
      url.pathname === "/" &&
      !url.search &&
      !url.hash,
    400,
    "Use the storage account’s exact HTTPS S3 endpoint",
  );
  return { endpoint: url.origin, region: url.hostname.split(".")[1] };
}
const bucketName = (value) =>
  typeof value === "string" &&
  /^[a-z0-9][a-z0-9-]{4,61}[a-z0-9]$/.test(value) &&
  !value.startsWith("b2-");
const nativeUrl = (value) => {
  const u = new URL(value);
  requireValue(
    u.protocol === "https:" &&
      /^api\d+\.backblazeb2\.com$/.test(u.hostname) &&
      !u.port &&
      !u.username &&
      !u.password &&
      u.pathname === "/",
    502,
    "Storage authorization returned an invalid endpoint",
  );
  return u.origin;
};

// The account-level provisioning credential is never used for file transfers.
export class BucketProvisioner {
  constructor({ fetchImpl = fetch, timeoutMs = 20000 } = {}) {
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
  }
  async json(url, options) {
    let r;
    try {
      r = await this.fetch(url, {
        ...options,
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      throw fail(
        502,
        "Storage provider could not be reached; retry setup shortly",
      );
    }
    let d;
    try {
      d = await r.json();
    } catch {
      throw fail(502, "Storage provider returned an invalid response");
    }
    if (!r.ok) {
      const known = {
        too_many_buckets: "Storage account bucket limit reached",
        duplicate_bucket_name: "Bucket name is already in use",
        unauthorized: "Storage credential is missing required permissions",
        bad_auth_token: "Storage credential was rejected",
        expired_auth_token: "Storage authorization expired; retry setup",
      };
      const operation = new URL(url).pathname.split("/").at(-1);
      const failure = fail(
        r.status === 401 || r.status === 403 ? 400 : 502,
        known[d.code] ||
          "Storage setup was rejected; check the bucket and key permissions",
      );
      failure.providerOperation = [
        "b2_authorize_account",
        "b2_list_buckets",
        "b2_create_bucket",
        "b2_create_key",
        "b2_list_file_versions",
      ].includes(operation)
        ? operation
        : "unknown";
      failure.providerCode = Object.hasOwn(known, d.code)
        ? d.code
        : "provider_error";
      console.warn(
        JSON.stringify({
          event: "storage_provider_rejected",
          operation: failure.providerOperation,
          code: failure.providerCode,
          status: r.status,
        }),
      );
      throw failure;
    }
    return d;
  }
  async authorize(keyId, applicationKey, provisioning = false) {
    const fields = provisioning
      ? ["STORAGE_PROVISIONING_KEY_ID", "STORAGE_PROVISIONING_APPLICATION_KEY"]
      : ["Bucket key ID", "Bucket application key"];
    const clean = (value, field) => {
      const text = typeof value === "string" ? value.trim() : "";
      const problem =
        !text || /[\s"']/.test(text) || text.startsWith(field + "=");
      if (problem) {
        const e = fail(
          400,
          `${field} must contain only its value, without quotes or a variable-name prefix`,
        );
        e.field = field;
        throw e;
      }
      return text;
    };
    keyId = clean(keyId, fields[0]);
    applicationKey = clean(applicationKey, fields[1]);
    let d;
    try {
      d = await this.json(
        "https://api.backblazeb2.com/b2api/v4/b2_authorize_account",
        {
          headers: {
            Authorization:
              "Basic " +
              Buffer.from(keyId + ":" + applicationKey).toString("base64"),
          },
        },
      );
    } catch (e) {
      if (
        e.providerOperation === "b2_authorize_account" &&
        e.providerCode === "bad_auth_token"
      )
        e.message = provisioning
          ? "The provisioning key ID and application key did not authenticate as a matching pair"
          : "The bucket key ID and application key did not authenticate as a matching pair";
      throw e;
    }
    const api = d.apiInfo?.storageApi;
    requireValue(
      api && d.accountId && d.authorizationToken,
      502,
      "Storage authorization response was incomplete",
    );
    return {
      accountId: d.accountId,
      token: d.authorizationToken,
      apiUrl: nativeUrl(api.apiUrl),
      ...storageEndpoint(api.s3ApiUrl),
      allowed: api.allowed,
      expires: d.applicationKeyExpirationTimestamp,
    };
  }
  call(auth, method, payload) {
    return this.json(auth.apiUrl + "/b2api/v4/" + method, {
      method: "POST",
      headers: {
        Authorization: auth.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ accountId: auth.accountId, ...payload }),
    });
  }
  async verify(auth, bucket) {
    const d = await this.call(auth, "b2_list_buckets", { bucketName: bucket });
    const b = d.buckets?.find((x) => x.bucketName === bucket);
    requireValue(b, 400, "Bucket was not found for this storage credential");
    requireValue(b.bucketType === "allPrivate", 400, "Choose a private bucket");
    requireValue(
      b.defaultServerSideEncryption?.value?.mode === "SSE-B2" &&
        b.defaultServerSideEncryption.value.algorithm === "AES256",
      400,
      "Enable default AES256 encryption and allow readBucketEncryption on the key",
    );
    return b;
  }
  async connect(input) {
    const auth = await this.authorize(input.keyId, input.applicationKey);
    const allowed = auth.allowed;
    requireValue(
      Array.isArray(allowed?.buckets) && allowed.buckets.length === 1,
      400,
      "Use an application key restricted to exactly one bucket",
    );
    requireValue(
      !allowed.namePrefix,
      400,
      "Use a bucket key without a file-name prefix restriction",
    );
    requireValue(
      FILE_CAPABILITIES.every((c) => allowed.capabilities?.includes(c)) &&
        !allowed.capabilities?.some((c) =>
          [
            "writeKeys",
            "deleteKeys",
            "writeBuckets",
            "deleteBuckets",
            "bypassGovernance",
          ].includes(c),
        ),
      400,
      "Use a bucket-restricted file key with the documented permissions and no account-management permissions",
    );
    requireValue(
      !auth.expires || auth.expires > Date.now() + 86400000,
      400,
      "Storage credential expires too soon",
    );
    requireValue(
      auth.endpoint === input.endpoint,
      400,
      "S3 endpoint does not match the application key’s account",
    );
    const b = await this.verify(auth, input.bucket);
    requireValue(
      allowed.buckets[0].id === b.bucketId,
      400,
      "Application key is assigned to a different bucket",
    );
    return { ...input, bucketId: b.bucketId };
  }
  async checkProvisioning(env) {
    const auth = await this.authorize(
      env.STORAGE_PROVISIONING_KEY_ID,
      env.STORAGE_PROVISIONING_APPLICATION_KEY,
      true,
    );
    requireValue(
      !auth.allowed?.buckets?.length &&
        !auth.allowed?.namePrefix &&
        ADMIN_CAPABILITIES.every((c) =>
          auth.allowed?.capabilities?.includes(c),
        ),
      400,
      "Provisioning key needs unrestricted bucket creation and key creation permissions",
    );
    return auth;
  }
  async create(tenant, env, onBucket) {
    const auth = await this.checkProvisioning(env);
    const bucket = "sv-" + tenant.replaceAll("-", "");
    // Deterministic opaque name allows recovery after a timeout without creating another bucket.
    const list = await this.call(auth, "b2_list_buckets", {
      bucketName: bucket,
    });
    let b = list.buckets?.find((x) => x.bucketName === bucket);
    if (!b)
      b = await this.call(auth, "b2_create_bucket", {
        bucketName: bucket,
        bucketType: "allPrivate",
        bucketInfo: { "sv-workspace": tenant },
        defaultServerSideEncryption: { mode: "SSE-B2", algorithm: "AES256" },
        corsRules: [],
        lifecycleRules: [],
      });
    requireValue(
      b.bucketInfo?.["sv-workspace"] === tenant,
      409,
      "Bucket ownership marker does not match this workspace",
    );
    await this.verify(auth, bucket);
    await onBucket({
      bucket,
      bucketId: b.bucketId,
      endpoint: auth.endpoint,
      region: auth.region,
    });
    const key = await this.call(auth, "b2_create_key", {
      keyName: "sv-" + tenant.replaceAll("-", ""),
      bucketIds: [b.bucketId],
      capabilities: FILE_CAPABILITIES,
    });
    requireValue(
      key.applicationKeyId && key.applicationKey,
      502,
      "Storage provider did not return a file credential",
    );
    return {
      bucket,
      bucketId: b.bucketId,
      endpoint: auth.endpoint,
      region: auth.region,
      keyId: key.applicationKeyId,
      applicationKey: key.applicationKey,
    };
  }
}

export async function createWorkspaceStorage({
  db,
  env,
  demo,
  data,
  provisioner = new BucketProvisioner(),
  cloudFactory = (e) => new CloudStorage(e),
}) {
  db = sqliteDatabase(db);
  if (db.kind !== "postgres") {
    await db.exec(`CREATE TABLE IF NOT EXISTS workspace_storage(tenant TEXT PRIMARY KEY,bucket TEXT NOT NULL UNIQUE,bucket_id TEXT,endpoint TEXT NOT NULL,region TEXT NOT NULL,credential TEXT,mode TEXT NOT NULL,status TEXT NOT NULL,created TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS storage_requests(request_id TEXT PRIMARY KEY,tenant TEXT NOT NULL UNIQUE,name TEXT NOT NULL);`);
    if (!(await db.hasColumn("files", "storage_tenant")))
      await db.exec("ALTER TABLE files ADD COLUMN storage_tenant TEXT");
    if (!(await db.hasColumn("workspace_storage", "lease_token")))
      await db.exec(
        "ALTER TABLE workspace_storage ADD COLUMN lease_token TEXT",
      );
    if (!(await db.hasColumn("workspace_storage", "lease_until")))
      await db.exec(
        "ALTER TABLE workspace_storage ADD COLUMN lease_until BIGINT NOT NULL DEFAULT 0",
      );
  }
  const get = async (t) =>
      await db.one("SELECT * FROM workspace_storage WHERE tenant=?", t),
    clients = new Map();
  let legacy;
  const metadataPending =
    !demo && db.kind !== "postgres" && !!(env.VERCEL || env.VERCEL_ENV);
  const capabilities = () => {
    let encrypted = demo;
    try {
      if (!demo) {
        encryptionKey(env);
        encrypted = true;
      }
    } catch {}
    return {
      connect: encrypted && !metadataPending,
      create:
        encrypted &&
        !metadataPending &&
        (demo ||
          !!(
            env.STORAGE_PROVISIONING_KEY_ID &&
            env.STORAGE_PROVISIONING_APPLICATION_KEY
          )),
      setupRequired: !encrypted || metadataPending,
      metadataPending,
    };
  };
  function input(value, tenant) {
    const v = value || { mode: "create" };
    requireValue(
      ["create", "connect"].includes(v.mode),
      400,
      "Choose new or existing dedicated storage",
    );
    requireValue(
      !metadataPending,
      503,
      "Dedicated storage provisioning on this host requires the Neon metadata migration first",
    );
    if (demo)
      return {
        mode: v.mode,
        bucket: v.bucket || "sv-" + tenant.replaceAll("-", ""),
        endpoint: "local",
        region: "local",
      };
    encryptionKey(env);
    if (v.mode === "create") {
      requireValue(
        env.STORAGE_PROVISIONING_KEY_ID &&
          env.STORAGE_PROVISIONING_APPLICATION_KEY,
        503,
        "Automatic bucket creation needs the server provisioning credential; connect an existing bucket instead",
      );
      return { mode: "create" };
    }
    requireValue(
      bucketName(v.bucket),
      400,
      "Use a 6–63 character lowercase bucket name containing letters, numbers and hyphens",
    );
    requireValue(
      typeof v.keyId === "string" &&
        v.keyId.length > 0 &&
        v.keyId.length < 200 &&
        typeof v.applicationKey === "string" &&
        v.applicationKey.length > 0 &&
        v.applicationKey.length < 300,
      400,
      "Bucket key ID and application key are required",
    );
    const e = storageEndpoint(v.endpoint);
    requireValue(
      v.bucket !== env.STORAGE_BUCKET,
      409,
      "The original shared bucket cannot be assigned as dedicated storage",
    );
    return {
      mode: v.mode,
      bucket: v.bucket,
      ...e,
      keyId: v.keyId.trim(),
      applicationKey: v.applicationKey.trim(),
    };
  }
  async function view(tenant, msp = false) {
    const s = await get(tenant);
    return s
      ? {
          kind: "dedicated",
          status: s.status,
          ...(msp
            ? {
                bucket: s.bucket,
                endpoint: s.endpoint,
                region: s.region,
                mode: s.mode,
              }
            : {}),
        }
      : {
          kind: "legacy",
          status: "ready",
          ...(msp
            ? {
                bucket: env.STORAGE_BUCKET || "Local shared storage",
                region: env.STORAGE_REGION || "local",
              }
            : {}),
        };
  }
  async function provision(tenant, value) {
    const v = input(value, tenant),
      name =
        v.mode === "create" ? "sv-" + tenant.replaceAll("-", "") : v.bucket,
      lease = randomBytes(24).toString("hex");
    await db.transaction(async () => {
      await db.lock("tenant:" + tenant);
      await db.lock("bucket:" + name);
      const old = await get(tenant);
      requireValue(
        !old || old.status !== "ready",
        409,
        "Dedicated storage is already assigned",
      );
      requireValue(
        !old || old.status !== "provisioning" || old.lease_until < Date.now(),
        409,
        "Storage setup is already running; retry shortly",
      );
      requireValue(
        !(await db.one("SELECT id FROM files WHERE tenant=? LIMIT 1", tenant)),
        409,
        "This workspace contains files; changing buckets requires a separately verified migration",
      );
      requireValue(
        !(await db.one(
          "SELECT tenant FROM workspace_storage WHERE bucket=? AND tenant<>?",
          name,
          tenant,
        )),
        409,
        "Bucket is already assigned to another workspace",
      );
      requireValue(
        !old || (old.bucket === name && old.mode === v.mode),
        409,
        "Resume setup using the same bucket; contact support to reconcile partial provisioning",
      );
      await db.run(
        "INSERT INTO workspace_storage(tenant,bucket,endpoint,region,mode,status,created,lease_token,lease_until) VALUES(?,?,?,?,?,'provisioning',?,?,?) ON CONFLICT(tenant) DO UPDATE SET status='provisioning',lease_token=excluded.lease_token,lease_until=excluded.lease_until",
        tenant,
        name,
        v.endpoint || "",
        v.region || "",
        v.mode,
        new Date().toISOString(),
        lease,
        Date.now() + 300000,
      );
    });
    try {
      let result;
      if (demo) result = { ...v, bucket: name, bucketId: name };
      else if (v.mode === "connect") result = await provisioner.connect(v);
      else
        result = await provisioner.create(tenant, env, async (r) => {
          const update = await db.run(
            "UPDATE workspace_storage SET bucket_id=?,endpoint=?,region=? WHERE tenant=? AND lease_token=?",
            r.bucketId,
            r.endpoint,
            r.region,
            tenant,
            lease,
          );
          requireValue(
            update.changes === 1,
            409,
            "Storage setup ownership changed; contact support",
          );
        });
      const sealed = demo
        ? null
        : sealCredentials(
            { keyId: result.keyId, applicationKey: result.applicationKey },
            encryptionKey(env),
            tenant,
          );
      const update = await db.run(
        "UPDATE workspace_storage SET bucket=?,bucket_id=?,endpoint=?,region=?,credential=?,status='ready',lease_token=NULL,lease_until=0 WHERE tenant=? AND lease_token=?",
        result.bucket,
        result.bucketId,
        result.endpoint,
        result.region,
        sealed,
        tenant,
        lease,
      );
      requireValue(
        update.changes === 1,
        409,
        "Storage setup ownership changed; contact support",
      );
      return await view(tenant, true);
    } catch (e) {
      await db.run(
        "UPDATE workspace_storage SET status='error',lease_token=NULL,lease_until=0 WHERE tenant=? AND lease_token=?",
        tenant,
        lease,
      );
      throw e;
    }
  }
  async function location(tenant) {
    const s = await get(tenant);
    requireValue(
      !s || s.status === "ready",
      503,
      "Workspace storage setup is incomplete",
    );
    return s ? tenant : null;
  }
  async function forFile(file) {
    if (!file.storage_tenant) {
      legacy ??= demo
        ? new LocalStorage(join(data, "objects"))
        : cloudFactory(env);
      return legacy;
    }
    requireValue(
      file.storage_tenant === file.tenant,
      403,
      "File storage assignment does not match workspace",
    );
    const s = await get(file.storage_tenant);
    requireValue(
      s?.status === "ready",
      503,
      "Workspace storage is unavailable",
    );
    if (!clients.has(s.tenant)) {
      if (demo)
        clients.set(
          s.tenant,
          new LocalStorage(join(data, "workspace-objects", s.tenant)),
        );
      else {
        const secret = openCredentials(
          s.credential,
          encryptionKey(env),
          s.tenant,
        );
        clients.set(
          s.tenant,
          cloudFactory({
            ...env,
            STORAGE_ENDPOINT: s.endpoint,
            STORAGE_REGION: s.region,
            STORAGE_BUCKET: s.bucket,
            STORAGE_KEY_ID: secret.keyId,
            STORAGE_APPLICATION_KEY: secret.applicationKey,
          }),
        );
      }
    }
    return clients.get(s.tenant);
  }
  return { capabilities, input, view, provision, location, forFile };
}
