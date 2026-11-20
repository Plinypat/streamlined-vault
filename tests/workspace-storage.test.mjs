import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import {
  createWorkspaceStorage,
  BucketProvisioner,
  FILE_CAPABILITIES,
  encryptionKey,
  sealCredentials,
  openCredentials,
  storageEndpoint,
} from "../server/workspace-storage.mjs";

const env = {
  STORAGE_CREDENTIAL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
  STORAGE_BUCKET: "original-shared",
  STORAGE_REGION: "us-west-004",
  STORAGE_ENDPOINT: "https://s3.us-west-004.backblazeb2.com",
  STORAGE_PROVISIONING_KEY_ID: "provisioner",
  STORAGE_PROVISIONING_APPLICATION_KEY: "synthetic-account-key",
};
async function fixture(options = {}) {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE files(id TEXT PRIMARY KEY,tenant TEXT)");
  const calls = [];
  const cloudFactory = (e) => {
    calls.push(e);
    return { bucket: e.STORAGE_BUCKET };
  };
  const provisioner = {
    connect: async (v) => ({ ...v, bucketId: "id-" + v.bucket }),
    create: async (tenant, e, onBucket) => {
      const v = {
        bucket: "sv-" + tenant.replaceAll("-", ""),
        bucketId: "id-" + tenant,
        endpoint: env.STORAGE_ENDPOINT,
        region: env.STORAGE_REGION,
        keyId: "key-" + tenant,
        applicationKey: "secret-" + tenant,
      };
      await onBucket(v);
      return v;
    },
  };
  const manager = await createWorkspaceStorage({
    db,
    env,
    demo: false,
    data: ".",
    cloudFactory,
    provisioner,
    ...options,
  });
  return { db, calls, manager, cloudFactory, provisioner };
}
const input = (bucket) => ({
  mode: "connect",
  bucket,
  endpoint: env.STORAGE_ENDPOINT,
  keyId: "synthetic-key-id",
  applicationKey: "synthetic-secret",
});

test("credentials are authenticated, encrypted and bound to the workspace", () => {
  const key = encryptionKey(env),
    value = { keyId: "sensitive-key-id", applicationKey: "secret-value" };
  const sealed = sealCredentials(value, key, "practice-a");
  assert.ok(!sealed.includes(value.applicationKey));
  assert.ok(!sealed.includes(value.keyId));
  assert.deepEqual(openCredentials(sealed, key, "practice-a"), value);
  assert.throws(() => openCredentials(sealed, key, "practice-b"));
  assert.throws(() => openCredentials(sealed, randomBytes(32), "practice-a"));
  assert.throws(
    () => encryptionKey({}),
    (e) => e.status === 503,
  );
});
test("endpoints reject arbitrary hosts, credentials, ports and URL paths", () => {
  assert.equal(storageEndpoint(env.STORAGE_ENDPOINT).region, "us-west-004");
  for (const value of [
    "http://s3.us-west-004.backblazeb2.com",
    "https://localhost",
    "https://s3.us-west-004.backblazeb2.com.evil.test",
    "https://user@s3.us-west-004.backblazeb2.com",
    "https://s3.us-west-004.backblazeb2.com:8080",
    "https://s3.us-west-004.backblazeb2.com/evil",
  ])
    assert.throws(() => storageEndpoint(value));
});
test("workspace file adapters use separate buckets and credentials; legacy files stay in their original bucket", async () => {
  const { manager, db, calls, cloudFactory, provisioner } = await fixture();
  await manager.provision("practice-a", input("practice-a-bucket"));
  await manager.provision("practice-b", { mode: "create" });
  assert.equal(await manager.location("practice-a"), "practice-a");
  assert.equal(
    (
      await manager.forFile({
        tenant: "practice-a",
        storage_tenant: "practice-a",
      })
    ).bucket,
    "practice-a-bucket",
  );
  assert.equal(
    (
      await manager.forFile({
        tenant: "practice-b",
        storage_tenant: "practice-b",
      })
    ).bucket,
    "sv-practiceb",
  );
  assert.equal(
    (await manager.forFile({ tenant: "practice-a", storage_tenant: null }))
      .bucket,
    "original-shared",
  );
  await assert.rejects(
    async () =>
      await manager.forFile({
        tenant: "practice-b",
        storage_tenant: "practice-a",
      }),
    (e) => e.status === 403,
  );
  assert.equal(calls[0].STORAGE_KEY_ID, "synthetic-key-id");
  assert.equal(calls[1].STORAGE_KEY_ID, "key-practice-b");
  assert.ok(
    !JSON.stringify(
      db.prepare("SELECT * FROM workspace_storage").all(),
    ).includes("synthetic-secret"),
  );
  const reopened = await createWorkspaceStorage({
    db,
    env,
    demo: false,
    data: ".",
    cloudFactory,
    provisioner,
  });
  assert.equal(
    (
      await reopened.forFile({
        tenant: "practice-a",
        storage_tenant: "practice-a",
      })
    ).bucket,
    "practice-a-bucket",
  );
  assert.deepEqual(await manager.view("practice-a"), {
    kind: "dedicated",
    status: "ready",
  });
  assert.ok(
    !JSON.stringify(await manager.view("practice-a", true)).includes("keyId"),
  );
  db.close();
});
test("a bucket cannot be assigned twice and file-bearing workspaces cannot be reassigned", async () => {
  const { manager, db } = await fixture();
  await manager.provision("practice-a", input("practice-a-bucket"));
  await assert.rejects(
    manager.provision("practice-b", input("practice-a-bucket")),
    (e) => e.status === 409,
  );
  await assert.rejects(
    manager.provision("practice-b", input("original-shared")),
    (e) => e.status === 409,
  );
  db.prepare("INSERT INTO files(id,tenant) VALUES(?,?)").run(
    "legacy-file",
    "practice-c",
  );
  await assert.rejects(
    manager.provision("practice-c", input("practice-c-bucket")),
    (e) => e.status === 409,
  );
  await assert.rejects(
    manager.provision("practice-a", input("replacement-bucket")),
    (e) => e.status === 409,
  );
  db.close();
});
test("failed provisioning blocks transfers and can resume using the same bucket", async () => {
  let failed = true;
  const f = await fixture({
    provisioner: {
      create: async () => {
        if (failed) throw Error("Synthetic provider failure");
        return {
          bucket: "sv-practicea",
          bucketId: "id-a",
          endpoint: env.STORAGE_ENDPOINT,
          region: env.STORAGE_REGION,
          keyId: "key-a",
          applicationKey: "secret-a",
        };
      },
    },
  });
  await assert.rejects(f.manager.provision("practice-a", { mode: "create" }));
  assert.equal((await f.manager.view("practice-a")).status, "error");
  await assert.rejects(
    async () => await f.manager.location("practice-a"),
    (e) => e.status === 503,
  );
  failed = false;
  await f.manager.provision("practice-a", { mode: "create" });
  assert.equal((await f.manager.view("practice-a")).status, "ready");
  f.db.close();
});

function providerFixture({
  capabilities = FILE_CAPABILITIES,
  buckets = [{ id: "id-a", name: "practice-a-bucket" }],
  privateBucket = true,
  encrypted = true,
  management = false,
} = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    let response;
    if (url.endsWith("b2_authorize_account"))
      response = {
        accountId: "account-a",
        authorizationToken: "synthetic-token",
        apiInfo: {
          storageApi: {
            apiUrl: "https://api004.backblazeb2.com",
            s3ApiUrl: env.STORAGE_ENDPOINT,
            allowed: {
              buckets: management ? null : buckets,
              capabilities: management
                ? [
                    ...FILE_CAPABILITIES,
                    "writeBuckets",
                    "writeBucketEncryption",
                    "writeKeys",
                  ]
                : capabilities,
              namePrefix: null,
            },
          },
        },
      };
    else if (url.endsWith("b2_list_buckets")) {
      const body = JSON.parse(options.body);
      response = {
        buckets:
          body.bucketName === "practice-a-bucket"
            ? [
                {
                  bucketName: body.bucketName,
                  bucketId: "id-a",
                  bucketType: privateBucket ? "allPrivate" : "allPublic",
                  defaultServerSideEncryption: {
                    value: {
                      mode: encrypted ? "SSE-B2" : null,
                      algorithm: "AES256",
                    },
                  },
                },
              ]
            : [],
      };
    } else if (url.endsWith("b2_create_bucket")) {
      const body = JSON.parse(options.body);
      response = { ...body, bucketId: "id-a" };
    } else if (url.endsWith("b2_create_key"))
      response = {
        applicationKeyId: "new-key-id",
        applicationKey: "new-secret",
      };
    return { ok: true, json: async () => response };
  };
  const provider = new BucketProvisioner({ fetchImpl });
  return { provider, calls };
}
test("provider connection requires a private encrypted bucket and exactly one bucket-restricted key", async () => {
  const { provider } = providerFixture();
  assert.equal(
    (await provider.connect(input("practice-a-bucket"))).bucketId,
    "id-a",
  );
  for (const options of [
    { buckets: null },
    { buckets: [{ id: "id-a" }, { id: "id-b" }] },
    { privateBucket: false },
    { encrypted: false },
    { capabilities: FILE_CAPABILITIES.filter((c) => c !== "writeFiles") },
    { capabilities: [...FILE_CAPABILITIES, "writeKeys"] },
  ])
    await assert.rejects(
      providerFixture(options).provider.connect(input("practice-a-bucket")),
      (e) => e.status === 400,
    );
});
test("automatic creation requests a private encrypted bucket and issues only a single-bucket file credential", async () => {
  const { provider, calls } = providerFixture({ management: true });
  let created;
  provider.verify = async () => ({ bucketId: "id-a" });
  const r = await provider.create(
    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    env,
    (v) => (created = v),
  );
  const bucket = JSON.parse(
      calls.find((c) => c.url.endsWith("b2_create_bucket")).options.body,
    ),
    key = JSON.parse(
      calls.find((c) => c.url.endsWith("b2_create_key")).options.body,
    );
  assert.equal(bucket.bucketType, "allPrivate");
  assert.deepEqual(bucket.defaultServerSideEncryption, {
    mode: "SSE-B2",
    algorithm: "AES256",
  });
  assert.ok(!bucket.bucketName.includes("practice"));
  assert.deepEqual(key.bucketIds, ["id-a"]);
  assert.deepEqual(key.capabilities, FILE_CAPABILITIES);
  assert.ok(!key.capabilities.includes("writeKeys"));
  assert.equal(r.keyId, "new-key-id");
  assert.equal(created.bucket, r.bucket);
});

test("stateless production hosts cannot provision buckets into ephemeral SQLite metadata", async () => {
  const { manager, db } = await fixture({ env: { ...env, VERCEL: "1" } });
  assert.equal(manager.capabilities().metadataPending, true);
  assert.equal(manager.capabilities().create, false);
  assert.equal(manager.capabilities().connect, false);
  assert.throws(
    () => manager.input({ mode: "create" }, "practice-a"),
    (e) => e.status === 503 && e.message.includes("Neon"),
  );
  db.close();
});
