import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CloudStorage } from "../server/storage.mjs";
import { openDatabase } from "../server/database.mjs";
import { createDirectTransfers } from "../server/direct-transfers.mjs";
import { BucketProvisioner } from "../server/workspace-storage.mjs";
import { contentSecurityPolicy } from "../server/clerk-auth.mjs";

test("direct multipart transfers move 33 MiB outside the portal and verify provider parts, checksums and scoped links", async (t) => {
  const stored = new Map();
  let object;
  const fake = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    res.setHeader("Content-Type", "application/xml");
    if (req.method === "POST" && url.searchParams.has("uploads"))
      return res.end(
        "<InitiateMultipartUploadResult><UploadId>synthetic-upload</UploadId></InitiateMultipartUploadResult>",
      );
    if (req.method === "PUT") {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const bytes = Buffer.concat(chunks);
      if (
        createHash("md5").update(bytes).digest("base64") !==
        req.headers["content-md5"]
      ) {
        res.statusCode = 400;
        return res.end("<Error><Code>BadDigest</Code></Error>");
      }
      const number = Number(url.searchParams.get("partNumber")),
        etag = '"' + createHash("md5").update(bytes).digest("hex") + '"';
      stored.set(number, { bytes, etag });
      res.setHeader("ETag", etag);
      return res.end();
    }
    if (req.method === "GET" && url.searchParams.has("uploadId")) {
      const marker = Number(url.searchParams.get("part-number-marker") || 0),
        max = Number(url.searchParams.get("max-parts") || 1000);
      const parts = [...stored]
        .filter(([n]) => n > marker)
        .sort((a, b) => a[0] - b[0])
        .slice(0, max);
      return res.end(
        "<ListPartsResult><IsTruncated>false</IsTruncated>" +
          parts
            .map(
              ([n, p]) =>
                `<Part><PartNumber>${n}</PartNumber><Size>${p.bytes.length}</Size><ETag>${p.etag}</ETag></Part>`,
            )
            .join("") +
          "</ListPartsResult>",
      );
    }
    if (req.method === "POST") {
      for await (const chunk of req) {
      }
      object = Buffer.concat(
        [...stored].sort((a, b) => a[0] - b[0]).map(([, p]) => p.bytes),
      );
      return res.end(
        "<CompleteMultipartUploadResult><ETag>complete</ETag></CompleteMultipartUploadResult>",
      );
    }
    if (object) {
      res.setHeader("Content-Length", object.length);
      res.setHeader("Content-Type", "application/octet-stream");
      return res.end(req.method === "HEAD" ? undefined : object);
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise((resolve) => fake.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => fake.close(resolve)));
  const endpoint = "http://127.0.0.1:" + fake.address().port,
    storage = new CloudStorage({
      STORAGE_ENDPOINT: endpoint,
      STORAGE_REGION: "us-west-004",
      STORAGE_BUCKET: "synthetic-bucket",
      STORAGE_KEY_ID: "synthetic-key",
      STORAGE_APPLICATION_KEY: "synthetic-secret",
    });
  const data = mkdtempSync(join(tmpdir(), "vault-direct-")),
    db = await openDatabase({ env: {}, demo: true, data });
  t.after(async () => {
    await db.close();
    rmSync(data, { recursive: true, force: true });
  });
  const partSize = 16 * 1024 ** 2,
    size = 33 * 1024 ** 2,
    file = {
      id: "synthetic",
      tenant: "practice",
      key: "tenants/practice/objects/opaque",
      size,
      status: "uploading",
      name: "synthetic.bin",
    };
  file.upload = await storage.start(file.key);
  await db.run(
    "INSERT INTO tenants(id,name,quota,status) VALUES('practice','Synthetic',4000000000000,'active')",
  );
  await db.run(
    "INSERT INTO files(id,tenant,name,folder,size,key,status,created) VALUES(?,?,?,?,?,?,?,?)",
    file.id,
    file.tenant,
    file.name,
    "General",
    size,
    file.key,
    "uploading",
    new Date().toISOString(),
  );
  let metered = 0,
    downloads = 0,
    failDownload = false;
  const direct = createDirectTransfers({
    db,
    workspaceStorage: { forFile: async () => storage },
    partSize,
    audit: async () => {},
    mspConsole: {
      recordUpload: async (t, n) => (metered += n),
      reserveDownload: async (t, n) => {
        if (failDownload) throw Object.assign(Error("limit"), { status: 409 });
        return "reservation";
      },
      finishDownload: async (id, n) => (downloads += n),
    },
  });
  const bytes = Buffer.alloc(size, 37),
    md5 = (b) => createHash("md5").update(b).digest("base64");
  for (let n = 1; n <= 3; n++) {
    const chunk = bytes.subarray((n - 1) * partSize, n * partSize);
    const grant = await db.transaction(() =>
      direct.part(file, n, "sign", { md5: md5(chunk) }),
    );
    const signed = new URL(grant.url);
    assert.equal(signed.pathname, "/synthetic-bucket/" + file.key);
    assert.equal(signed.searchParams.get("partNumber"), String(n));
    assert.equal(signed.searchParams.get("X-Amz-Expires"), "300");
    assert.match(
      signed.searchParams.get("X-Amz-SignedHeaders"),
      /content-length;content-md5/,
    );
    if (n === 1) {
      const corrupt = Buffer.from(chunk);
      corrupt[0]++;
      assert.equal(
        (
          await fetch(grant.url, {
            method: "PUT",
            headers: grant.headers,
            body: corrupt,
          })
        ).status,
        400,
      );
      await assert.rejects(
        () => db.transaction(() => direct.part(file, n, "ack", {})),
        (e) => e.status === 409,
      );
    }
    assert.equal(
      (
        await fetch(grant.url, {
          method: "PUT",
          headers: grant.headers,
          body: chunk,
        })
      ).status,
      200,
    );
    await db.transaction(() => direct.part(file, n, "ack", {}));
    await db.transaction(() => direct.part(file, n, "ack", {}));
  }
  assert.equal(metered, size);
  await assert.rejects(
    () =>
      db.transaction(() =>
        direct.part(file, 1, "sign", { md5: md5(Buffer.from("different")) }),
      ),
    (e) => e.status === 409,
  );
  await assert.rejects(
    () => direct.part(file, 4, "sign", { md5: md5(bytes) }),
    (e) => e.status === 400,
  );
  const parts = await db.q(
    "SELECT number,size,etag FROM parts WHERE file=? ORDER BY number",
    file.id,
  );
  await direct.verify(file, parts);
  const original = stored.get(1).etag;
  stored.get(1).etag = '"changed"';
  await assert.rejects(
    () => direct.verify(file, parts),
    (e) => e.status === 409,
  );
  stored.get(1).etag = original;
  await storage.complete(file.key, file.upload, parts);
  assert.equal((await storage.head(file.key)).size, size);
  const link = await direct.download(file, "synthetic@example.test");
  assert.equal(new URL(link.url).searchParams.get("X-Amz-Expires"), "60");
  assert.equal(downloads, size);
  assert.deepEqual(
    Buffer.from(await (await fetch(link.url)).arrayBuffer()),
    bytes,
  );
  failDownload = true;
  await assert.rejects(
    () => direct.download(file, "synthetic@example.test"),
    (e) => e.status === 409,
  );
  assert.equal(downloads, size);
});

test("browser transfer configuration preserves other rules, restricts origin and keeps the bucket private", async () => {
  const provider = new BucketProvisioner(),
    prior = {
      corsRuleName: "existing",
      allowedOrigins: ["https://other.example"],
    };
  let update;
  provider.checkProvisioning = async () => ({});
  provider.verify = async () => ({
    bucketId: "synthetic",
    revision: 4,
    corsRules: [prior],
  });
  provider.call = async (auth, method, value) => {
    assert.equal(method, "b2_update_bucket");
    update = value;
  };
  await provider.browserCors("synthetic-bucket", {
    APP_ORIGIN: "https://www.streamlinedvault.com",
  });
  assert.equal(update.bucketType, "allPrivate");
  assert.deepEqual(update.corsRules[0], prior);
  assert.deepEqual(update.corsRules[1].allowedOrigins, [
    "https://www.streamlinedvault.com",
  ]);
  assert.ok(!update.corsRules[1].allowedOrigins.includes("*"));
  assert.ok(
    contentSecurityPolicy("", true).includes("https://*.backblazeb2.com"),
  );
  assert.ok(!contentSecurityPolicy("").includes("backblazeb2"));
  await assert.rejects(
    () =>
      provider.browserCors("synthetic-bucket", {
        APP_ORIGIN: "http://example.test",
      }),
    (e) => e.status === 400,
  );
});
