import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { openDatabase } from "../server/database.mjs";
import { createMspConsole, validatePlan } from "../server/msp-console.mjs";

test("plan validation rejects invalid hard limits and drops unknown fields", () => {
  assert.throws(
    () =>
      validatePlan({
        published: true,
        downloadMode: "block",
        downloadLimitBytes: null,
      }),
    (e) => e.status === 400,
  );
  assert.throws(
    () => validatePlan({ published: true, downloadOverageCentsPerGB: -1 }),
    (e) => e.status === 400,
  );
  assert.throws(
    () => validatePlan(null),
    (e) => e.status === 400,
  );
  assert.equal(
    validatePlan({ published: false, unrelated: "ignored" }).unrelated,
    undefined,
  );
});
test("account inventory includes retained versions and resumes from an encrypted cursor without exposing file names", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "vault-msp-")),
    db = await openDatabase({ env: {}, demo: true, data: dir });
  t.after(async () => {
    await db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const calls = [],
    provider = {
      checkProvisioning: async () => ({}),
      call: async (auth, method, body) => {
        calls.push(method);
        if (method === "b2_list_buckets")
          return {
            buckets: [
              { bucketId: "one", bucketName: "portal-bucket" },
              { bucketId: "two", bucketName: "outside-portal-bucket" },
              { bucketId: "three", bucketName: "retained-bucket" },
            ],
          };
        assert.equal(method, "b2_list_file_versions");
        if (body.bucketId === "one" && !body.startFileName)
          return {
            files: [{ action: "upload", contentLength: 5 }],
            nextFileName: "sensitive-file-cursor",
            nextFileId: "private-cursor-id",
          };
        if (body.bucketId === "one")
          return {
            files: [
              { action: "upload", contentLength: 7 },
              { action: "start", contentLength: 99 },
            ],
            nextFileName: null,
          };
        return {
          files: [
            {
              action: "upload",
              contentLength: body.bucketId === "two" ? 3 : 9,
            },
          ],
          nextFileName: null,
        };
      },
    };
  const options = {
    db,
    env: {
      STORAGE_CREDENTIAL_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    },
    demo: false,
    workspaceStorage: {
      view: async () => ({ kind: "dedicated", status: "ready" }),
    },
    maxFileBytes: 4194304,
    audit: async () => {},
    provider,
  };
  const first = await createMspConsole(options),
    partial = await first.refreshInventory();
  assert.equal(partial.status, "scanning");
  assert.equal(partial.snapshot, null);
  const stored = await db.one(
    "SELECT cursor FROM provider_inventory WHERE id='account'",
  );
  assert.ok(!stored.cursor.includes("sensitive-file-cursor"));
  assert.ok(!stored.cursor.includes("private-cursor-id"));
  const second = await createMspConsole(options),
    completed = await second.refreshInventory();
  assert.equal(completed.status, "complete");
  assert.equal(completed.snapshot.bytes, 24);
  assert.equal(completed.snapshot.versions, 4);
  assert.equal(completed.snapshot.buckets.length, 3);
  assert.ok(!JSON.stringify(completed).includes("sensitive-file-cursor"));
  const refreshed = await second.refreshInventory();
  assert.equal(refreshed.status, "scanning");
  assert.equal(refreshed.snapshot.bytes, 24);
  assert.ok(calls.every((method) => method.startsWith("b2_list_")));
});

test("native file-version requests omit accountId while account bucket requests retain it", async () => {
  const { BucketProvisioner } = await import("../server/workspace-storage.mjs");
  const calls = [];
  const provider = new BucketProvisioner({
    fetchImpl: async (url, options) => {
      const body = JSON.parse(options.body);
      calls.push(body);
      if (url.endsWith("b2_list_file_versions"))
        assert.equal(Object.hasOwn(body, "accountId"), false);
      return { ok: true, json: async () => ({ files: [], buckets: [] }) };
    },
  });
  const auth = {
    apiUrl: "https://api.example.test",
    accountId: "synthetic-account",
    token: "synthetic-token",
  };
  await provider.call(auth, "b2_list_file_versions", {
    bucketId: "synthetic-bucket",
    maxFileCount: 1000,
    startFileName: "cursor",
    startFileId: "version",
  });
  assert.equal(calls[0].startFileName, "cursor");
  assert.equal(calls[0].startFileId, "version");
  await provider.call(auth, "b2_list_buckets", {});
  assert.equal(calls[1].accountId, "synthetic-account");
});
