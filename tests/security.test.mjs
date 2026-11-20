import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import pg from "pg";
import { postgresDatabase, migratePostgres } from "../server/database.mjs";
import { createWorkspaceStorage } from "../server/workspace-storage.mjs";

const testPostgres = process.env.TEST_POSTGRES_URL;
const port = testPostgres ? 14174 : 14173,
  origin = `http://127.0.0.1:${port}`,
  dir = mkdtempSync(join(tmpdir(), "vault-tests-"));
let proc, admin, client;
async function request(path, method = "GET", body, session, extra = {}) {
  const r = await fetch(origin + path, {
    method,
    headers: {
      Origin: origin,
      ...(session
        ? { Cookie: session.cookie, "X-CSRF-Token": session.csrf }
        : {}),
      ...(body !== undefined
        ? {
            "Content-Type": Buffer.isBuffer(body)
              ? "application/octet-stream"
              : "application/json",
          }
        : {}),
      ...extra,
    },
    body:
      body === undefined
        ? undefined
        : Buffer.isBuffer(body)
          ? body
          : JSON.stringify(body),
  });
  const type = r.headers.get("content-type") || "";
  return {
    status: r.status,
    headers: r.headers,
    value: type.includes("application/json")
      ? await r.json()
      : await r.arrayBuffer(),
  };
}
async function sign(role) {
  const r = await request("/auth/demo", "POST", { role });
  return {
    cookie: r.headers.get("set-cookie").split(";")[0],
    csrf: r.value.csrf,
  };
}
async function startServer(listenPort = port) {
  const child = spawn(process.execPath, ["server/index.mjs"], {
    env: {
      ...process.env,
      DEMO_MODE: "true",
      NODE_ENV: "test",
      PORT: String(listenPort),
      APP_ORIGIN: `http://127.0.0.1:${listenPort}`,
      DATA_DIRECTORY: dir,
      ...(testPostgres
        ? {
            DATABASE_URL: testPostgres,
            METADATA_DRIVER: "postgres",
            TEST_DATABASE_LOCAL: "true",
          }
        : {}),
    },
    stdio: "pipe",
  });
  let output = "";
  child.stderr.on("data", (b) => (output += b));
  await new Promise((ok, bad) => {
    const timeout = setTimeout(
      () => bad(Error(output || "Startup timed out")),
      10000,
    );
    child.stdout.on("data", () => {
      clearTimeout(timeout);
      ok();
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      bad(Error(output + " exit " + code));
    });
  });
  return child;
}
before(async () => {
  if (testPostgres) {
    const u = new URL(testPostgres);
    assert.ok(
      ["127.0.0.1", "localhost"].includes(u.hostname) &&
        u.pathname === "/sv_test",
      "Postgres reset is restricted to the local synthetic sv_test database",
    );
    const reset = new pg.Pool({ connectionString: testPostgres, ssl: false });
    try {
      await reset.query("DROP SCHEMA IF EXISTS streamlined_vault CASCADE");
      // Simulate an existing v1 deployment before exercising normal startup.
      const upgrade = postgresDatabase(reset);
      await upgrade.exec("CREATE SCHEMA streamlined_vault");
      await upgrade.exec(
        "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,applied TEXT NOT NULL)",
      );
      await upgrade.exec(
        readFileSync(
          new URL("../server/migrations/001-metadata.sql", import.meta.url),
          "utf8",
        ),
      );
      await upgrade.run(
        "INSERT INTO schema_migrations VALUES(1,?)",
        new Date().toISOString(),
      );
      await upgrade.run(
        "INSERT INTO tenants(id,name,quota,status) VALUES('upgrade-fixture','Preserved workspace',4000000000000,'active')",
      );
      await migratePostgres(upgrade);
      const preserved = await upgrade.one(
        "SELECT * FROM tenants WHERE id='upgrade-fixture'",
      );
      assert.equal(preserved.name, "Preserved workspace");
      assert.equal(preserved.kind, "client");
      assert.equal(preserved.owner_email, null);
      assert.equal(
        (
          await upgrade.one(
            "SELECT MAX(version) AS version FROM schema_migrations",
          )
        ).version,
        2,
      );
      await migratePostgres(upgrade); // Repeat cold starts must leave data intact.
      await upgrade.run("DELETE FROM tenants WHERE id='upgrade-fixture'");
    } finally {
      await reset.end();
    }
  }
  proc = await startServer();
  admin = await sign("msp");
  client = await sign("client");
});
after(() => {
  proc?.kill();
  setTimeout(() => {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
  }, 500).unref();
});
test("anonymous API access fails; state changes require both origin and CSRF", async () => {
  assert.equal((await request("/api/me")).status, 401);
  assert.equal(
    (
      await request("/api/tenants", "POST", { name: "Denied" }, admin, {
        "X-CSRF-Token": "wrong",
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await request("/api/tenants", "POST", { name: "Denied" }, admin, {
        Origin: "https://elsewhere.test",
      })
    ).status,
    403,
  );
});
test("MSP provisioning does not grant other practices access", async () => {
  const created = await request(
    "/api/tenants",
    "POST",
    { name: "Isolation test" },
    admin,
  );
  assert.equal(created.status, 201);
  const t = created.value.id;
  assert.equal(
    (await request(`/api/tenants/${t}/files`, "GET", undefined, client)).status,
    403,
  );
  assert.equal(
    (await request("/api/tenants", "POST", { name: "Forbidden" }, client))
      .status,
    403,
  );
  const me = await request("/api/me", "GET", undefined, client);
  assert.ok(!me.value.tenants.some((x) => x.id === t));
});
test("multipart upload checks integrity and size, preserves bytes and supports trash restore", async () => {
  const base = "/api/tenants/northside";
  const bytes = Buffer.from("Synthetic imaging bytes. No patient data.");
  const start = await request(
    base + "/uploads",
    "POST",
    { name: "sample.dcm", folder: "Testing", size: bytes.length },
    client,
  );
  assert.equal(start.status, 201);
  const f = start.value.id;
  assert.equal(
    (await request(`${base}/uploads/${f}/complete`, "POST", {}, client)).status,
    409,
  );
  assert.equal(
    (
      await request(`${base}/uploads/${f}/parts/1`, "PUT", bytes, client, {
        "X-Content-SHA256": "0".repeat(64),
      })
    ).status,
    400,
  );
  const digest = createHash("sha256").update(bytes).digest("hex");
  assert.equal(
    (
      await request(`${base}/uploads/${f}/parts/1`, "PUT", bytes, client, {
        "X-Content-SHA256": digest,
      })
    ).status,
    200,
  );
  assert.equal(
    (await request(`${base}/uploads/${f}/complete`, "POST", {}, client)).status,
    200,
  );
  const download = await request(
    `${base}/files/${f}/download`,
    "GET",
    undefined,
    client,
  );
  assert.deepEqual(Buffer.from(download.value), bytes);
  assert.ok(
    !JSON.stringify([...download.headers])
      .toLowerCase()
      .includes("backblaze"),
  );
  const range = await request(
    `${base}/files/${f}/download`,
    "GET",
    undefined,
    client,
    { Range: "bytes=0-8" },
  );
  assert.equal(range.status, 206);
  assert.deepEqual(Buffer.from(range.value), bytes.subarray(0, 9));
  assert.equal(
    (
      await request(
        `/api/tenants/oakvalley/files/${f}/download`,
        "GET",
        undefined,
        client,
      )
    ).status,
    404,
  );
  assert.equal(
    (await request(`${base}/files/${f}`, "DELETE", {}, client)).status,
    200,
  );
  assert.equal(
    (await request(`${base}/files/${f}/download`, "GET", undefined, client))
      .status,
    404,
  );
  assert.equal(
    (await request(`${base}/files/${f}/restore`, "POST", {}, client)).status,
    200,
  );
  assert.equal(
    (await request(`${base}/files/${f}/download`, "GET", undefined, client))
      .status,
    200,
  );
});
test("server quota reserves concurrent uploads and cancellation releases reservation", async () => {
  const start = await request(
      "/api/tenants",
      "POST",
      { name: "Quota test" },
      admin,
    ),
    base = `/api/tenants/${start.value.id}`;
  // 23 reservations at 160,000 MiB fit in 4 TB; the 24th does not.
  let first;
  for (let i = 0; i < 23; i++) {
    const r = await request(
      base + "/uploads",
      "POST",
      { name: "reservation.bin", folder: "Test", size: 167772160000 },
      admin,
    );
    assert.equal(r.status, 201);
    first ??= r.value.id;
  }
  assert.equal(
    (
      await request(
        base + "/uploads",
        "POST",
        { name: "overflow.bin", folder: "Test", size: 167772160000 },
        admin,
      )
    ).status,
    409,
  );
  assert.equal(
    (await request(base + "/uploads/" + first, "DELETE", {}, admin)).status,
    200,
  );
  assert.equal(
    (
      await request(
        base + "/uploads",
        "POST",
        { name: "fits-again.bin", folder: "Test", size: 167772160000 },
        admin,
      )
    ).status,
    201,
  );
});
test("automation tokens are scoped, cannot administer, and revoke immediately", async () => {
  const base = "/api/tenants/northside";
  const r = await request(
    base + "/tokens",
    "POST",
    { label: "Test device", scope: "upload", days: 1 },
    client,
  );
  assert.equal(r.status, 201);
  const auth = { Authorization: "Bearer " + r.value.token };
  assert.equal(
    (await request(base + "/files", "GET", undefined, undefined, auth)).status,
    403,
  );
  assert.equal(
    (
      await request(
        "/api/tenants/oakvalley/uploads",
        "POST",
        { name: "x", folder: "x", size: 1 },
        undefined,
        auth,
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await request(
        base + "/members",
        "POST",
        { email: "x@example.test", role: "admin" },
        undefined,
        auth,
      )
    ).status,
    403,
  );
  const up = await request(
    base + "/uploads",
    "POST",
    { name: "agent.txt", folder: "Test", size: 1 },
    undefined,
    auth,
  );
  assert.equal(up.status, 201);
  await request(base + "/tokens/" + r.value.id, "DELETE", {}, client);
  assert.equal(
    (
      await request(
        `${base}/uploads/${up.value.id}`,
        "GET",
        undefined,
        undefined,
        auth,
      )
    ).status,
    401,
  );
  const listed = await request(base + "/tokens", "GET", undefined, client);
  assert.ok(!JSON.stringify(listed.value).includes(r.value.token));
});
test("upload initialization and completion retries do not duplicate data or quota", async () => {
  const base = "/api/tenants/northside",
    payload = {
      name: "idempotent.txt",
      folder: "Test",
      size: 1,
      requestId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    };
  const a = await request(base + "/uploads", "POST", payload, client),
    b = await request(base + "/uploads", "POST", payload, client);
  assert.equal(a.value.id, b.value.id);
  assert.equal(b.status, 200);
  assert.equal(
    (await request(base + "/uploads", "POST", { ...payload, size: 2 }, client))
      .status,
    409,
  );
  const content = Buffer.from("x");
  await request(
    `${base}/uploads/${a.value.id}/parts/1`,
    "PUT",
    content,
    client,
    { "X-Content-SHA256": createHash("sha256").update(content).digest("hex") },
  );
  assert.equal(
    (
      await request(
        `${base}/uploads/${a.value.id}/complete`,
        "POST",
        {},
        client,
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await request(
        `${base}/uploads/${a.value.id}/complete`,
        "POST",
        {},
        client,
      )
    ).status,
    200,
  );
  const list = await request(base + "/files", "GET", undefined, client);
  assert.equal(list.value.files.filter((f) => f.id === a.value.id).length, 1);
});
test("viewer membership permits listing but denies upload and membership changes", async () => {
  const t = await request(
      "/api/tenants",
      "POST",
      { name: "Viewer boundary" },
      admin,
    ),
    base = `/api/tenants/${t.value.id}`;
  await request(
    base + "/members",
    "POST",
    { email: "client@example.test", role: "viewer" },
    admin,
  );
  assert.equal(
    (await request(base + "/files", "GET", undefined, client)).status,
    200,
  );
  assert.equal(
    (
      await request(
        base + "/uploads",
        "POST",
        { name: "denied.txt", folder: "Test", size: 1 },
        client,
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await request(
        base + "/members",
        "POST",
        { email: "client@example.test", role: "admin" },
        client,
      )
    ).status,
    403,
  );
});
test("device enrollment is one-time, policy-bound, scoped and immediately revocable", async () => {
  const base = "/api/tenants/northside";
  const enrollment = await request(
    base + "/devices",
    "POST",
    {
      label: "Synthetic workstation",
      folder: "Imaging",
      schedule: { kind: "interval", minutes: 15 },
    },
    admin,
  );
  assert.equal(enrollment.status, 201);
  assert.equal(
    (
      await request(
        base + "/devices",
        "POST",
        {
          label: "Invalid schedule",
          folder: "Imaging",
          schedule: { kind: "interval", minutes: 1 },
        },
        admin,
      )
    ).status,
    400,
  );
  const device = enrollment.value.id;
  const [a, b] = await Promise.all([
    request("/api/device-enroll", "POST", { code: enrollment.value.code }),
    request("/api/device-enroll", "POST", { code: enrollment.value.code }),
  ]);
  assert.deepEqual([a.status, b.status].sort(), [201, 401]);
  const enrolled = a.status === 201 ? a.value : b.value,
    auth = { Authorization: "Bearer " + enrolled.token };
  assert.equal(enrolled.workspace, "northside");
  assert.equal(
    (await request(base + "/devices", "GET", undefined, undefined, auth))
      .status,
    403,
  );
  assert.equal(
    (
      await request(
        "/api/tenants/oakvalley/uploads",
        "POST",
        { name: "no.txt", folder: "Imaging", size: 1 },
        undefined,
        auth,
      )
    ).status,
    403,
  );
  const heartbeat = await request(
    "/api/device/heartbeat",
    "POST",
    { status: "idle", version: "0.3.0" },
    undefined,
    auth,
  );
  assert.equal(heartbeat.status, 200);
  assert.equal(heartbeat.value.policy.schedule.minutes, 15);
  await request(`${base}/devices/${device}/run`, "POST", {}, admin);
  const command = await request(
    "/api/device/heartbeat",
    "POST",
    { status: "idle", version: "0.3.0" },
    undefined,
    auth,
  );
  assert.equal(command.value.command, 1);
  const summary = {
    id: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
    status: "success",
    uploaded: 3,
    skipped: 2,
    failed: 0,
  };
  assert.equal(
    (await request("/api/device/runs", "POST", summary, undefined, auth))
      .status,
    200,
  );
  await request("/api/device/runs", "POST", summary, undefined, auth);
  const runs = await request(
    `${base}/devices/${device}/runs`,
    "GET",
    undefined,
    admin,
  );
  assert.equal(runs.value.length, 1);
  await request(`${base}/devices/${device}`, "PATCH", { paused: true }, admin);
  assert.equal(
    (
      await request(
        base + "/uploads",
        "POST",
        { name: "paused.txt", folder: "Imaging", size: 1 },
        undefined,
        auth,
      )
    ).status,
    423,
  );
  assert.equal(
    (
      await request(
        "/api/device/heartbeat",
        "POST",
        { status: "paused", version: "0.3.0" },
        undefined,
        auth,
      )
    ).status,
    200,
  );
  await request(
    `${base}/devices/${device}`,
    "PATCH",
    {
      paused: false,
      policy: {
        folder: "New destination",
        schedule: { kind: "daily", time: "20:00", days: [0, 1, 2, 3, 4] },
      },
    },
    admin,
  );
  const policy = await request(
    "/api/device/heartbeat",
    "POST",
    { status: "idle", version: "0.3.0" },
    undefined,
    auth,
  );
  assert.equal(policy.value.revision, 2);
  const list = await request(base + "/devices", "GET", undefined, admin);
  assert.ok(!JSON.stringify(list.value).includes(enrolled.token));
  assert.ok(!JSON.stringify(list.value).includes(enrollment.value.code));
  await request(`${base}/devices/${device}`, "DELETE", {}, admin);
  assert.equal(
    (
      await request(
        "/api/device/heartbeat",
        "POST",
        { status: "idle", version: "0.3.0" },
        undefined,
        auth,
      )
    ).status,
    401,
  );
  assert.equal(
    (
      await request("/api/device-enroll", "POST", {
        code: enrollment.value.code,
      })
    ).status,
    401,
  );
});
test("unredeemed enrollment can be renewed and old code stops working", async () => {
  const base = "/api/tenants/northside";
  const e = await request(
    base + "/devices",
    "POST",
    {
      label: "Renew enrollment",
      folder: "Files",
      schedule: { kind: "daily", time: "02:00", days: [0, 6] },
    },
    admin,
  );
  const renewed = await request(
    `${base}/devices/${e.value.id}/enrollment`,
    "POST",
    {},
    admin,
  );
  assert.equal(renewed.status, 201);
  assert.equal(
    (await request("/api/device-enroll", "POST", { code: e.value.code }))
      .status,
    401,
  );
  assert.equal(
    (await request("/api/device-enroll", "POST", { code: renewed.value.code }))
      .status,
    201,
  );
});
test("scheduled Python uploader transfers bytes, reports results and skips unchanged files on the next run", async () => {
  const base = "/api/tenants/northside";
  const created = await request(
    base + "/devices",
    "POST",
    {
      label: "End-to-end test",
      folder: "Scheduled images",
      schedule: { kind: "interval", minutes: 15 },
    },
    admin,
  );
  const enrolled = await request("/api/device-enroll", "POST", {
    code: created.value.code,
  });
  const device = enrolled.value;
  async function probe() {
    return await new Promise((ok, bad) => {
      const child = spawn(
        process.env.PYTHON || "python",
        ["agent/tests/integration_probe.py"],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      let stdout = "",
        stderr = "";
      child.stdout.on("data", (b) => (stdout += b));
      child.stderr.on("data", (b) => (stderr += b));
      child.on("error", bad);
      child.on("exit", (code) => {
        if (code) bad(Error("Uploader probe failed: " + stderr));
        else {
          try {
            ok(JSON.parse(stdout));
          } catch (e) {
            bad(e);
          }
        }
      });
      child.stdin.end(
        JSON.stringify({
          portal: origin,
          workspace: "northside",
          device: device.device,
          token: device.token,
          root: join(dir, "agent-probe"),
        }),
      );
    });
  }
  const first = await probe();
  assert.equal(first.status, "success");
  assert.equal(first.uploaded, 1);
  let files = (await request(base + "/files", "GET", undefined, admin)).value
    .files;
  const file = files.find((f) => f.name === "synthetic-study.txt");
  assert.ok(file);
  assert.equal(file.folder, "Scheduled images");
  const downloaded = await request(
    `${base}/files/${file.id}/download`,
    "GET",
    undefined,
    admin,
  );
  assert.equal(
    Buffer.from(downloaded.value).toString(),
    "Synthetic scheduled upload. No patient information.",
  );
  await request(`${base}/devices/${device.device}/run`, "POST", {}, admin);
  const second = await probe();
  assert.equal(second.uploaded, 0);
  assert.equal(second.skipped, 1);
  files = (await request(base + "/files", "GET", undefined, admin)).value.files;
  assert.equal(files.filter((f) => f.name === "synthetic-study.txt").length, 1);
  const history = await request(
    `${base}/devices/${device.device}/runs`,
    "GET",
    undefined,
    admin,
  );
  assert.equal(history.value.length, 2);
});

test("new workspace retries reuse a dedicated bucket and uploader credentials route into it", async () => {
  const requestId = "aaaaaaaa-1111-2222-3333-444444444444",
    payload = {
      name: "Dedicated storage pilot",
      storage: { mode: "create" },
      requestId,
    };
  const created = await request("/api/tenants", "POST", payload, admin);
  assert.equal(created.status, 201);
  assert.equal(created.value.storage.kind, "dedicated");
  const retry = await request("/api/tenants", "POST", payload, admin);
  assert.equal(retry.status, 200);
  assert.equal(retry.value.id, created.value.id);
  const base = `/api/tenants/${created.value.id}`;
  assert.equal(
    (
      await request(
        base + "/storage",
        "POST",
        { storage: { mode: "create" } },
        client,
      )
    ).status,
    403,
  );
  const token = await request(
    base + "/tokens",
    "POST",
    { label: "Dedicated uploader", scope: "upload" },
    admin,
  );
  const auth = { Authorization: "Bearer " + token.value.token };
  const bytes = Buffer.from("Synthetic dedicated bucket bytes"),
    started = await request(
      base + "/uploads",
      "POST",
      {
        name: "dedicated.txt",
        folder: "Imaging",
        size: bytes.length,
        storage_tenant: "northside",
      },
      undefined,
      auth,
    );
  assert.equal(started.status, 201);
  assert.equal(
    (
      await request(
        `${base}/uploads/${started.value.id}/parts/1`,
        "PUT",
        bytes,
        undefined,
        {
          ...auth,
          "X-Content-SHA256": createHash("sha256").update(bytes).digest("hex"),
        },
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await request(
        `${base}/uploads/${started.value.id}/complete`,
        "POST",
        {},
        undefined,
        auth,
      )
    ).status,
    200,
  );
  const downloaded = await request(
    `${base}/files/${started.value.id}/download`,
    "GET",
    undefined,
    admin,
  );
  assert.deepEqual(Buffer.from(downloaded.value), bytes);
  assert.equal(
    (
      await request(
        `/api/tenants/northside/files/${started.value.id}/download`,
        "GET",
        undefined,
        client,
      )
    ).status,
    404,
  );
  const duplicate = await request(
    "/api/tenants",
    "POST",
    {
      name: "Duplicate assignment",
      storage: { mode: "connect", bucket: created.value.storage.bucket },
    },
    admin,
  );
  assert.equal(duplicate.status, 409);
  await request(
    base + "/members",
    "POST",
    { email: "client@example.test", role: "viewer" },
    admin,
  );
  const me = await request("/api/me", "GET", undefined, client),
    practice = me.value.tenants.find((t) => t.id === created.value.id);
  assert.deepEqual(practice.storage, { kind: "dedicated", status: "ready" });
  assert.ok(!me.value.storageCapabilities);
});

test(
  "Postgres shares durable state across servers and serializes concurrent reservations and enrollment",
  { skip: !testPostgres },
  async () => {
    const secondPort = 14175,
      secondOrigin = `http://127.0.0.1:${secondPort}`,
      second = await startServer(secondPort);
    async function other(
      path,
      method = "GET",
      value,
      auth = admin,
      headers = {},
    ) {
      const response = await fetch(secondOrigin + path, {
        method,
        headers: {
          Origin: secondOrigin,
          ...(auth ? { Cookie: auth.cookie, "X-CSRF-Token": auth.csrf } : {}),
          "Content-Type": "application/json",
          ...headers,
        },
        ...(value === undefined ? {} : { body: JSON.stringify(value) }),
      });
      return { status: response.status, value: await response.json() };
    }
    try {
      const created = await request(
        "/api/tenants",
        "POST",
        { name: "Concurrent synthetic practice", storage: { mode: "create" } },
        admin,
      );
      assert.equal(created.status, 201);
      const tid = created.value.id,
        base = `/api/tenants/${tid}`;
      assert.ok(
        (await other("/api/me")).value.tenants.some(
          (t) => t.id === tid && t.storage.kind === "dedicated",
        ),
      );
      const reservations = await Promise.all(
        Array.from({ length: 32 }, (_, i) =>
          (i % 2 ? other : request)(
            base + "/uploads",
            "POST",
            { name: `parallel-${i}.bin`, folder: "Test", size: 167772160000 },
            admin,
          ),
        ),
      );
      assert.equal(reservations.filter((r) => r.status === 201).length, 23);
      assert.equal(reservations.filter((r) => r.status === 409).length, 9);
      assert.equal(
        (await other(base + "/files")).value.used,
        23 * 167772160000,
      );
      const enrolled = await request(
        base + "/devices",
        "POST",
        {
          label: "Concurrency workstation",
          folder: "Test",
          schedule: { kind: "interval", minutes: 15 },
        },
        admin,
      );
      assert.equal(enrolled.status, 201);
      const claims = await Promise.all([
        request("/api/device-enroll", "POST", { code: enrolled.value.code }),
        other(
          "/api/device-enroll",
          "POST",
          { code: enrolled.value.code },
          null,
        ),
      ]);
      assert.deepEqual(claims.map((x) => x.status).sort(), [201, 401]);
      await Promise.all(
        Array.from({ length: 12 }, (_, i) =>
          (i % 2 ? other : request)(
            base + `/devices/${enrolled.value.id}/run`,
            "POST",
            {},
            admin,
          ),
        ),
      );
      const device = claims.find((c) => c.status === 201).value;
      const beat = await request(
        "/api/device/heartbeat",
        "POST",
        { status: "idle", version: "test" },
        undefined,
        { Authorization: "Bearer " + device.token },
      );
      assert.equal(beat.value.command, 12);
      const exited = new Promise((resolve) => proc.once("exit", resolve));
      proc.kill();
      await exited;
      proc = await startServer();
      const persisted = await request("/api/me", "GET", undefined, admin);
      assert.equal(persisted.status, 200);
      assert.equal(
        persisted.value.tenants.find((t) => t.id === tid).storage.bucket,
        created.value.storage.bucket,
      );
      assert.equal(
        (await request(base + "/files", "GET", undefined, admin)).value.used,
        23 * 167772160000,
      );
      const pool = new pg.Pool({ connectionString: testPostgres, ssl: false });
      try {
        const db = postgresDatabase(pool),
          newTenant = "storage-lease-test";
        await db.run(
          "INSERT INTO tenants(id,name,quota,status) VALUES(?,?,?,?)",
          newTenant,
          "Encrypted synthetic storage",
          4_000_000_000_000,
          "active",
        );
        let release, started;
        const providerReady = new Promise((r) => (started = r)),
          providerBarrier = new Promise((r) => (release = r));
        const settings = {
          VERCEL: "1",
          STORAGE_CREDENTIAL_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString(
            "base64",
          ),
          STORAGE_PROVISIONING_KEY_ID: "synthetic",
          STORAGE_PROVISIONING_APPLICATION_KEY: "synthetic",
        };
        const provisioner = {
          create: async (t, e, onBucket) => {
            const result = {
              bucket: "sv-" + t.replaceAll("-", ""),
              bucketId: "bucket-synthetic",
              endpoint: "https://s3.us-west-004.backblazeb2.com",
              region: "us-west-004",
              keyId: "synthetic-bucket-key",
              applicationKey: "synthetic-bucket-secret",
            };
            await onBucket(result);
            started();
            await providerBarrier;
            return result;
          },
        };
        const cloudFactory = (e) => ({
          bucket: e.STORAGE_BUCKET,
          credential: e.STORAGE_APPLICATION_KEY,
        });
        const a = await createWorkspaceStorage({
            db,
            env: settings,
            demo: false,
            data: dir,
            provisioner,
            cloudFactory,
          }),
          b = await createWorkspaceStorage({
            db: postgresDatabase(pool),
            env: settings,
            demo: false,
            data: dir,
            provisioner,
            cloudFactory,
          });
        assert.equal(a.capabilities().metadataPending, false);
        const setup = a.provision(newTenant, { mode: "create" });
        await providerReady;
        await assert.rejects(
          b.provision(newTenant, { mode: "create" }),
          (e) => e.status === 409,
        );
        release();
        await setup;
        const profile = await db.one(
          "SELECT * FROM workspace_storage WHERE tenant=?",
          newTenant,
        );
        assert.ok(!profile.credential.includes("synthetic-bucket-secret"));
        assert.ok(!profile.credential.includes("synthetic-bucket-key"));
        const reopened = await createWorkspaceStorage({
          db: postgresDatabase(pool),
          env: settings,
          demo: false,
          data: dir,
          provisioner,
          cloudFactory,
        });
        assert.equal(
          (
            await reopened.forFile({
              tenant: newTenant,
              storage_tenant: newTenant,
            })
          ).credential,
          "synthetic-bucket-secret",
        );
        await assert.rejects(
          db.transaction(async () => {
            await db.run(
              "INSERT INTO tenants(id,name,quota,status) VALUES(?,?,?,?)",
              "rollback-synthetic",
              "Rollback",
              1,
              "active",
            );
            throw Error("rollback-marker");
          }),
          /rollback-marker/,
        );
        assert.equal(
          await db.one(
            "SELECT id FROM tenants WHERE id=?",
            "rollback-synthetic",
          ),
          undefined,
        );
        const rows = (
          await pool.query(
            "SELECT id,tenant,actor,action,resource,created,previous,digest FROM streamlined_vault.audit ORDER BY seq",
          )
        ).rows;
        let previous = "";
        for (const r of rows) {
          assert.equal(r.previous, previous);
          const a = {
            id: r.id,
            tenant: r.tenant,
            actor: r.actor,
            action: r.action,
            resource: r.resource,
            created: r.created,
            previous: r.previous,
          };
          assert.equal(
            r.digest,
            createHash("sha256").update(JSON.stringify(a)).digest("hex"),
          );
          previous = r.digest;
        }
      } finally {
        await pool.end();
      }
    } finally {
      second.kill();
    }
  },
);

test("MSP settings, private workspaces, aggregate usage and plan controls are protected", async () => {
  assert.equal(
    (await request("/api/msp/settings", "GET", undefined, client)).status,
    403,
  );
  assert.equal(
    (await request("/api/msp/overview", "GET", undefined, client)).status,
    403,
  );
  assert.equal(
    (await request("/api/msp/inventory", "POST", {}, client)).status,
    403,
  );
  const own = await request(
    "/api/tenants",
    "POST",
    {
      name: "Private MSP synthetic",
      kind: "internal",
      storage: { mode: "create" },
    },
    admin,
  );
  assert.equal(own.status, 201);
  const again = await request(
    "/api/tenants",
    "POST",
    {
      name: "Duplicate private attempt",
      kind: "internal",
      storage: { mode: "create" },
    },
    admin,
  );
  assert.equal(again.value.id, own.value.id);
  const privateBase = `/api/tenants/${own.value.id}`;
  assert.equal(
    (await request(privateBase + "/files", "GET", undefined, client)).status,
    403,
  );
  assert.equal(
    (
      await request(
        privateBase + "/members",
        "POST",
        { email: "client@example.test", role: "admin" },
        admin,
      )
    ).status,
    403,
  );
  const settings = await request("/api/msp/settings", "GET", undefined, admin);
  assert.equal(settings.value.internalWorkspace.id, own.value.id);
  const overview = await request("/api/msp/overview", "GET", undefined, admin);
  assert.ok(overview.value.internal.some((t) => t.id === own.value.id));
  assert.ok(!overview.value.clients.some((t) => t.id === own.value.id));
  const clientView = await request("/api/me", "GET", undefined, client);
  assert.ok(!clientView.value.tenants.some((t) => t.id === own.value.id));
  const policy = {
    published: false,
    downloadLimitBytes: 1000,
    downloadMode: "block",
    downloadOverageCentsPerGB: 2,
    storageUpgradeCentsPerTB: 1500,
    additionalServices: "Synthetic draft terms",
  };
  assert.equal(
    (await request("/api/msp/plan", "PATCH", policy, admin)).status,
    200,
  );
  let plan = await request(
    "/api/tenants/northside/plan",
    "GET",
    undefined,
    client,
  );
  assert.deepEqual(plan.value.policy, { published: false });
  assert.ok(!plan.value.draft);
  assert.equal(
    (
      await request(
        "/api/tenants/northside/plan",
        "PATCH",
        { ...policy, published: true },
        client,
      )
    ).status,
    403,
  );
  assert.equal(
    (
      await request(
        "/api/msp/plan",
        "PATCH",
        { ...policy, published: true },
        admin,
      )
    ).status,
    200,
  );
  plan = await request("/api/tenants/northside/plan", "GET", undefined, client);
  assert.equal(plan.value.policy.downloadLimitBytes, 1000);
  assert.equal(plan.value.billingAutomatic, false);
  const internalPlan = await request(
    privateBase + "/plan",
    "GET",
    undefined,
    admin,
  );
  assert.equal(internalPlan.value.policy.published, false);
  const inventory = await request("/api/msp/inventory", "POST", {}, admin);
  assert.equal(inventory.value.status, "complete");
  assert.equal(inventory.value.snapshot.synthetic, true);
});

test("published hard download limits reserve concurrent traffic; drafts do not invent charges", async () => {
  const created = await request(
      "/api/tenants",
      "POST",
      { name: "Metered synthetic practice", storage: { mode: "create" } },
      admin,
    ),
    base = `/api/tenants/${created.value.id}`;
  const content = Buffer.from("1234567890"),
    start = await request(
      base + "/uploads",
      "POST",
      { name: "meter.txt", folder: "Test", size: content.length },
      admin,
    ),
    fid = start.value.id;
  await request(`${base}/uploads/${fid}/parts/1`, "PUT", content, admin, {
    "X-Content-SHA256": createHash("sha256").update(content).digest("hex"),
  });
  await request(`${base}/uploads/${fid}/complete`, "POST", {}, admin);
  await request(
    base + "/plan",
    "PATCH",
    {
      published: true,
      downloadLimitBytes: 10,
      downloadMode: "block",
      downloadOverageCentsPerGB: null,
      storageUpgradeCentsPerTB: null,
      additionalServices: "By agreement",
    },
    admin,
  );
  const results = await Promise.all([
    request(`${base}/files/${fid}/download`, "GET", undefined, admin),
    request(`${base}/files/${fid}/download`, "GET", undefined, admin),
  ]);
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  const usage = await request(base + "/plan", "GET", undefined, admin);
  assert.equal(usage.value.meter.uploadedBytes, 10);
  assert.equal(
    usage.value.meter.downloadedBytes + usage.value.meter.reservedDownloadBytes,
    10,
  );
  const stats = await request("/api/msp/overview", "GET", undefined, admin);
  assert.ok(
    stats.value.clients.find((t) => t.id === created.value.id).meter
      .downloadedBytes <= 10,
  );
});
