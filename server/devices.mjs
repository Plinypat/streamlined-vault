import { randomBytes, randomUUID, createHash } from "node:crypto";
const hash = (s) => createHash("sha256").update(s).digest("hex");
export async function createDevices({
  db,
  one,
  q,
  run,
  audit,
  need,
  body,
  send,
  tenantAccess,
  now,
}) {
  if (db.kind !== "postgres")
    await db.exec(`CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,label TEXT NOT NULL,token TEXT,policy TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,command INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0,last_seen TEXT,status TEXT NOT NULL DEFAULT 'pending',version TEXT,last_success TEXT,created TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS enrollments(hash TEXT PRIMARY KEY,device TEXT NOT NULL,expires BIGINT NOT NULL,consumed INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS device_runs(id TEXT PRIMARY KEY,device TEXT NOT NULL,tenant TEXT NOT NULL,status TEXT NOT NULL,uploaded INTEGER NOT NULL,skipped INTEGER NOT NULL,failed INTEGER NOT NULL,created TEXT NOT NULL);`);
  function policy(b) {
    const p = b?.schedule;
    need(
      p && ["interval", "daily"].includes(p.kind),
      400,
      "Choose an interval or daily schedule",
    );
    if (p.kind === "interval")
      need([15, 60, 240].includes(p.minutes), 400, "Unsupported interval");
    else
      need(
        /^([01]\d|2[0-3]):[0-5]\d$/.test(p.time) &&
          Array.isArray(p.days) &&
          p.days.length > 0 &&
          p.days.length <= 7 &&
          new Set(p.days).size === p.days.length &&
          p.days.every((d) => Number.isInteger(d) && d >= 0 && d <= 6),
        400,
        "Choose a local time and days",
      );
    need(
      typeof b.folder === "string" &&
        b.folder.length > 0 &&
        b.folder.length <= 100 &&
        !/[\x00-\x1f]/.test(b.folder),
      400,
      "Choose a cloud folder",
    );
    return {
      schedule:
        p.kind === "interval"
          ? { kind: p.kind, minutes: p.minutes }
          : { kind: p.kind, time: p.time, days: p.days },
      folder: b.folder,
    };
  }
  const view = async (d) => ({
    id: d.id,
    label: d.label,
    enrolled: !!d.token,
    credential_expires: d.token
      ? (await one("SELECT expires FROM tokens WHERE id=?", d.token))?.expires
      : null,
    policy: JSON.parse(d.policy),
    revision: d.revision,
    paused: !!d.paused,
    revoked: !!d.revoked,
    last_seen: d.last_seen,
    status: d.status,
    version: d.version,
    last_success: d.last_success,
    created: d.created,
  });
  async function newEnrollment(device) {
    await run("DELETE FROM enrollments WHERE device=?", device);
    const code = "sv_enroll_" + randomBytes(24).toString("base64url"),
      expires = Date.now() + 900000;
    await run(
      "INSERT INTO enrollments VALUES(?,?,?,0)",
      hash(code),
      device,
      expires,
    );
    return { code, expires };
  }
  async function enroll(req, res) {
    const b = await body(req);
    need(
      typeof b.code === "string" && b.code.length < 200,
      400,
      "Enrollment credential required",
    );
    const result = await db.transaction(async () => {
      const codeHash = hash(b.code),
        initial = await one(
          "SELECT device FROM enrollments WHERE hash=?",
          codeHash,
        );
      need(initial, 401, "Enrollment is invalid or expired");
      await db.lock("device:" + initial.device);
      const e = await one(
        "SELECT * FROM enrollments WHERE hash=? AND consumed=0 AND expires>?",
        codeHash,
        Date.now(),
      );
      need(e, 401, "Enrollment is invalid or expired");
      const d = await one(
        "SELECT * FROM devices WHERE id=? AND revoked=0 AND token IS NULL",
        e.device,
      );
      need(d, 401, "Enrollment is no longer valid");
      const t = await one("SELECT status FROM tenants WHERE id=?", d.tenant);
      need(t?.status === "active", 423, "Workspace unavailable");
      const token = "sv_device_" + randomBytes(32).toString("base64url"),
        tid = randomUUID(),
        expires = Date.now() + 90 * 86400000;
      const claim = await run(
        "UPDATE enrollments SET consumed=1 WHERE hash=? AND consumed=0",
        codeHash,
      );
      need(claim.changes === 1, 401, "Enrollment is no longer valid");
      await run(
        "INSERT INTO tokens(id,tenant,label,hash,scope,expires) VALUES(?,?,?,?,?,?)",
        tid,
        d.tenant,
        d.label,
        hash(token),
        "upload",
        expires,
      );
      await run(
        "UPDATE devices SET token=?,status='idle' WHERE id=?",
        tid,
        d.id,
      );
      await audit(d.tenant, "device-enrollment", "Uploader enrolled", d.id);
      return {
        device: d.id,
        workspace: d.tenant,
        token,
        expires,
        policy: JSON.parse(d.policy),
        revision: d.revision,
      };
    });
    return send(res, 201, result);
  }
  async function agentDevice(user) {
    need(user.agent && user.device, 403, "Device credential required");
    const d = await one(
      "SELECT * FROM devices WHERE id=? AND token=? AND revoked=0",
      user.device,
      user.tokenId,
    );
    need(d, 401, "Device is revoked");
    const token = await one(
      "SELECT id FROM tokens WHERE id=? AND revoked=0 AND expires>?",
      user.tokenId,
      Date.now(),
    );
    need(token, 401, "Device is revoked");
    return d;
  }
  async function agent(req, res, user, tail) {
    const b = await body(req);
    const result = await db.transaction(async () => {
      await db.lock("device:" + user.device);
      const d = await agentDevice(user);
      await tenantAccess(user, d.tenant);
      if (tail === "/heartbeat" && req.method === "POST") {
        need(
          ["idle", "uploading", "paused", "error"].includes(b.status) &&
            typeof b.version === "string" &&
            /^[0-9a-zA-Z.+-]{1,30}$/.test(b.version),
          400,
          "Invalid device status",
        );
        await run(
          "UPDATE devices SET last_seen=?,status=?,version=? WHERE id=?",
          now(),
          b.status,
          b.version,
          d.id,
        );
        return {
          device: d.id,
          workspace: d.tenant,
          policy: JSON.parse(d.policy),
          revision: d.revision,
          command: d.command,
          paused: !!d.paused,
          credential_expires: (
            await one("SELECT expires FROM tokens WHERE id=?", d.token)
          ).expires,
        };
      }
      if (tail === "/runs" && req.method === "POST") {
        need(
          typeof b.id === "string" &&
            /^[a-f0-9-]{36}$/.test(b.id) &&
            ["success", "failed", "paused"].includes(b.status) &&
            ["uploaded", "skipped", "failed"].every(
              (k) =>
                Number.isSafeInteger(b[k]) && b[k] >= 0 && b[k] <= 10000000,
            ),
          400,
          "Invalid run summary",
        );
        await db.lock("device-run:" + b.id);
        const existing = await one(
          "SELECT device FROM device_runs WHERE id=?",
          b.id,
        );
        need(
          !existing || existing.device === d.id,
          409,
          "Run identifier already used",
        );
        if (!existing) {
          await run(
            "INSERT INTO device_runs VALUES(?,?,?,?,?,?,?,?)",
            b.id,
            d.id,
            d.tenant,
            b.status,
            b.uploaded,
            b.skipped,
            b.failed,
            now(),
          );
          if (b.status === "success")
            await run(
              "UPDATE devices SET last_success=? WHERE id=?",
              now(),
              d.id,
            );
          await audit(
            d.tenant,
            `device:${d.id}`,
            "Uploader run " + b.status,
            d.id,
          );
        }
        return { ok: true };
      }
      throw Object.assign(Error("Not found"), { status: 404 });
    });
    return send(res, 200, result);
  }
  async function portal(req, res, user, tenant, tail) {
    await tenantAccess(user, tenant, false, true);
    if (tail === "/devices" && req.method === "GET")
      return send(
        res,
        200,
        await Promise.all(
          (
            await q(
              "SELECT * FROM devices WHERE tenant=? ORDER BY created DESC",
              tenant,
            )
          ).map(view),
        ),
      );
    if (tail === "/devices" && req.method === "POST") {
      const b = await body(req);
      need(
        typeof b.label === "string" &&
          b.label.trim().length > 1 &&
          b.label.length <= 80 &&
          !/[\x00-\x1f]/.test(b.label),
        400,
        "Enter a device label",
      );
      const p = policy(b),
        did = randomUUID();
      const result = await db.transaction(async () => {
        await run(
          "INSERT INTO devices(id,tenant,label,policy,created) VALUES(?,?,?,?,?)",
          did,
          tenant,
          b.label.trim(),
          JSON.stringify(p),
          now(),
        );
        const e = await newEnrollment(did);
        await audit(tenant, user.email, "Uploader enrollment created", did);
        return { id: did, ...e };
      });
      return send(res, 201, result);
    }
    const m = /^\/devices\/([^/]+)(?:\/(enrollment|run|runs))?$/.exec(tail);
    need(m, 404, "Not found");
    const b = ["POST", "PATCH"].includes(req.method) ? await body(req) : {};
    const result = await db.transaction(async () => {
      await db.lock("device:" + m[1]);
      const d = await one(
        "SELECT * FROM devices WHERE id=? AND tenant=?",
        m[1],
        tenant,
      );
      need(d, 404, "Uploader not found");
      if (m[2] === "runs" && req.method === "GET")
        return await q(
          "SELECT id,status,uploaded,skipped,failed,created FROM device_runs WHERE device=? ORDER BY created DESC LIMIT 30",
          d.id,
        );
      need(!d.revoked, 409, "Uploader is revoked");
      if (m[2] === "enrollment" && req.method === "POST") {
        need(!d.token, 409, "Device is already enrolled");
        const e = await newEnrollment(d.id);
        await audit(tenant, user.email, "Uploader enrollment renewed", d.id);
        return e;
      }
      if (m[2] === "run" && req.method === "POST") {
        need(d.token && !d.paused, 409, "Enroll or resume this uploader first");
        await run("UPDATE devices SET command=command+1 WHERE id=?", d.id);
        await audit(tenant, user.email, "Uploader run requested", d.id);
        return { ok: true, message: "Queued for the next device contact" };
      }
      if (req.method === "PATCH" && !m[2]) {
        if (b.policy) {
          const p = policy(b.policy);
          await run(
            "UPDATE devices SET policy=?,revision=revision+1 WHERE id=?",
            JSON.stringify(p),
            d.id,
          );
        }
        if (b.paused !== undefined) {
          need(typeof b.paused === "boolean", 400);
          await run(
            "UPDATE devices SET paused=? WHERE id=?",
            b.paused ? 1 : 0,
            d.id,
          );
        }
        await audit(tenant, user.email, "Uploader settings updated", d.id);
        return { ok: true };
      }
      if (req.method === "DELETE" && !m[2]) {
        await run("UPDATE devices SET revoked=1 WHERE id=?", d.id);
        if (d.token)
          await run("UPDATE tokens SET revoked=1 WHERE id=?", d.token);
        await run("DELETE FROM enrollments WHERE device=?", d.id);
        await audit(tenant, user.email, "Uploader revoked", d.id);
        return { ok: true };
      }
      throw Object.assign(Error("Not found"), { status: 404 });
    });
    return send(
      res,
      m[2] === "enrollment" && req.method === "POST" ? 201 : 200,
      result,
    );
  }
  return { enroll, agent, portal };
}
