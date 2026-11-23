import { productionAuthorized } from "./activation.mjs";
import { createDirectTransfers } from "./direct-transfers.mjs";
import { AsyncLocalStorage } from "node:async_hooks";
import { createSecurityLog, routeClass } from "./security-log.mjs";
import { createSecurityConsole } from "./security-console.mjs";
import http from "node:http";
import { openDatabase } from "./database.mjs";
import {
  randomBytes,
  randomUUID,
  createHash,
  timingSafeEqual,
} from "node:crypto";
import { mkdirSync, readFileSync, existsSync } from "node:fs";
import { resolve, join, extname } from "node:path";
import { Transform } from "node:stream";
import { createMspConsole } from "./msp-console.mjs";
import { pipeline } from "node:stream/promises";
import {
  createWorkspaceStorage,
  BucketProvisioner,
} from "./workspace-storage.mjs";
import { createDevices } from "./devices.mjs";
import { createClerkAuth, contentSecurityPolicy } from "./clerk-auth.mjs";

const env = process.env,
  demo = env.DEMO_MODE === "true",
  production = env.NODE_ENV === "production";
env.CLERK_PUBLISHABLE_KEY =
  env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY || env.CLERK_PUBLISHABLE_KEY;
if (demo && production) throw Error("Demo mode is prohibited in production");
const origin = env.APP_ORIGIN || "http://127.0.0.1:4173",
  data = resolve(env.DATA_DIRECTORY || "data");
if (!demo) {
  for (const k of [
    "CLERK_PUBLISHABLE_KEY",
    "CLERK_SECRET_KEY",
    "MSP_ADMINS",
    "STORAGE_ENDPOINT",
    "STORAGE_REGION",
    "STORAGE_BUCKET",
    "STORAGE_KEY_ID",
    "STORAGE_APPLICATION_KEY",
  ])
    if (!env[k]) throw Error(`Missing server configuration: ${k}`);
  if (!origin.startsWith("https://")) throw Error("Live mode requires HTTPS");
}
let db;
try {
  db = await openDatabase({ env, demo, data });
} catch (e) {
  console.error(
    JSON.stringify({
      event: "metadata_startup_failed",
      code: /^[A-Z0-9_]+$/.test(e.code || "")
        ? e.code
        : "DATABASE_CONFIGURATION",
    }),
  );
  process.exit(1);
}
const q = (sql, ...args) => db.q(sql, ...args),
  one = (sql, ...args) => db.one(sql, ...args),
  run = (sql, ...args) => db.run(sql, ...args);
const hash = (v) => createHash("sha256").update(v).digest("hex"),
  now = () => new Date().toISOString(),
  id = () => randomUUID();
const msp = new Set(
  (env.MSP_ADMINS || "admin@example.test")
    .split(",")
    .map((v) => v.trim().toLowerCase()),
);
const securityLog = createSecurityLog({ db });
const requestContext = new AsyncLocalStorage();
const workspaceStorage = await createWorkspaceStorage({ db, env, demo, data });
// Read-only diagnostics: authorize/check capabilities only. Never creates resources.
if (
  !demo &&
  env.STORAGE_PROVISIONING_KEY_ID &&
  env.STORAGE_PROVISIONING_APPLICATION_KEY
) {
  try {
    await new BucketProvisioner({ timeoutMs: 5000 }).checkProvisioning(env);
    console.log(
      JSON.stringify({ event: "storage_provisioning_check", status: "ready" }),
    );
  } catch (e) {
    console.warn(
      JSON.stringify({
        event: "storage_provisioning_check",
        status: "failed",
        operation: e.providerOperation || "configuration",
        code: e.providerCode || "CONFIGURATION",
        field: e.field,
        message: e.message,
      }),
    );
  }
}
const ready = demo || productionAuthorized(env);
const PART = 16 * 1024 * 1024;
const MAX = 50 * 1024 ** 3;
const pilotTransfer = false;
async function audit(tenant, actor, action, resource = "") {
  return db.transaction(async () => {
    await db.lock("audit:chain");
    const previous =
      (await one("SELECT digest FROM audit ORDER BY rowid DESC LIMIT 1"))
        ?.digest || "";
    const a = {
      id: id(),
      tenant,
      actor,
      action,
      resource,
      created: now(),
      previous,
    };
    const digest = hash(JSON.stringify(a));
    await run(
      "INSERT INTO audit(id,tenant,actor,action,resource,created,previous,digest) VALUES(?,?,?,?,?,?,?,?)",
      a.id,
      tenant,
      actor,
      action,
      resource,
      a.created,
      previous,
      digest,
    );
  });
}
function publicFile(f) {
  return {
    id: f.id,
    name: f.name,
    folder: f.folder,
    size: f.size,
    status: f.status,
    created: f.created,
  };
}
function error(status, message) {
  return Object.assign(Error(message), { status });
}
function need(test, status = 403, message = "Access denied") {
  if (!test) throw error(status, message);
}
async function send(res, status, value) {
  const context = requestContext.getStore();
  if (context?.actor && status < 400 && !context.responded) {
    context.responded = true;
    await securityLog.event("request_completed", { ...context, status });
  }
  if (res.headersSent) return;
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(value));
}
async function body(req, limit = 65536, raw = false) {
  let size = 0,
    parts = [];
  for await (const b of req) {
    size += b.length;
    if (size > limit) throw error(413, "Request is too large");
    parts.push(b);
  }
  const b = Buffer.concat(parts);
  if (raw) return b;
  try {
    return JSON.parse(b.toString() || "{}");
  } catch {
    throw error(400, "Invalid JSON");
  }
}
async function session(req) {
  const token = /\bss_session=([^;]+)/.exec(req.headers.cookie || "")?.[1];
  if (!token) return null;
  const s = await one(
    "SELECT * FROM sessions WHERE hash=? AND expires>?",
    hash(token),
    Date.now(),
  );
  return s
    ? { ...JSON.parse(s.user), csrf: s.csrf, sessionHash: s.hash }
    : null;
}
async function login(res, user) {
  const token = randomBytes(32).toString("base64url"),
    csrf = randomBytes(24).toString("base64url");
  await run(
    "INSERT INTO sessions VALUES(?,?,?,?)",
    hash(token),
    JSON.stringify(user),
    Date.now() + 15 * 60 * 1000,
    csrf,
  );
  res.setHeader(
    "Set-Cookie",
    `ss_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=900${demo ? "" : "; Secure"}`,
  );
  return { ...user, csrf };
}
async function authenticate(req) {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ss_") || auth?.startsWith("Bearer sv_device_")) {
    const t = await one(
      "SELECT * FROM tokens WHERE hash=? AND revoked=0 AND expires>?",
      hash(auth.slice(7)),
      Date.now(),
    );
    need(t, 401, "Uploader credential invalid or expired");
    await run("UPDATE tokens SET last=? WHERE id=?", now(), t.id);
    const device = await one(
      "SELECT id FROM devices WHERE token=? AND revoked=0",
      t.id,
    );
    return {
      email: `agent:${t.id}`,
      agent: true,
      tenant: t.tenant,
      scope: t.scope,
      tokenId: t.id,
      device: device?.id,
    };
  }
  const cookie = await session(req);
  let user;
  if (demo) {
    need(cookie, 401, "Please sign in");
    user = cookie;
  } else {
    user = await clerkAuth.authenticate(req);
    need(
      cookie &&
        cookie.clerkId === user.clerkId &&
        cookie.clerkSessionId === user.clerkSessionId,
      401,
      "Please refresh your sign-in",
    );
    user = { ...user, csrf: cookie.csrf, sessionHash: cookie.sessionHash };
  }
  if (!["GET", "HEAD"].includes(req.method)) {
    need(
      req.headers["x-csrf-token"] === user.csrf,
      403,
      "Session verification failed",
    );
    need(req.headers.origin === origin, 403, "Request origin not allowed");
  }
  return user;
}
async function tenantAccess(user, tenant, write = false, admin = false) {
  const t = await one("SELECT * FROM tenants WHERE id=?", tenant);
  need(t, 404, "Workspace not found");
  if (requestContext.getStore()) requestContext.getStore().tenant = t.id;
  need(
    t.kind !== "internal" ||
      (user.msp && t.owner_email === user.email) ||
      (user.agent && user.tenant === tenant),
    403,
    "This is a private MSP workspace",
  );
  let role = user.agent
    ? user.tenant === tenant
      ? user.scope === "upload"
        ? "uploader"
        : "viewer"
      : null
    : user.msp
      ? "admin"
      : (
          await one(
            "SELECT role FROM members WHERE tenant=? AND email=?",
            tenant,
            user.email,
          )
        )?.role;
  need(role);
  need(t.status === "active" || user.msp, 423, "Workspace is suspended");
  if (write) {
    need(["admin", "editor", "uploader"].includes(role));
    if (user.device)
      need(
        !(await one("SELECT paused FROM devices WHERE id=?", user.device))
          ?.paused,
        423,
        "Uploader is paused",
      );
  }
  if (admin) need(role === "admin" && !user.agent);
  return { ...t, role };
}
async function accessible(user) {
  return user.msp
    ? await q(
        "SELECT * FROM tenants WHERE kind='client' OR (kind='internal' AND owner_email=?)",
        user.email,
      )
    : await q(
        "SELECT t.* FROM tenants t JOIN members m ON m.tenant=t.id WHERE m.email=? AND t.kind='client'",
        user.email,
      );
}
async function usage(tenant) {
  return Number(
    (
      await one(
        "SELECT COALESCE(SUM(size),0) total FROM files WHERE tenant=? AND status IN ('ready','uploading','finishing','canceling','trash')",
        tenant,
      )
    ).total,
  );
}
const clerkAuth = demo
  ? null
  : createClerkAuth({
      env,
      origin,
      resolveIdentity: ({ clerkId, email }) =>
        db.transaction(async () => {
          await db.lock("identity-email:" + email);
          await db.lock("identity-subject:" + clerkId);
          const identity = await one(
            "SELECT * FROM clerk_identities WHERE clerk_id=? OR email=?",
            clerkId,
            email,
          );
          need(
            !identity ||
              (identity.clerk_id === clerkId && identity.email === email),
            403,
            "Account binding changed; contact your administrator",
          );
          need(
            msp.has(email) ||
              (await one("SELECT email FROM members WHERE email=?", email)),
            403,
            "Ask your administrator for practice access",
          );
          if (!identity)
            await run(
              "INSERT INTO clerk_identities VALUES(?,?)",
              clerkId,
              email,
            );
          return { msp: msp.has(email) };
        }),
    });
if (demo && !(await one("SELECT id FROM tenants LIMIT 1"))) {
  for (const [n, i] of [
    ["Northside Medical", "northside"],
    ["Oak Valley Dental", "oakvalley"],
    ["Lakeside Imaging", "lakeside"],
  ]) {
    await run(
      "INSERT INTO tenants(id,name,quota,status) VALUES(?,?,?,?)",
      i,
      n,
      4_000_000_000_000,
      "active",
    );
    await run(
      "INSERT INTO members VALUES(?,?,?)",
      i,
      "client@example.test",
      "admin",
    );
    await audit(i, "system", "Workspace created");
  }
}
const devices = await createDevices({
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
});

const mspConsole = await createMspConsole({
  db,
  env,
  demo,
  workspaceStorage,
  maxFileBytes: MAX,
  audit,
});
const directTransfers = createDirectTransfers({
  db,
  workspaceStorage,
  mspConsole,
  partSize: PART,
  audit,
});
const security = createSecurityConsole({
  db,
  env,
  demo,
  data,
  log: securityLog,
  workspaceStorage,
  audit,
});
const limits = new Map();
const server = http.createServer((req, res) =>
  requestContext.run(
    { requestId: id(), method: req.method, route: "other" },
    async () => {
      const context = requestContext.getStore();
      res.setHeader("X-Request-ID", context.requestId);
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Referrer-Policy", "no-referrer");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader(
        "Content-Security-Policy",
        contentSecurityPolicy(clerkAuth?.config.frontendApi, !demo),
      );
      if (!demo)
        res.setHeader(
          "Strict-Transport-Security",
          "max-age=31536000; includeSubDomains",
        );
      try {
        const url = new URL(req.url, origin),
          path = url.pathname,
          method = req.method;
        context.route = routeClass(path);
        const ip = req.socket.remoteAddress;
        const l = limits.get(ip) || { n: 0, until: Date.now() + 60000 };
        if (l.until < Date.now()) {
          l.n = 0;
          l.until = Date.now() + 60000;
        }
        l.n++;
        limits.set(ip, l);
        need(l.n < 1800, 429, "Too many requests; retry shortly");
        if (
          [
            "/internal/metadata-backup",
            "/internal/security-maintenance",
            "/internal/security-status",
            "/internal/security-archive-connect",
          ].includes(path)
        ) {
          const expected = env.CRON_SECRET;
          need(
            typeof expected === "string" &&
              expected.length >= 32 &&
              typeof req.headers.authorization === "string" &&
              Buffer.byteLength(req.headers.authorization) ===
                Buffer.byteLength("Bearer " + expected) &&
              timingSafeEqual(
                Buffer.from(req.headers.authorization),
                Buffer.from("Bearer " + expected),
              ),
            401,
            "Maintenance authorization required",
          );
          context.maintenanceAuthenticated = true;
          if (path === "/internal/security-status" && method === "GET") {
            const state = await security.status();
            return send(res, 200, {
              backups: state.backups,
              notifications: state.notifications,
              technicalApproval: state.technicalApproval,
              gates: state.gates,
              activation: state.activation,
              archive: state.archive,
              maintenance: state.maintenance,
              checks: state.checks.slice(0, 12),
              openAlerts: state.alerts
                .filter((a) => a.status === "open")
                .map((a) => a.code),
              environment: await security.archive.environment(),
            });
          }
          if (
            path === "/internal/security-archive-connect" &&
            method === "POST"
          ) {
            const value = await security.archive.connect(await body(req));
            await audit(
              "msp",
              "security-maintenance",
              "Approved protected audit archive connected",
            );
            return send(res, 200, value);
          }
          if (path === "/internal/metadata-backup" && method === "GET")
            return send(
              res,
              200,
              await security.backups.run({
                scheduled:
                  req.headers["x-vercel-cron-schedule"] === "7 * * * *" &&
                  String(req.headers["user-agent"] || "").startsWith(
                    "vercel-cron/",
                  ),
              }),
            );
          need(
            path === "/internal/security-maintenance" && method === "GET",
            405,
            "Maintenance method not allowed",
          );
          const scheduled =
            req.headers["x-vercel-cron-schedule"] === "*/15 * * * *" &&
            String(req.headers["user-agent"] || "").startsWith("vercel-cron/");
          const result = await security.maintenance(
            scheduled ? "security-maintenance" : "security-endpoint-check",
          );
          console.info(
            JSON.stringify({
              event: "security_maintenance_completed",
              scheduled,
              archivedBatches: result.archivedBatches || 0,
              requestId: context.requestId,
              at: now(),
            }),
          );
          return send(res, 200, result);
        }
        if (path === "/api/config")
          return send(res, 200, {
            demo,
            ready,
            activation: { productionAuthorized: !demo && ready },
            brand: "Streamlined Vault",
            partSize: PART,
            transferLimits: {
              maxFileBytes: MAX,
              pilot: pilotTransfer,
              direct: !demo,
              linkExpirySeconds: 60,
            },
            auth: demo ? "demo" : "clerk",
            ...(clerkAuth
              ? {
                  clerk: {
                    publishableKey: clerkAuth.config.publishableKey,
                    frontendApi: clerkAuth.config.frontendApi,
                  },
                }
              : {}),
          });
        if (path === "/health") {
          await one("SELECT 1 AS ok");
          return send(res, 200, { ok: true, metadata: db.kind });
        }
        if (path === "/api/device-enroll" && method === "POST")
          return await devices.enroll(req, res);
        if (path === "/auth/demo" && method === "POST") {
          need(demo, 404);
          need(req.headers.origin === origin);
          const b = await body(req);
          return send(
            res,
            200,
            await login(res, {
              email:
                b.role === "msp" ? "admin@example.test" : "client@example.test",
              name:
                b.role === "msp"
                  ? "MSP Administrator"
                  : "Practice Administrator",
              msp: b.role === "msp",
            }),
          );
        }
        if (path === "/auth/complete" && method === "POST") {
          need(!demo, 404);
          need(
            req.headers.origin === origin,
            403,
            "Request origin not allowed",
          );
          const identity = await clerkAuth.authenticate(req);
          context.actor = identity.email;
          await securityLog.event("sign_in", context);
          await audit("msp", identity.email, "Sign-in completed");
          return send(res, 200, await login(res, identity));
        }
        if (path.startsWith("/api/")) {
          const user = await authenticate(req);
          context.actor = user.email;
          await securityLog.event("request_authenticated", context);
          if (path.startsWith("/api/msp/security")) {
            need(user.msp);
            if (path === "/api/msp/security" && method === "GET")
              return send(res, 200, await security.status());
            if (path === "/api/msp/security/backup" && method === "POST") {
              await audit(
                "msp",
                user.email,
                "Manual metadata backup requested",
              );
              return send(res, 200, await security.backups.run());
            }
            if (path === "/api/msp/security/evidence" && method === "POST")
              return send(
                res,
                200,
                await security.recordEvidence(user.email, await body(req)),
              );
            if (
              path === "/api/msp/security/test-notification" &&
              method === "POST"
            ) {
              await run(
                "UPDATE security_alerts SET status='resolved' WHERE code='notification_test'",
              );
              await securityLog.alert("notification_test", "info");
              await audit("msp", user.email, "Notification test requested");
              return send(res, 200, await security.notifications.drain());
            }
            if (path === "/api/msp/security/maintenance" && method === "POST")
              return send(res, 200, await security.maintenance(user.email));
            if (
              path === "/api/msp/security/storage-check" &&
              method === "POST"
            ) {
              const b = await body(req);
              await tenantAccess(user, b.tenant);
              return send(
                res,
                200,
                await security.storageCheck(b.tenant, user.email),
              );
            }
            if (
              path === "/api/msp/security/access-review" &&
              method === "POST"
            ) {
              await security.accessReview(user.email);
              return send(res, 200, { ok: true });
            }
            if (path === "/api/msp/security/access" && method === "GET")
              return send(res, 200, {
                administrators: [...msp],
                members: await q(
                  "SELECT tenant,email,role FROM members ORDER BY tenant,email",
                ),
              });
            if (
              path === "/api/msp/security/resolve-alert" &&
              method === "POST"
            ) {
              const b = await body(req);
              await security.resolveAlert(user.email, b);
              return send(res, 200, { ok: true });
            }
            if (path === "/api/msp/security/acknowledge" && method === "POST") {
              const b = await body(req);
              need(typeof b.id === "string" && b.id.length <= 100, 400);
              await security.acknowledge(b.id, user.email);
              return send(res, 200, { ok: true });
            }
            throw error(404, "Security operation not found");
          }
          if (path.startsWith("/api/device/"))
            return await devices.agent(
              req,
              res,
              user,
              path.slice("/api/device".length),
            );
          if (path === "/api/me") {
            const tenants = await Promise.all(
              (await accessible(user)).map(async (t) => ({
                ...t,
                storage: await workspaceStorage.view(t.id, user.msp),
                browserTransfers: user.msp
                  ? await security.browserStatus(t.id)
                  : undefined,
                plan: await mspConsole.plan(t.id),
                used: await usage(t.id),
                role: user.msp
                  ? "admin"
                  : (
                      await one(
                        "SELECT role FROM members WHERE tenant=? AND email=?",
                        t.id,
                        user.email,
                      )
                    )?.role,
              })),
            );
            return send(res, 200, {
              ...user,
              ...(user.msp
                ? { activation: await security.activationStatus() }
                : {}),
              ...(user.msp
                ? { storageCapabilities: workspaceStorage.capabilities() }
                : {}),
              tenants,
            });
          }
          if (path === "/api/logout" && method === "POST") {
            await securityLog.event("sign_out", context);
            await audit("msp", user.email, "Sign-out requested");
            if (!demo) await clerkAuth.revoke(user.clerkSessionId);
            await run(
              "DELETE FROM sessions WHERE hash=?",
              user.sessionHash || "",
            );
            res.setHeader(
              "Set-Cookie",
              `ss_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${demo ? "" : "; Secure"}`,
            );
            return send(res, 200, { ok: true });
          }
          if (path.startsWith("/api/msp/")) {
            need(user.msp);
            if (path === "/api/msp/overview" && method === "GET")
              return send(res, 200, await mspConsole.overview(user));
            if (path === "/api/msp/settings" && method === "GET")
              return send(res, 200, {
                email: user.email,
                internalWorkspace: await one(
                  "SELECT id,name,status FROM tenants WHERE kind='internal' AND owner_email=?",
                  user.email,
                ),
                policy: await mspConsole.settings(),
                storageCapabilities: workspaceStorage.capabilities(),
              });
            if (path === "/api/msp/plan" && method === "PATCH")
              return send(
                res,
                200,
                await mspConsole.savePlan(null, await body(req), user.email),
              );
            if (path === "/api/msp/inventory" && method === "POST")
              return send(res, 200, await mspConsole.refreshInventory());
            throw error(404, "Not found");
          }
          if (path === "/api/tenants" && method === "POST") {
            need(user.msp);
            const b = await body(req);
            need(
              typeof b.name === "string" &&
                b.name.trim().length > 1 &&
                b.name.length <= 100,
              400,
              "Practice name is required",
            );
            need(
              !b.requestId || /^[a-f0-9-]{36}$/.test(b.requestId),
              400,
              "Invalid setup request identifier",
            );
            const kind = b.kind || "client";
            need(
              ["client", "internal"].includes(kind),
              400,
              "Invalid workspace type",
            );
            const tenant = await db.transaction(async () => {
              if (kind === "internal") {
                await db.lock("internal-owner:" + user.email);
                const own = await one(
                  "SELECT id FROM tenants WHERE kind='internal' AND owner_email=?",
                  user.email,
                );
                if (own) return own.id;
              }
              if (b.requestId) await db.lock("setup:" + b.requestId);
              const prior = b.requestId
                ? await one(
                    "SELECT * FROM storage_requests WHERE request_id=?",
                    b.requestId,
                  )
                : null;
              need(
                !prior || prior.name === b.name.trim(),
                409,
                "Setup request is already assigned to a different practice",
              );
              if (prior) {
                const assigned = await one(
                  "SELECT kind,owner_email FROM tenants WHERE id=?",
                  prior.tenant,
                );
                need(
                  assigned.kind === kind &&
                    (kind !== "internal" ||
                      assigned.owner_email === user.email),
                  409,
                  "Setup request is assigned to another workspace type",
                );
                return prior.tenant;
              }
              const tid = id();
              workspaceStorage.input(b.storage, tid);
              await run(
                "INSERT INTO tenants(id,name,quota,status) VALUES(?,?,?,?)",
                tid,
                b.name.trim(),
                4_000_000_000_000,
                "storage_pending",
              );
              await run(
                "UPDATE tenants SET kind=?,owner_email=? WHERE id=?",
                kind,
                kind === "internal" ? user.email : null,
                tid,
              );
              if (b.requestId)
                await run(
                  "INSERT INTO storage_requests VALUES(?,?,?)",
                  b.requestId,
                  tid,
                  b.name.trim(),
                );
              await audit(tid, user.email, "Workspace storage setup started");
              return tid;
            });
            const current = await workspaceStorage.view(tenant, true);
            if (current.kind === "dedicated" && current.status === "ready") {
              await run(
                "UPDATE tenants SET status='active' WHERE id=? AND status IN ('storage_pending','storage_error')",
                tenant,
              );
              return send(res, 200, { id: tenant, storage: current });
            }
            try {
              const storage = await workspaceStorage.provision(
                tenant,
                b.storage,
              );
              await run(
                "UPDATE tenants SET status='active' WHERE id=?",
                tenant,
              );
              await audit(
                tenant,
                user.email,
                "Dedicated workspace storage connected",
              );
              return send(res, 201, { id: tenant, storage });
            } catch (e) {
              if (e.status !== 409)
                await run(
                  "UPDATE tenants SET status='storage_error' WHERE id=? AND status<>'active'",
                  tenant,
                );
              await audit(
                tenant,
                user.email,
                "Workspace storage setup needs attention",
              );
              throw e;
            }
          }
          const route = /^\/api\/tenants\/([^/]+)(.*)$/.exec(path);
          need(route, 404, "Not found");
          const tenant = route[1],
            tail = route[2];
          const t = await tenantAccess(user, tenant);
          context.tenant = tenant;
          if (tail === "/plan" && method === "GET")
            return send(res, 200, {
              ...(await mspConsole.plan(tenant)),
              ...(user.msp ? { draft: await mspConsole.policy(tenant) } : {}),
            });
          if (tail === "/plan" && method === "PATCH") {
            need(user.msp);
            return send(
              res,
              200,
              await mspConsole.savePlan(tenant, await body(req), user.email),
            );
          }
          if (tail === "/devices" || tail.startsWith("/devices/"))
            return await devices.portal(req, res, user, tenant, tail);
          if (tail === "/storage" && method === "POST") {
            need(user.msp);
            const b = await body(req);
            const storage = await workspaceStorage.provision(tenant, b.storage);
            if (["storage_pending", "storage_error"].includes(t.status))
              await run(
                "UPDATE tenants SET status='active' WHERE id=?",
                tenant,
              );
            await audit(
              tenant,
              user.email,
              "Dedicated workspace storage connected",
            );
            return send(res, 200, storage);
          }
          if (tail === "/storage/browser-transfers" && method === "POST") {
            need(user.msp);
            await workspaceStorage.prepareBrowser(tenant);
            await security.recordBrowser(tenant);
            await audit(
              tenant,
              user.email,
              "Browser transfer origin configured",
            );
            return send(res, 200, { ok: true });
          }
          if (tail === "/settings" && method === "PATCH") {
            need(user.msp);
            need(
              (await workspaceStorage.view(tenant)).status === "ready",
              409,
              "Complete storage setup first",
            );
            const b = await body(req);
            need(["active", "suspended"].includes(b.status), 400);
            await run(
              "UPDATE tenants SET status=? WHERE id=?",
              b.status,
              tenant,
            );
            await audit(
              tenant,
              user.email,
              "Workspace status changed",
              b.status,
            );
            return send(res, 200, { ok: true });
          }
          if (tail === "/files" && method === "GET") {
            need(t.role !== "uploader");
            return send(res, 200, {
              files: (
                await q(
                  "SELECT * FROM files WHERE tenant=? AND status=? ORDER BY created DESC",
                  tenant,
                  url.searchParams.get("trash") === "true" ? "trash" : "ready",
                )
              ).map(publicFile),
              used: await usage(tenant),
              quota: t.quota,
            });
          }
          if (tail === "/members" && method === "GET") {
            await tenantAccess(user, tenant, false, true);
            return send(
              res,
              200,
              await q("SELECT email,role FROM members WHERE tenant=?", tenant),
            );
          }
          if (tail === "/members" && method === "POST") {
            need(
              t.kind !== "internal",
              403,
              "Private MSP workspaces cannot be shared with practice members",
            );
            await tenantAccess(user, tenant, false, true);
            const b = await body(req);
            need(
              /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email || "") &&
                ["admin", "editor", "viewer", "uploader"].includes(b.role),
              400,
              "Valid email and role required",
            );
            await run(
              "INSERT INTO members VALUES(?,?,?) ON CONFLICT(tenant,email) DO UPDATE SET role=excluded.role",
              tenant,
              b.email.toLowerCase(),
              b.role,
            );
            await audit(
              tenant,
              user.email,
              "Member access assigned",
              hash(b.email.toLowerCase()) + ":" + b.role,
            );
            return send(res, 200, { ok: true });
          }
          if (tail === "/members" && method === "DELETE") {
            await tenantAccess(user, tenant, false, true);
            const b = await body(req);
            need(
              b.email !== user.email,
              400,
              "Use another administrator to remove your own access",
            );
            need(
              await one(
                "SELECT email FROM members WHERE tenant=? AND email=?",
                tenant,
                b.email,
              ),
              404,
            );
            await run(
              "DELETE FROM members WHERE tenant=? AND email=?",
              tenant,
              b.email,
            );
            await audit(
              tenant,
              user.email,
              "Member access removed",
              hash(b.email.toLowerCase()),
            );
            return send(res, 200, { ok: true });
          }
          if (tail === "/audit" && method === "GET") {
            need(["admin", "editor", "viewer"].includes(t.role));
            const events = await q(
              "SELECT id,actor,action,resource,created FROM audit WHERE tenant=? ORDER BY rowid DESC LIMIT 500",
              tenant,
            );
            if (url.searchParams.has("export")) {
              await audit(tenant, user.email, "Activity export requested");
              res.writeHead(200, {
                "Content-Type": "application/json",
                "Content-Disposition": 'attachment; filename="activity.json"',
              });
              return res.end(JSON.stringify(events, null, 2));
            }
            return send(res, 200, events);
          }
          if (tail === "/notices")
            return send(
              res,
              200,
              await q(
                "SELECT * FROM notices WHERE tenant=? ORDER BY created DESC LIMIT 30",
                tenant,
              ),
            );
          if (tail === "/tokens" && method === "GET") {
            await tenantAccess(user, tenant, false, true);
            return send(
              res,
              200,
              await q(
                "SELECT id,label,scope,expires,revoked,last FROM tokens WHERE tenant=?",
                tenant,
              ),
            );
          }
          if (tail === "/tokens" && method === "POST") {
            await tenantAccess(user, tenant, false, true);
            const b = await body(req);
            need(
              ["upload", "read"].includes(b.scope) &&
                typeof b.label === "string" &&
                b.label.length > 0 &&
                b.label.length < 80,
              400,
              "Label and scope required",
            );
            const token = "ss_" + randomBytes(32).toString("base64url"),
              tid = id(),
              expires =
                Date.now() +
                Math.min(Math.max(Number(b.days) || 30, 1), 90) * 86400000;
            await run(
              "INSERT INTO tokens(id,tenant,label,hash,scope,expires) VALUES(?,?,?,?,?,?)",
              tid,
              tenant,
              b.label,
              hash(token),
              b.scope,
              expires,
            );
            await audit(
              tenant,
              user.email,
              "Automation credential created",
              tid,
            );
            return send(res, 201, { id: tid, token, expires });
          }
          if (/^\/tokens\/[^/]+$/.test(tail) && method === "DELETE") {
            await tenantAccess(user, tenant, false, true);
            await run(
              "UPDATE tokens SET revoked=1 WHERE id=? AND tenant=?",
              tail.split("/")[2],
              tenant,
            );
            await audit(
              tenant,
              user.email,
              "Automation credential revoked",
              tail.split("/")[2],
            );
            return send(res, 200, { ok: true });
          }
          if (tail === "/uploads" && method === "POST") {
            need(
              !(await security.recoveryPending()),
              503,
              "Recovery review is required before file transfers",
            );
            await tenantAccess(user, tenant, true);
            need(
              ready,
              503,
              "Storage activation requires completed operator review",
            );
            const b = await body(req);
            need(
              typeof b.name === "string" &&
                b.name.length > 0 &&
                b.name.length <= 200 &&
                !/[\x00-\x1f/\\]/.test(b.name),
              400,
              "Invalid file name",
            );
            need(
              typeof b.folder === "string" &&
                b.folder.length <= 200 &&
                !/[\x00-\x1f]/.test(b.folder),
              400,
              "Invalid folder",
            );
            need(
              Number.isSafeInteger(b.size) && b.size > 0 && b.size <= MAX,
              400,
              "File exceeds the current upload size limit shown in your plan",
            );
            need(
              !b.requestId || /^[a-f0-9-]{36}$/.test(b.requestId),
              400,
              "Invalid request identifier",
            );
            const fid = id(),
              key = `tenants/${tenant}/objects/${fid}`,
              storageTenant = await workspaceStorage.location(tenant),
              storage = await workspaceStorage.forFile({
                tenant,
                storage_tenant: storageTenant,
              });
            if (b.browser && storage.transport === "direct")
              await workspaceStorage.prepareBrowser(tenant);
            const previous = await db.transaction(async () => {
              await db.lock("tenant:" + tenant);
              if (b.requestId) {
                const p = await one(
                  "SELECT * FROM files WHERE tenant=? AND requestid=?",
                  tenant,
                  b.requestId,
                );
                if (p) {
                  need(
                    p.name === b.name &&
                      p.size === b.size &&
                      p.folder === b.folder,
                    409,
                    "Request identifier already used",
                  );
                  need(
                    p.upload,
                    409,
                    "Upload is still preparing; retry shortly",
                  );
                  return p;
                }
              }
              need(
                (await workspaceStorage.location(tenant)) === storageTenant,
                409,
                "Storage assignment changed; retry upload",
              );
              need(
                (await usage(tenant)) + b.size <= t.quota,
                409,
                "Workspace storage allowance exceeded",
              );
              await run(
                "INSERT INTO files(id,tenant,name,folder,size,key,status,created,requestid,storage_tenant) VALUES(?,?,?,?,?,?,?,?,?,?)",
                fid,
                tenant,
                b.name,
                b.folder,
                b.size,
                key,
                "uploading",
                now(),
                b.requestId || null,
                storageTenant,
              );
              return null;
            });
            if (previous)
              return send(res, 200, {
                id: previous.id,
                transport: storage.transport || "proxy",
                partSize: PART,
                parts: Math.ceil(previous.size / PART),
              });
            try {
              const upload = await storage.start(key);
              await run("UPDATE files SET upload=? WHERE id=?", upload, fid);
            } catch (e) {
              await run("DELETE FROM files WHERE id=?", fid);
              throw e;
            }
            await audit(tenant, user.email, "Upload started", fid);
            return send(res, 201, {
              id: fid,
              transport: storage.transport || "proxy",
              partSize: PART,
              parts: Math.ceil(b.size / PART),
            });
          }
          const directPart =
            /^\/uploads\/([^/]+)\/parts\/(\d+)\/(sign|ack)$/.exec(tail);
          if (directPart && method === "POST") {
            await tenantAccess(user, tenant, true);
            need(ready, 503, "Storage not activated");
            const input = await body(req);
            const value = await db.transaction(async () => {
              await db.lock("file:" + directPart[1]);
              await tenantAccess(user, tenant, true);
              const file = await one(
                "SELECT * FROM files WHERE id=? AND tenant=?",
                directPart[1],
                tenant,
              );
              need(file, 404, "Upload not found");
              return await directTransfers.part(
                file,
                Number(directPart[2]),
                directPart[3],
                input,
              );
            });
            return send(res, 200, value);
          }
          const ur =
            /^\/uploads\/([^/]+)(?:\/(parts)(?:\/(\d+))?|\/(complete))?$/.exec(
              tail,
            );
          if (ur) {
            await tenantAccess(user, tenant, true);
            need(ready, 503, "Storage not activated");
            const content =
              method === "PUT" && ur[2] ? await body(req, PART, true) : null;
            if (content) await mspConsole.recordUpload(tenant, content.length);
            if (content) {
              const checksum = req.headers["x-content-sha256"];
              need(
                typeof checksum === "string" &&
                  /^[a-f0-9]{64}$/.test(checksum) &&
                  hash(content) === checksum,
                400,
                "Transfer checksum mismatch",
              );
            }
            const result = await db.transaction(async () => {
              await db.lock("file:" + ur[1]);
              await tenantAccess(user, tenant, true);
              const f = await one(
                "SELECT * FROM files WHERE id=? AND tenant=?",
                ur[1],
                tenant,
              );
              need(f, 404, "Upload not found");
              if (method === "GET")
                return {
                  value: {
                    id: f.id,
                    name: f.name,
                    size: f.size,
                    status: f.status,
                    transport:
                      (await workspaceStorage.forFile(f)).transport || "proxy",
                    partSize: PART,
                    parts: await q(
                      "SELECT number,size FROM parts WHERE file=?",
                      f.id,
                    ),
                  },
                };
              if (method === "POST" && ur[4] && f.status === "ready")
                return { value: publicFile(f) };
              if (method === "PUT" && ur[2]) {
                need(f.status === "uploading", 409, "Upload is completing");
                const n = Number(ur[3]),
                  count = Math.ceil(f.size / PART);
                need(n >= 1 && n <= count, 400, "Invalid part number");
                const expected = n === count ? f.size - (n - 1) * PART : PART;
                need(content.length === expected, 400, "Part length mismatch");
                const storage = await workspaceStorage.forFile(f),
                  etag = await storage.part(f.key, f.upload, n, content);
                await run(
                  "INSERT INTO parts VALUES(?,?,?,?) ON CONFLICT(file,number) DO UPDATE SET etag=excluded.etag,size=excluded.size",
                  f.id,
                  n,
                  etag,
                  content.length,
                );
                return { value: { number: n, received: content.length } };
              }
              if (method === "POST" && ur[4]) {
                need(
                  f.status === "uploading",
                  409,
                  "Completion already in progress; contact support if interrupted",
                );
                const parts = await q(
                  "SELECT number,etag,size FROM parts WHERE file=? ORDER BY number",
                  f.id,
                );
                need(
                  parts.length === Math.ceil(f.size / PART) &&
                    parts.reduce((a, p) => a + p.size, 0) === f.size,
                  409,
                  "Upload is incomplete",
                );
                await directTransfers.verify(f, parts);
                await run(
                  "UPDATE files SET status='finishing' WHERE id=?",
                  f.id,
                );
                return { finish: true, file: f, parts };
              }
              if (method === "DELETE") {
                need(
                  ["uploading", "canceling"].includes(f.status),
                  409,
                  "Completion in progress",
                );
                await run(
                  "UPDATE files SET status='canceling' WHERE id=?",
                  f.id,
                );
                return { cancel: true, file: f };
              }
              throw error(405, "Unsupported upload operation");
            });
            if (result.finish) {
              const f = result.file,
                storage = await workspaceStorage.forFile(f),
                version = await storage.complete(f.key, f.upload, result.parts),
                info = await storage.head(f.key, version);
              need(
                info.size === f.size,
                502,
                "Stored file size verification failed",
              );
              await run(
                "UPDATE files SET status='ready',version=? WHERE id=? AND status='finishing'",
                version,
                f.id,
              );
              await audit(
                tenant,
                user.email,
                "Upload completed and size verified",
                f.id,
              );
              return send(res, 200, publicFile({ ...f, status: "ready" }));
            }
            if (result.cancel) {
              const f = result.file;
              await (await workspaceStorage.forFile(f)).abort(f.key, f.upload);
              await db.transaction(async () => {
                await db.lock("file:" + f.id);
                await run("DELETE FROM upload_part_grants WHERE file=?", f.id);
                await run("DELETE FROM parts WHERE file=?", f.id);
                await run(
                  "DELETE FROM files WHERE id=? AND status='canceling'",
                  f.id,
                );
                await audit(tenant, user.email, "Upload canceled", f.id);
              });
              return send(res, 200, { ok: true });
            }
            return send(res, 200, result.value);
          }
          const fr =
            /^\/files\/([^/]+)(?:\/(download|download-link|restore))?$/.exec(
              tail,
            );
          if (fr) {
            need(t.role !== "uploader");
            const f = await one(
              "SELECT * FROM files WHERE id=? AND tenant=?",
              fr[1],
              tenant,
            );
            need(f, 404, "File not found");
            if (method === "POST" && fr[2] === "download-link") {
              need(
                !(await security.recoveryPending()),
                503,
                "Recovery review is required before file transfers",
              );
              need(f.status === "ready", 404);
              need(ready, 503, "Storage not activated");
              return send(
                res,
                200,
                await directTransfers.download(f, user.email),
              );
            }
            if (method === "GET" && fr[2] === "download") {
              need(
                !(await security.recoveryPending()),
                503,
                "Recovery review is required before file transfers",
              );
              need(f.status === "ready", 404);
              need(ready, 503, "Storage not activated");
              const adapter = await workspaceStorage.forFile(f);
              if (adapter.transport === "direct") {
                const link = await directTransfers.download(f, user.email);
                res.writeHead(302, { Location: link.url });
                res.end();
                return;
              }
              const range = req.headers.range;
              need(
                !range || /^bytes=\d+-\d*$/.test(range),
                416,
                "Unsupported range",
              );
              const match = range ? /^bytes=(\d+)-(\d*)$/.exec(range) : null,
                start = match ? Number(match[1]) : 0,
                end =
                  match && match[2]
                    ? Math.min(Number(match[2]), f.size - 1)
                    : f.size - 1;
              need(
                start >= 0 && start < f.size && end >= start,
                416,
                "Unsupported range",
              );
              const transfer = await mspConsole.reserveDownload(
                tenant,
                end - start + 1,
              );
              let streamed = 0,
                success = false;
              try {
                const result = await (
                  await workspaceStorage.forFile(f)
                ).get(f.key, f.version, range);
                await audit(tenant, user.email, "Download authorized", f.id);
                res.writeHead(range ? 206 : 200, {
                  "Content-Type": "application/octet-stream",
                  "Content-Disposition": `attachment; filename="download"; filename*=UTF-8''${encodeURIComponent(f.name).replace(/'/g, "%27")}`,
                  "Content-Length": result.length,
                  "Accept-Ranges": "bytes",
                  ...(result.range ? { "Content-Range": result.range } : {}),
                });
                const meter = new Transform({
                  transform(chunk, encoding, done) {
                    streamed += chunk.length;
                    done(null, chunk);
                  },
                });
                await pipeline(result.body, meter, res);
                success = true;
              } finally {
                await mspConsole.finishDownload(transfer, streamed, success);
              }

              return;
            }
            if (method === "PATCH") {
              await tenantAccess(user, tenant, true);
              need(f.status === "ready", 409);
              const b = await body(req);
              need(
                typeof b.name === "string" &&
                  b.name.length > 0 &&
                  b.name.length <= 200 &&
                  !/[\x00-\x1f/\\]/.test(b.name),
                400,
                "Invalid file name",
              );
              await run("UPDATE files SET name=? WHERE id=?", b.name, f.id);
              await audit(tenant, user.email, "File renamed", f.id);
              return send(res, 200, { ok: true });
            }
            if (method === "DELETE") {
              await tenantAccess(user, tenant, true);
              need(f.status === "ready", 409);
              await run("UPDATE files SET status='trash' WHERE id=?", f.id);
              await audit(tenant, user.email, "File moved to trash", f.id);
              return send(res, 200, { ok: true });
            }
            if (method === "POST" && fr[2] === "restore") {
              await tenantAccess(user, tenant, true);
              need(f.status === "trash", 409);
              await run("UPDATE files SET status='ready' WHERE id=?", f.id);
              await audit(tenant, user.email, "File restored", f.id);
              return send(res, 200, { ok: true });
            }
          }
          throw error(404, "Not found");
        }
        need(method === "GET" || method === "HEAD", 405);
        const file = path === "/" ? "index.html" : path.slice(1);
        need(
          [
            "index.html",
            "app.js",
            "style.css",
            "demo.js",
            "clerk-client.js",
            "spark-md5.min.js",
            "favicon.svg",
            "favicon.ico",
          ].includes(file),
          404,
          "Not found",
        );
        const contents = readFileSync(resolve("dist", file));
        res.writeHead(200, {
          "Content-Type": {
            ".html": "text/html; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
          }[extname(file)],
        });
        res.end(contents);
      } catch (e) {
        if (res.headersSent) {
          try {
            await securityLog.event("request_failed", {
              ...context,
              status: 502,
              severity: "high",
            });
          } catch {
            console.error(
              JSON.stringify({
                event: "security_log_unavailable",
                requestId: context.requestId,
              }),
            );
          }
          res.destroy();
          return;
        }
        const status = e.status || 500;
        try {
          await securityLog.event(
            status === 401
              ? "authentication_failed"
              : status >= 500
                ? "request_failed"
                : "request_denied",
            {
              ...context,
              status,
              severity: status >= 500 ? "high" : "warning",
            },
          );
        } catch {
          console.error(
            JSON.stringify({
              event: "security_log_unavailable",
              requestId: context.requestId,
            }),
          );
        }

        if (status >= 500)
          console.error(
            JSON.stringify({
              event: "request_failed",
              code: e.name || "Error",
              at: now(),
              requestId: context.requestId,
            }),
          );
        return send(res, status, {
          error:
            context.maintenanceAuthenticated &&
            e.code === "ARCHIVE_CONFIGURATION"
              ? e.message
              : status >= 500
                ? "Service temporarily unavailable. Contact your storage administrator."
                : e.message,
          ...(e.code ? { code: e.code } : {}),
        });
      }
    },
  ),
);
const timer = setInterval(() => {
  run("DELETE FROM sessions WHERE expires<?", Date.now()).catch(() =>
    console.error(JSON.stringify({ event: "session_cleanup_failed" })),
  );
  for (const [key, l] of limits) if (l.until < Date.now()) limits.delete(key);
}, 30000);
timer.unref();
server.requestTimeout = 15 * 60 * 1000;
server.headersTimeout = 60000;
server.listen(
  Number(env.PORT) || 4173,
  demo ? "127.0.0.1" : env.HOST || "127.0.0.1",
  () =>
    console.log(
      `Streamlined Vault ${demo ? "LOCAL TEST MODE" : "server"}: ${origin}`,
    ),
);
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, () => {
    clearInterval(timer);
    server.close(async () => {
      await db.close();
      process.exit(0);
    });
  });
