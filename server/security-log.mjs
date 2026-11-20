import { createHash, randomUUID } from "node:crypto";
export const digest = (value) =>
  createHash("sha256")
    .update(typeof value === "string" ? value : JSON.stringify(value))
    .digest("hex");
export const auditValue = (r) => ({
  id: r.id,
  tenant: r.tenant,
  actor: r.actor,
  action: r.action,
  resource: r.resource,
  created: r.created,
  previous: r.previous,
});
export const eventValue = (r) => ({
  id: r.id,
  created: r.created,
  event: r.event,
  severity: r.severity,
  status: r.status,
  actor: r.actor,
  tenant: r.tenant,
  resource: r.resource,
  request_id: r.request_id,
  route: r.route,
  method: r.method,
  previous: r.previous,
});
const codes = new Set([
  "maintenance_started",
  "request_completed",
  "request_authenticated",
  "request_denied",
  "authentication_failed",
  "request_failed",
  "sign_in",
  "sign_out",
  "archive_failed",
  "archive_verified",
  "integrity_failed",
  "storage_check_failed",
  "storage_check_verified",
  "maintenance_failed",
  "access_review",
  "recovery_verified",
]);
const safeId = (s) =>
  typeof s === "string" && /^[A-Za-z0-9:_-]{1,120}$/.test(s) ? s : "";
export function routeClass(path) {
  if (path.startsWith("/auth/")) return "authentication";
  if (path.startsWith("/api/msp/security")) return "security_console";
  if (path.startsWith("/api/msp/")) return "msp_console";
  if (path.startsWith("/api/device")) return "uploader";
  if (path.startsWith("/api/tenants/"))
    return path.includes("/uploads")
      ? "upload"
      : path.includes("/files")
        ? "file"
        : path.includes("/members")
          ? "membership"
          : "workspace";
  return path === "/api/logout" ? "sign_out" : "other";
}
export function createSecurityLog({
  db,
  clock = () => new Date().toISOString(),
}) {
  async function alert(code, severity = "high") {
    return db.transaction(async () => {
      await db.lock("security:alert:" + code);
      const now = clock(),
        normalized = safeId(code) || "security_failure";
      const existing = await db.one(
        "SELECT * FROM security_alerts WHERE code=?",
        normalized,
      );
      const id = existing?.id || randomUUID();
      await db.run(
        "INSERT INTO security_alerts(id,code,severity,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET last_seen=excluded.last_seen,occurrences=security_alerts.occurrences+1,status='open',acknowledged_by=NULL,acknowledged_at=NULL",
        id,
        normalized,
        severity,
        now,
        now,
      );
      if (!existing || existing.status !== "open") {
        const generation = randomUUID();
        await db.run(
          "INSERT INTO alert_deliveries(id,alert_id,generation,category,severity,status,next_attempt,created) VALUES(?,?,?,?,?,'pending',?,?)",
          randomUUID(),
          id,
          generation,
          normalized,
          ["high", "critical", "warning", "info"].includes(severity)
            ? severity
            : "high",
          Date.now(),
          now,
        );
      }
      return id;
    });
  }

  async function event(code, input = {}) {
    if (!codes.has(code)) throw Error("Unknown security event");
    return await db.transaction(async () => {
      await db.lock("security:chain");
      const previous =
        (
          await db.one(
            "SELECT digest FROM security_events ORDER BY rowid DESC LIMIT 1",
          )
        )?.digest || "";
      const value = {
        id: randomUUID(),
        created: clock(),
        event: code,
        severity: ["info", "warning", "high", "critical"].includes(
          input.severity,
        )
          ? input.severity
          : "info",
        status: Number.isInteger(input.status) ? input.status : 0,
        actor: input.actor
          ? digest(String(input.actor).toLowerCase())
          : "anonymous",
        tenant: safeId(input.tenant),
        resource: safeId(input.resource),
        request_id: safeId(input.requestId),
        route: [
          "authentication",
          "security_console",
          "msp_console",
          "uploader",
          "upload",
          "file",
          "membership",
          "workspace",
          "sign_out",
          "other",
        ].includes(input.route)
          ? input.route
          : "other",
        method: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"].includes(
          input.method,
        )
          ? input.method
          : "OTHER",
        previous,
      };
      await db.run(
        "INSERT INTO security_events(id,created,event,severity,status,actor,tenant,resource,request_id,route,method,previous,digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ...Object.values(value),
        digest(value),
      );
      if (["high", "critical"].includes(value.severity))
        await alert(code, value.severity);
      return value.id;
    });
  }
  async function verify(source = "audit", { maxRows = 10000 } = {}) {
    if (!["audit", "security_events"].includes(source))
      throw Error("Invalid log source");
    return db.transaction(async () => {
      await db.lock("security:verify:" + source);
      const saved = await db.one(
          "SELECT value FROM security_state WHERE id=?",
          "integrity:" + source,
        ),
        cursor = saved ? JSON.parse(saved.value) : null;
      let last = cursor?.position || 0,
        previous = cursor?.tip || "",
        lastId = cursor?.lastId || "",
        count = 0;
      if (last) {
        const anchor = await db.one(
          `SELECT digest FROM ${source} WHERE id=?`,
          lastId,
        );
        if (anchor?.digest !== previous) {
          await alert("integrity_failed", "critical");
          return { ok: false, source, checked: 0, failedId: lastId };
        }
      }
      let complete = false;
      for (;;) {
        const rows = await db.q(
          `SELECT rowid AS position,* FROM ${source} WHERE rowid>? ORDER BY rowid LIMIT 1000`,
          last,
        );
        if (!rows.length) {
          complete = true;
          break;
        }
        for (const row of rows) {
          if (
            row.previous !== previous ||
            digest(source === "audit" ? auditValue(row) : eventValue(row)) !==
              row.digest
          ) {
            await alert("integrity_failed", "critical");
            return { ok: false, source, checked: count, failedId: row.id };
          }
          previous = row.digest;
          last = Number(row.position);
          lastId = row.id;
          count++;
        }
        if (count >= maxRows) break;
      }
      await db.run(
        "INSERT INTO security_state(id,value,updated) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
        "integrity:" + source,
        JSON.stringify(
          complete
            ? { position: 0, completedAt: clock() }
            : { position: last, tip: previous, lastId },
        ),
        clock(),
      );
      return { ok: true, source, checked: count, tip: previous, complete };
    });
  }
  return { event, alert, verify };
}
