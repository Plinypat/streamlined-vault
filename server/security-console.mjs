import { randomUUID, randomBytes, createHash } from "node:crypto";
import { createAuditArchive, readBounded } from "./audit-archive.mjs";
const hash = (b) => createHash("sha256").update(b).digest("hex");
const need = (v, message) => {
  if (!v) throw Object.assign(Error(message), { status: 409 });
};
export async function runStorageCanary(
  adapter,
  { origin, foreign, fetcher = fetch } = {},
) {
  const key = "security-canary/" + randomUUID(),
    bytes = randomBytes(17 * 1024 * 1024),
    part = 16 * 1024 * 1024;
  let upload,
    version,
    completed = false;
  try {
    upload = await adapter.start(key);
    const parts = [];
    for (
      let number = 1, offset = 0;
      offset < bytes.length;
      number++, offset += part
    ) {
      const chunk = bytes.subarray(offset, offset + part);
      let etag;
      if (adapter.transport === "direct") {
        const grant = await adapter.signPart(
          key,
          upload,
          number,
          chunk.length,
          createHash("md5").update(chunk).digest("base64"),
        );
        need(
          new URL(grant.url).protocol === "https:",
          "Canary transfer requires HTTPS",
        );
        const response = await fetcher(grant.url, {
          method: "PUT",
          headers: grant.headers,
          body: chunk,
          redirect: "error",
        });
        need(response.ok, "Canary signed upload failed");
        const [stored] = await adapter.listParts(key, upload, number);
        need(
          stored?.number === number && stored.size === chunk.length,
          "Canary part verification failed",
        );
        etag = stored.etag;
        if (origin && number === 1) {
          const cors = await fetcher(grant.url, {
            method: "OPTIONS",
            headers: {
              Origin: origin,
              "Access-Control-Request-Method": "PUT",
              "Access-Control-Request-Headers": "content-md5",
            },
            redirect: "error",
          });
          need(
            cors.ok &&
              cors.headers.get("access-control-allow-origin") === origin,
            "Browser transfer origin could not be verified",
          );
        }
      } else etag = await adapter.part(key, upload, number, chunk);
      parts.push({ number, etag, size: chunk.length });
    }
    version = await adapter.complete(key, upload, parts);
    completed = true;
    const info = await adapter.head(key, version);
    need(info.size === bytes.length, "Canary stored size mismatch");
    if (adapter.transport === "direct")
      need(
        info.encryption === "AES256",
        "Canary object encryption was not verified",
      );
    let restoreBody;
    if (adapter.transport === "direct") {
      const link = await adapter.signDownload(
        key,
        version,
        "streamlined-vault-security-test.bin",
      );
      need(
        new URL(link.url).protocol === "https:",
        "Canary download requires HTTPS",
      );
      const response = await fetcher(link.url, { redirect: "error" });
      need(response.ok, "Canary signed download failed");
      restoreBody = response.body;
    } else restoreBody = (await adapter.get(key, version)).body;
    const restored = await readBounded(restoreBody, 20 * 1024 * 1024);
    need(hash(restored) === hash(bytes), "Canary restore checksum mismatch");
    const range = await readBounded(
      (await adapter.get(key, version, "bytes=13-31")).body,
    );
    need(range.equals(bytes.subarray(13, 32)), "Canary range restore mismatch");
    if (foreign)
      need(
        await foreign.deniedReadProbe(adapter.bucket, key, version),
        "Cross-bucket credential isolation failed",
      );
    return {
      ok: true,
      bytes: bytes.length,
      multipart: true,
      checksumVerified: true,
      rangeVerified: true,
      crossBucketVerified: !!foreign,
      browserOriginVerified: !!origin,
      objectEncryptionVerified: adapter.transport === "direct",
    };
  } finally {
    if (completed) await adapter.removeCanary(key, version);
    else if (upload) await adapter.abort(key, upload);
  }
}
export function createSecurityConsole({
  db,
  env,
  demo,
  data,
  log,
  workspaceStorage,
  audit,
  archive: providedArchive,
}) {
  const archive =
    providedArchive || createAuditArchive({ db, env, demo, data, log });
  async function check(kind, tenant, status, result) {
    const item = {
      id: randomUUID(),
      kind,
      tenant: tenant || "",
      status,
      result,
      created: new Date().toISOString(),
    };
    await db.run(
      "INSERT INTO security_checks VALUES(?,?,?,?,?,?)",
      item.id,
      kind,
      item.tenant,
      status,
      JSON.stringify(result),
      item.created,
    );
    return item;
  }
  async function databaseCheck() {
    if (demo && db.kind === "sqlite")
      return await check("database", "", "synthetic", {
        encryptedTransport: false,
        restrictedRole: false,
        synthetic: true,
      });
    const row = await db.one(
      "SELECT s.ssl,s.version,r.rolsuper,EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname='streamlined_vault' AND n.nspowner=r.oid) AS schema_owner,EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='streamlined_vault' AND c.relowner=r.oid) AS table_owner FROM pg_roles r LEFT JOIN pg_stat_ssl s ON s.pid=pg_backend_pid() WHERE r.rolname=current_user",
    );
    const result = {
      encryptedTransport: !!row.ssl,
      tlsVersion: row.version || null,
      restrictedRole: !row.rolsuper && !row.schema_owner && !row.table_owner,
    };
    if (!result.encryptedTransport || !result.restrictedRole)
      await log.alert("database_hardening_required", "high");
    return await check(
      "database",
      "",
      result.encryptedTransport && result.restrictedRole
        ? "passed"
        : "attention",
      result,
    );
  }
  async function storageCheck(tenant, actor) {
    need(tenant, "Choose a workspace for the transfer test");
    try {
      const review = await workspaceStorage.securityReview(tenant),
        location = await workspaceStorage.location(tenant);
      const adapter = await workspaceStorage.forFile({
        tenant,
        storage_tenant: location,
      });
      let foreign;
      if (!demo) {
        const other = await db.one(
          "SELECT tenant FROM workspace_storage WHERE status='ready' AND tenant<>? AND bucket<>? LIMIT 1",
          tenant,
          adapter.bucket,
        );
        if (other)
          foreign = await workspaceStorage.forFile({
            tenant: other.tenant,
            storage_tenant: other.tenant,
          });
        await workspaceStorage.prepareBrowser(tenant);
      }
      const transfer = await runStorageCanary(adapter, {
        origin: demo ? undefined : new URL(env.APP_ORIGIN).origin,
        foreign,
      });
      const result = { ...review, ...transfer, synthetic: demo };
      await audit(tenant, actor, "Synthetic security restore verified");
      await log.event("storage_check_verified", { actor, tenant });
      return await check(
        "storage",
        tenant,
        demo ? "synthetic" : "passed",
        result,
      );
    } catch (e) {
      await log.event("storage_check_failed", {
        actor,
        tenant,
        severity: "high",
      });
      await check("storage", tenant, "failed", {
        code: e.providerCode || "STORAGE_CHECK_FAILED",
        message:
          e.code === "ARCHIVE_CONFIGURATION" || (e.status && e.status < 500)
            ? e.message
            : "Storage security check failed; review provider configuration and retry",
      });
      throw e;
    }
  }
  async function maintenance(actor = "security-maintenance") {
    let claimed = false;
    const started = Date.now();
    await db.transaction(async () => {
      await db.lock("security:maintenance");
      const lease = await archive.setting("maintenance_lease");
      if (lease?.until > Date.now()) return;
      await archive.save("maintenance_lease", {
        until: Date.now() + 240000,
        owner: started,
      });
      claimed = true;
    });
    if (!claimed) return { ok: true, busy: true };
    try {
      const integrity = await Promise.all([
        log.verify("audit"),
        log.verify("security_events"),
      ]);
      need(
        integrity.every((r) => r.ok),
        "Log integrity check failed",
      );
      await databaseCheck();
      const devices = await db.q(
        "SELECT id,tenant,last_seen,last_success FROM devices WHERE revoked=0 AND paused=0 AND token IS NOT NULL",
      );
      for (const d of devices)
        if (!d.last_seen || Date.now() - Date.parse(d.last_seen) > 86400000)
          await log.alert("uploader_offline_" + d.id, "high");
        else if (
          !d.last_success ||
          Date.now() - Date.parse(d.last_success) > 172800000
        )
          await log.alert("uploader_no_success_" + d.id, "high");
      const interrupted = await db.one(
        "SELECT COUNT(*) AS count FROM files WHERE status IN ('uploading','finishing','canceling') AND created<?",
        new Date(Date.now() - 86400000).toISOString(),
      );
      if (Number(interrupted.count) > 0)
        await log.alert("stalled_uploads", "high");
      const failures = await db.one(
        "SELECT COUNT(*) AS count FROM security_events WHERE event='authentication_failed' AND created>?",
        new Date(Date.now() - 15 * 60000).toISOString(),
      );
      if (Number(failures.count) >= 20)
        await log.alert("repeated_authentication_failures", "high");
      if (!demo) {
        const candidate = await db.one(
          "SELECT t.id FROM tenants t WHERE t.status='active' AND NOT EXISTS(SELECT 1 FROM security_checks c WHERE c.kind='storage' AND c.tenant=t.id AND c.created>?) ORDER BY t.id LIMIT 1",
          new Date(Date.now() - 86400000).toISOString(),
        );
        if (candidate)
          try {
            await storageCheck(candidate.id, actor);
          } catch {
            /* Failure is recorded; archival must continue. */
          }
      }
      await log.event("maintenance_started", { actor });
      let result = { ok: true, archivedBatches: 0, synthetic: demo };
      for (let i = 0; i < 16 && Date.now() - started < 90000; i++) {
        const batch = await archive.flush();
        result.archivedBatches += batch.archivedBatches;
        if (batch.archivedBatches === 0) break;
      }
      const verified = await archive.verifyLatest();
      await log.event("archive_verified", { actor });
      await archive.save("maintenance_last_success", {
        at: new Date().toISOString(),
        durationMs: Date.now() - started,
        synthetic: demo,
        source: actor === "security-maintenance" ? "scheduled" : "manual",
      });
      if (actor === "security-maintenance")
        await archive.save("maintenance_last_scheduled_success", {
          at: new Date().toISOString(),
        });
      await archive.save("maintenance_last_failure", null);
      await check(
        "log_integrity",
        "",
        demo
          ? "synthetic"
          : integrity.every((r) => r.complete)
            ? "passed"
            : "in_progress",
        {
          integrity,
          archive: verified,
        },
      );
      return { ...result, verified };
    } catch (e) {
      await log.event("maintenance_failed", { actor, severity: "high" });
      await archive.save("maintenance_last_failure", {
        at: new Date().toISOString(),
        code: e.providerCode || "MAINTENANCE_FAILED",
        message:
          e.code === "ARCHIVE_CONFIGURATION" || (e.status && e.status < 500)
            ? e.message
            : "Maintenance failed; archive provisioning/retention configuration needs review",
      });
      throw e;
    } finally {
      await db.transaction(async () => {
        await db.lock("security:maintenance");
        const lease = await archive.setting("maintenance_lease");
        if (lease?.owner === started)
          await archive.save("maintenance_lease", { until: 0 });
      });
    }
  }
  async function status() {
    const checks = (
      await db.q(
        "SELECT * FROM security_checks ORDER BY created DESC LIMIT 100",
      )
    ).map((c) => ({ ...c, result: JSON.parse(c.result) }));
    const alerts = await db.q(
      "SELECT * FROM security_alerts ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END,last_seen DESC LIMIT 100",
    );
    const last = await archive.setting("maintenance_last_success");
    const scheduled = await archive.setting(
      "maintenance_last_scheduled_success",
    );
    return {
      technicalApproval: false,
      synthetic: demo,
      archive: await archive.status(),
      maintenance: {
        configured: !!env.CRON_SECRET,
        lastSuccess: last,
        lastScheduledSuccess: scheduled,
        lastFailure: await archive.setting("maintenance_last_failure"),
        stale:
          !scheduled || Date.now() - Date.parse(scheduled.at) > 2 * 3600000,
      },
      checks,
      alerts,
      events: await db.q(
        "SELECT id,created,event,severity,status,tenant,resource,request_id,route,method FROM security_events ORDER BY rowid DESC LIMIT 100",
      ),
      accessReview: await archive.setting("access_review"),
      remaining: [
        "Independent recovery-key custody and metadata restore drill",
        "Production endpoint/MFA recovery and revocation acceptance",
        "Runtime database role, previously shared credential rotation and platform configuration review",
        "External alert delivery and independent schedule monitoring",
      ],
    };
  }
  async function acknowledge(id, actor) {
    await db.run(
      "UPDATE security_alerts SET status='acknowledged',acknowledged_by=?,acknowledged_at=? WHERE id=?",
      actor,
      new Date().toISOString(),
      id,
    );
    await audit("msp", actor, "Security alert acknowledged", id);
  }
  async function accessReview(actor) {
    await archive.save("access_review", {
      at: new Date().toISOString(),
      reviewer: actor,
    });
    await log.event("access_review", { actor });
    await audit("msp", actor, "Privileged access reviewed");
  }
  return {
    status,
    maintenance,
    storageCheck,
    databaseCheck,
    acknowledge,
    accessReview,
    archive,
    recoveryPending: () => archive.setting("recovery_review_required"),
  };
}
