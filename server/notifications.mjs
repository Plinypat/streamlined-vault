import { randomUUID } from "node:crypto";
const categories = {
  metadata_backup_failed: "Metadata backup failure",
  metadata_backup_capacity: "Metadata backup capacity warning",
  integrity_failed: "Log integrity failure",
  archive_failed: "Audit archive failure",
  maintenance_failed: "Security maintenance failure",
  database_hardening_required: "Database security review required",
  notification_test: "Notification delivery test",
  backup_recovered: "Metadata backup recovered",
  maintenance_recovered: "Security maintenance recovered",
};
export function alertCategory(code) {
  return (
    categories[code] ||
    (code.startsWith("uploader_")
      ? "Uploader requires attention"
      : "Security check requires attention")
  );
}
export async function heartbeat(url, kind, { fetcher = fetch } = {}) {
  if (!url) return { configured: false };
  const u = new URL(url);
  if (
    u.origin !== "https://hc-ping.com" ||
    !/^\/[a-f0-9-]{36}$/.test(u.pathname) ||
    u.search ||
    u.hash ||
    u.username ||
    u.password
  )
    throw Error("Invalid monitor configuration");
  const response = await fetcher(u.href + (kind === "failure" ? "/fail" : ""), {
    method: "POST",
    body: "",
    redirect: "error",
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) throw Error("Monitor delivery failed");
  return { configured: true, accepted: true };
}
export function createNotifications({ db, env, fetcher = fetch }) {
  const configured = () =>
    !!env.RESEND_API_KEY && !!env.ALERT_EMAIL_FROM && !!env.ALERT_EMAIL_TO;
  async function drain() {
    if (!configured()) return { configured: false, accepted: 0 };
    return db.transaction(async () => {
      await db.lock("operations:email");
      const missing = await db.q(
        "SELECT a.id,a.code,a.severity FROM security_alerts a WHERE a.status='open' AND NOT EXISTS(SELECT 1 FROM alert_deliveries d WHERE d.alert_id=a.id) LIMIT 50",
      );
      for (const a of missing)
        await db.run(
          "INSERT INTO alert_deliveries(id,alert_id,generation,category,severity,status,next_attempt,created) VALUES(?,?,? ,?,?,'pending',?,?)",
          randomUUID(),
          a.id,
          randomUUID(),
          a.code,
          a.severity,
          Date.now(),
          new Date().toISOString(),
        );
      const rows = await db.q(
        "SELECT * FROM alert_deliveries WHERE status='pending' AND next_attempt<=? ORDER BY created LIMIT 10",
        Date.now(),
      );
      let accepted = 0;
      for (const row of rows) {
        if (Date.now() - Date.parse(row.created) > 23 * 3600000) {
          await db.run(
            "UPDATE alert_deliveries SET status='review_required' WHERE id=?",
            row.id,
          );
          continue;
        }
        try {
          const origin = new URL(env.APP_ORIGIN).origin;
          if (!origin.startsWith("https://")) throw Error("HTTPS required");
          const r = await fetcher("https://api.resend.com/emails", {
            method: "POST",
            redirect: "error",
            signal: AbortSignal.timeout(8000),
            headers: {
              Authorization: "Bearer " + env.RESEND_API_KEY,
              "Content-Type": "application/json",
              "Idempotency-Key": row.id,
            },
            body: JSON.stringify({
              from: env.ALERT_EMAIL_FROM,
              to: [env.ALERT_EMAIL_TO],
              subject: "Streamlined Vault: " + alertCategory(row.category),
              text: `${alertCategory(row.category)}\nSeverity: ${row.severity}\nTime: ${row.created}\nIncident: ${row.id}\nDashboard: ${origin}\nSign in and open Security & logs. No patient or file details are included.`,
            }),
          });
          if (!r.ok) {
            let reason='PROVIDER_REJECTED';
            try {const result=await r.json(),message=String(result.message||'').toLowerCase();
              reason=message.includes('domain')?'SENDING_DOMAIN_REVIEW':message.includes('from')?'SENDER_FORMAT_REVIEW':message.includes('api key')?'API_KEY_REVIEW':message.includes('testing')?'SENDING_ACCOUNT_REVIEW':'PROVIDER_REJECTED';
            }catch{}
            console.warn(JSON.stringify({event:'email_delivery_rejected',status:r.status||0,reason,incident:row.id}));
            throw Error("Email request failed");
          }
          const result = await r.json();
          if (typeof result.id !== "string")
            throw Error("Missing provider acceptance");
          await db.run(
            "UPDATE alert_deliveries SET status='accepted',accepted=?,provider_id=?,attempts=attempts+1 WHERE id=?",
            new Date().toISOString(),
            result.id,
            row.id,
          );
          accepted++;
        } catch {
          const attempts = row.attempts + 1;
          await db.run(
            "UPDATE alert_deliveries SET attempts=?,status=?,next_attempt=? WHERE id=?",
            attempts,
            attempts >= 5 ? "failed" : "pending",
            Date.now() + Math.min(3600000, 60000 * 2 ** attempts),
            row.id,
          );
        }
      }
      return { configured: true, accepted };
    });
  }
  async function status() {
    return {
      configured: configured(),
      maintenanceMonitorConfigured: !!env.HEALTHCHECKS_MAINTENANCE_URL,
      backupMonitorConfigured: !!env.HEALTHCHECKS_BACKUP_URL,
      deliveries: await db.q(
        "SELECT id,status,attempts,created,accepted FROM alert_deliveries ORDER BY created DESC LIMIT 20",
      ),
    };
  }
  return { drain, status };
}
