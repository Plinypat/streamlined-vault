import { randomUUID, randomBytes } from "node:crypto";
import {
  BucketProvisioner,
  encryptionKey,
  sealCredentials,
  openCredentials,
} from "./workspace-storage.mjs";

const fail = (status, message) => Object.assign(Error(message), { status });
const need = (value, status, message) => {
  if (!value) throw fail(status, message);
};
const period = () => new Date().toISOString().slice(0, 7);
const defaults = {
  published: false,
  downloadLimitBytes: null,
  downloadMode: "notice",
  downloadOverageCentsPerGB: null,
  storageUpgradeCentsPerTB: null,
  additionalServices:
    "Additional storage, assisted restores and migration services require a separate agreement.",
};
export function validatePlan(input) {
  need(
    input && typeof input === "object" && !Array.isArray(input),
    400,
    "A plan configuration is required",
  );
  const policy = { ...defaults, ...input };
  need(
    typeof policy.published === "boolean" &&
      ["notice", "block"].includes(policy.downloadMode),
    400,
    "Choose valid publication and download-limit settings",
  );
  for (const key of [
    "downloadLimitBytes",
    "downloadOverageCentsPerGB",
    "storageUpgradeCentsPerTB",
  ])
    need(
      policy[key] === null ||
        (Number.isSafeInteger(policy[key]) &&
          policy[key] >= 0 &&
          policy[key] <= 10 ** 15),
      400,
      "Plan amounts must be non-negative whole values",
    );
  need(
    policy.downloadMode !== "block" || policy.downloadLimitBytes !== null,
    400,
    "Set a download allowance before enabling a hard limit",
  );
  need(
    typeof policy.additionalServices === "string" &&
      policy.additionalServices.length <= 2000,
    400,
    "Additional-service description is too long",
  );
  return Object.fromEntries(
    Object.keys(defaults).map((key) => [key, policy[key]]),
  );
}

export async function createMspConsole({
  db,
  env,
  demo,
  workspaceStorage,
  maxFileBytes,
  audit,
  provider = new BucketProvisioner(),
}) {
  const installed = new Date().toISOString();
  await db.run(
    "INSERT INTO service_settings(id,value,updated) VALUES('meter_start',?,?) ON CONFLICT(id) DO NOTHING",
    installed,
    installed,
  );
  const meterStart = (
    await db.one("SELECT value FROM service_settings WHERE id='meter_start'")
  ).value;
  async function settings() {
    const row = await db.one(
      "SELECT value FROM service_settings WHERE id='default_plan'",
    );
    return row ? validatePlan(JSON.parse(row.value)) : { ...defaults };
  }
  async function policy(tenant) {
    const t = await db.one("SELECT kind FROM tenants WHERE id=?", tenant);
    if (t?.kind === "internal") return { ...defaults };
    const row = await db.one(
      "SELECT policy FROM workspace_plans WHERE tenant=?",
      tenant,
    );
    return row ? validatePlan(JSON.parse(row.policy)) : await settings();
  }
  async function transfers(tenant) {
    const rows = await db.q(
      "SELECT direction,COALESCE(SUM(bytes),0) AS bytes,COALESCE(SUM(CASE WHEN status='active' THEN reserved ELSE 0 END),0) AS reserved FROM transfer_events WHERE tenant=? AND period=? GROUP BY direction",
      tenant,
      period(),
    );
    const up = rows.find((r) => r.direction === "upload"),
      down = rows.find((r) => r.direction === "download");
    return {
      period: period(),
      uploadedBytes: Number(up?.bytes || 0),
      downloadedBytes: Number(down?.bytes || 0),
      reservedDownloadBytes: Number(down?.reserved || 0),
      trackingSince: meterStart,
    };
  }
  async function plan(tenant) {
    const p = await policy(tenant),
      t = await db.one("SELECT quota FROM tenants WHERE id=?", tenant);
    return {
      storageLimitBytes: t?.quota || 4e12,
      maxFileBytes,
      meter: await transfers(tenant),
      policy: p.published ? p : { published: false },
      billingAutomatic: false,
    };
  }
  async function savePlan(tenant, value, actor) {
    if (tenant)
      need(
        (await db.one("SELECT kind FROM tenants WHERE id=?", tenant))?.kind !==
          "internal",
        400,
        "Client billing plans do not apply to private MSP workspaces",
      );
    const p = validatePlan(value),
      now = new Date().toISOString();
    await db.transaction(async () => {
      if (tenant)
        await db.run(
          "INSERT INTO workspace_plans(tenant,policy,updated) VALUES(?,?,?) ON CONFLICT(tenant) DO UPDATE SET policy=excluded.policy,updated=excluded.updated",
          tenant,
          JSON.stringify(p),
          now,
        );
      else
        await db.run(
          "INSERT INTO service_settings(id,value,updated) VALUES('default_plan',?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value,updated=excluded.updated",
          JSON.stringify(p),
          now,
        );
      await audit(
        tenant || "msp",
        actor,
        p.published
          ? "Service allowance published"
          : "Service allowance draft saved",
      );
    });
    return p;
  }
  async function recordUpload(tenant, bytes) {
    await db.run(
      "INSERT INTO transfer_events(id,tenant,direction,period,bytes,status,created) VALUES(?,?,'upload',?,?,'complete',?)",
      randomUUID(),
      tenant,
      period(),
      bytes,
      new Date().toISOString(),
    );
  }
  async function reserveDownload(tenant, bytes) {
    const id = randomUUID(),
      now = new Date().toISOString();
    await db.transaction(async () => {
      await db.lock("download:" + tenant + ":" + period());
      await db.run(
        "UPDATE transfer_events SET reserved=0,status='interrupted' WHERE tenant=? AND direction='download' AND status='active' AND expires<?",
        tenant,
        Date.now(),
      );
      const p = await policy(tenant),
        m = await transfers(tenant);
      if (p.published && p.downloadMode === "block")
        need(
          m.downloadedBytes + m.reservedDownloadBytes + bytes <=
            p.downloadLimitBytes,
          409,
          "Monthly download allowance reached. Contact your storage administrator.",
        );
      await db.run(
        "INSERT INTO transfer_events(id,tenant,direction,period,reserved,status,created,expires) VALUES(?,?,'download',?,?,'active',?,?)",
        id,
        tenant,
        period(),
        bytes,
        now,
        Date.now() + 3600000,
      );
    });
    return id;
  }
  async function finishDownload(id, bytes, success) {
    await db.run(
      "UPDATE transfer_events SET bytes=?,reserved=0,status=?,expires=0 WHERE id=?",
      bytes,
      success ? "complete" : "interrupted",
      id,
    );
  }
  async function inventoryStatus() {
    const row = await db.one(
      "SELECT status,snapshot,updated FROM provider_inventory WHERE id='account'",
    );
    return row
      ? {
          status: row.status,
          snapshot: row.snapshot ? JSON.parse(row.snapshot) : null,
          updated: row.updated,
        }
      : { status: "not_scanned", snapshot: null };
  }
  async function overview(user) {
    const tenants = await db.q(
      "SELECT * FROM tenants WHERE kind='client' OR (kind='internal' AND owner_email=?)",
      user.email,
    );
    const rows = await Promise.all(
      tenants.map(async (t) => {
        const files = await db.one(
          "SELECT COUNT(*) AS count,COALESCE(SUM(CASE WHEN status IN ('ready','trash','uploading','finishing','canceling') THEN size ELSE 0 END),0) AS used,COALESCE(SUM(CASE WHEN status='trash' THEN size ELSE 0 END),0) AS trash FROM files WHERE tenant=?",
          t.id,
        );
        const devices = await db.one(
          "SELECT COUNT(*) AS count FROM devices WHERE tenant=? AND revoked=0",
          t.id,
        );
        return {
          id: t.id,
          name: t.name,
          kind: t.kind,
          status: t.status,
          quota: t.quota,
          used: Number(files.used),
          trashBytes: Number(files.trash),
          fileCount: Number(files.count),
          deviceCount: Number(devices.count),
          storage: await workspaceStorage.view(t.id, true),
          meter: await transfers(t.id),
        };
      }),
    );
    const clients = rows.filter((t) => t.kind === "client");
    return {
      clients,
      internal: rows.filter((t) => t.kind === "internal"),
      totals: {
        clients: clients.length,
        used: clients.reduce((n, t) => n + t.used, 0),
        quota: clients.reduce((n, t) => n + t.quota, 0),
        files: clients.reduce((n, t) => n + t.fileCount, 0),
        uploadedBytes: clients.reduce((n, t) => n + t.meter.uploadedBytes, 0),
        downloadedBytes: clients.reduce(
          (n, t) => n + t.meter.downloadedBytes,
          0,
        ),
      },
      provider: await inventoryStatus(),
      period: period(),
      trackingSince: meterStart,
    };
  }
  async function refreshInventory() {
    if (demo) {
      const total = await db.one(
        "SELECT COALESCE(SUM(size),0) AS bytes,COUNT(*) AS versions FROM files WHERE status IN ('ready','trash')",
      );
      const snapshot = {
        bytes: Number(total.bytes),
        versions: Number(total.versions),
        buckets: [],
        capturedAt: new Date().toISOString(),
        synthetic: true,
        scope: "Synthetic managed workspace data",
      };
      await db.run(
        "INSERT INTO provider_inventory(id,status,snapshot,updated) VALUES('account','complete',?,?) ON CONFLICT(id) DO UPDATE SET status='complete',snapshot=excluded.snapshot,updated=excluded.updated",
        JSON.stringify(snapshot),
        snapshot.capturedAt,
      );
      return await inventoryStatus();
    }
    const key = encryptionKey(env),
      lease = randomBytes(24).toString("hex");
    let state;
    await db.transaction(async () => {
      await db.lock("provider-inventory");
      const row = await db.one(
        "SELECT * FROM provider_inventory WHERE id='account'",
      );
      need(
        !row || !row.lease_token || row.lease_until < Date.now(),
        409,
        "An inventory scan is already running",
      );
      state = row?.cursor
        ? openCredentials(row.cursor, key, "provider-inventory")
        : null;
      await db.run(
        "INSERT INTO provider_inventory(id,status,lease_token,lease_until,updated) VALUES('account','scanning',?,?,?) ON CONFLICT(id) DO UPDATE SET status='scanning',lease_token=excluded.lease_token,lease_until=excluded.lease_until",
        lease,
        Date.now() + 180000,
        new Date().toISOString(),
      );
    });
    try {
      const auth = await provider.checkProvisioning(env);
      if (!state) {
        const list = await provider.call(auth, "b2_list_buckets", {});
        state = {
          buckets: (list.buckets || []).map((b) => ({
            id: b.bucketId,
            name: b.bucketName,
            bytes: 0,
            versions: 0,
          })),
          index: 0,
          nextName: null,
          nextId: null,
          startedAt: new Date().toISOString(),
        };
      }
      for (
        let page = 0;
        page < 2 && state.index < state.buckets.length;
        page++
      ) {
        const bucket = state.buckets[state.index];
        const response = await provider.call(auth, "b2_list_file_versions", {
          bucketId: bucket.id,
          maxFileCount: 1000,
          ...(state.nextName
            ? { startFileName: state.nextName, startFileId: state.nextId }
            : {}),
        });
        need(
          Array.isArray(response.files),
          502,
          "Inventory response was incomplete",
        );
        for (const file of response.files)
          if (file.action === "upload") {
            need(
              Number.isSafeInteger(file.contentLength) &&
                file.contentLength >= 0,
              502,
              "Inventory size was invalid",
            );
            bucket.bytes += file.contentLength;
            bucket.versions++;
          }
        if (response.nextFileName) {
          need(
            response.nextFileName !== state.nextName ||
              response.nextFileId !== state.nextId,
            502,
            "Inventory cursor did not advance",
          );
          state.nextName = response.nextFileName;
          state.nextId = response.nextFileId;
        } else {
          state.index++;
          state.nextName = null;
          state.nextId = null;
        }
      }
      const done = state.index >= state.buckets.length,
        now = new Date().toISOString();
      const snapshot = done
        ? {
            bytes: state.buckets.reduce((n, b) => n + b.bytes, 0),
            versions: state.buckets.reduce((n, b) => n + b.versions, 0),
            buckets: state.buckets,
            startedAt: state.startedAt,
            capturedAt: now,
            scope: "All account buckets, completed object versions only",
            exclusions:
              "Unfinished multipart parts, billing byte-hours and transfer charges are not included",
          }
        : null;
      await db.run(
        "UPDATE provider_inventory SET status=?,cursor=?,snapshot=COALESCE(?,snapshot),lease_token=NULL,lease_until=0,updated=? WHERE id='account' AND lease_token=?",
        done ? "complete" : "scanning",
        done ? null : sealCredentials(state, key, "provider-inventory"),
        snapshot ? JSON.stringify(snapshot) : null,
        now,
        lease,
      );
      return await inventoryStatus();
    } catch (e) {
      await db.run(
        "UPDATE provider_inventory SET status='error',lease_token=NULL,lease_until=0,updated=? WHERE id='account' AND lease_token=?",
        new Date().toISOString(),
        lease,
      );
      throw e;
    }
  }
  return {
    settings,
    policy,
    plan,
    savePlan,
    overview,
    inventoryStatus,
    refreshInventory,
    recordUpload,
    reserveDownload,
    finishDownload,
  };
}
