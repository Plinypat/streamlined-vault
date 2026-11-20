const need = (value, status, message) => {
  if (!value) throw Object.assign(Error(message), { status });
};
export function createDirectTransfers({
  db,
  workspaceStorage,
  mspConsole,
  partSize,
  audit,
}) {
  async function part(file, number, action, input) {
    need(file.status === "uploading", 409, "Upload is completing");
    const count = Math.ceil(file.size / partSize),
      size = number === count ? file.size - (number - 1) * partSize : partSize;
    need(
      Number.isInteger(number) && number >= 1 && number <= count,
      400,
      "Invalid part number",
    );
    const storage = await workspaceStorage.forFile(file);
    need(
      storage.transport === "direct",
      400,
      "This upload uses the portal transfer route",
    );
    if (action === "sign") {
      need(
        typeof input?.md5 === "string" &&
          /^[A-Za-z0-9+/]{22}==$/.test(input.md5),
        400,
        "A valid part checksum is required",
      );
      const prior = await db.one(
        "SELECT * FROM upload_part_grants WHERE file=? AND number=?",
        file.id,
        number,
      );
      need(
        !prior || (prior.md5 === input.md5 && Number(prior.size) === size),
        409,
        "This part belongs to different content; cancel and restart the upload",
      );
      await db.run(
        "INSERT INTO upload_part_grants(file,number,md5,size) VALUES(?,?,?,?) ON CONFLICT(file,number) DO NOTHING",
        file.id,
        number,
        input.md5,
        size,
      );
      return {
        ...(await storage.signPart(
          file.key,
          file.upload,
          number,
          size,
          input.md5,
        )),
        size,
      };
    }
    const grant = await db.one(
      "SELECT * FROM upload_part_grants WHERE file=? AND number=?",
      file.id,
      number,
    );
    need(grant, 409, "Request an upload link before confirming this part");
    const [stored] = await storage.listParts(file.key, file.upload, number);
    need(
      stored?.number === number && stored.size === size && stored.etag,
      409,
      "Stored part is missing or its size does not match",
    );
    await db.run(
      "INSERT INTO parts VALUES(?,?,?,?) ON CONFLICT(file,number) DO UPDATE SET etag=excluded.etag,size=excluded.size",
      file.id,
      number,
      stored.etag,
      size,
    );
    if (!grant.acknowledged) {
      await mspConsole.recordUpload(file.tenant, size);
      await db.run(
        "UPDATE upload_part_grants SET acknowledged=1 WHERE file=? AND number=?",
        file.id,
        number,
      );
    }
    return { number, received: size };
  }
  async function verify(file, parts) {
    const storage = await workspaceStorage.forFile(file);
    if (storage.transport !== "direct") return;
    const actual = await storage.listParts(file.key, file.upload);
    need(
      actual.length === parts.length &&
        actual.every(
          (p, i) =>
            p.number === parts[i].number &&
            p.size === Number(parts[i].size) &&
            p.etag === parts[i].etag,
        ),
      409,
      "Stored parts changed; verify and retry the transfer",
    );
  }
  async function download(file, actor) {
    const storage = await workspaceStorage.forFile(file);
    need(
      storage.transport === "direct",
      400,
      "This file uses the portal download route",
    );
    const reservation = await mspConsole.reserveDownload(
      file.tenant,
      Number(file.size),
    );
    try {
      const link = await storage.signDownload(
        file.key,
        file.version,
        "streamlined-vault-" +
          file.id +
          ((/\.(dcm|jpg|jpeg|png|tif|tiff|pdf|zip|bin|json|xml|csv|xlsx|docx)$/i.exec(
            file.name,
          ) || [])[0] || ".bin"),
      );
      await audit(
        file.tenant,
        actor,
        "Short-lived download authorized",
        file.id,
      );
      // Reserve a whole file on link issuance. Links are reusable until expiry;
      // actual direct traffic requires provider billing reconciliation.
      await mspConsole.finishDownload(reservation, Number(file.size), true);
      return link;
    } catch (e) {
      await mspConsole.finishDownload(reservation, 0, false);
      throw e;
    }
  }
  return { part, verify, download };
}
