import {
  S3Client,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  ListPartsCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

// Every operation gets its key from a server-owned tenant/file record, never a caller-supplied bucket or prefix.
export class CloudStorage {
  constructor(env) {
    this.bucket = env.STORAGE_BUCKET;
    this.client = new S3Client({
      endpoint: env.STORAGE_ENDPOINT,
      region: env.STORAGE_REGION,
      forcePathStyle: true,
      requestChecksumCalculation: "WHEN_REQUIRED",
      responseChecksumValidation: "WHEN_REQUIRED",
      credentials: {
        accessKeyId: env.STORAGE_KEY_ID,
        secretAccessKey: env.STORAGE_APPLICATION_KEY,
      },
    });
  }
  transport = "direct";
  async signPart(key, uploadId, number, size, md5) {
    const url = await getSignedUrl(
      this.client,
      new UploadPartCommand({
        Bucket: this.bucket,
        Key: key,
        UploadId: uploadId,
        PartNumber: number,
        ContentLength: size,
        ContentMD5: md5,
      }),
      {
        expiresIn: 300,
        signableHeaders: new Set(["content-length", "content-md5"]),
      },
    );
    return { url, headers: { "Content-MD5": md5 }, expiresIn: 300 };
  }
  async listParts(key, uploadId, number) {
    const parts = [];
    let marker = number ? number - 1 : undefined;
    do {
      const r = await this.client.send(
        new ListPartsCommand({
          Bucket: this.bucket,
          Key: key,
          UploadId: uploadId,
          PartNumberMarker: marker,
          MaxParts: number ? 1 : 1000,
        }),
      );
      parts.push(
        ...(r.Parts || []).map((p) => ({
          number: p.PartNumber,
          size: p.Size,
          etag: p.ETag,
        })),
      );
      if (number || !r.IsTruncated) break;
      if (!r.NextPartNumberMarker || r.NextPartNumberMarker === marker)
        throw Error("Storage part cursor did not advance");
      marker = r.NextPartNumberMarker;
    } while (parts.length <= 10000);
    return parts;
  }
  async signDownload(key, version, name) {
    return {
      url: await getSignedUrl(
        this.client,
        new GetObjectCommand({
          Bucket: this.bucket,
          Key: key,
          ...(version ? { VersionId: version } : {}),
          ResponseContentDisposition: `attachment; filename="download"; filename*=UTF-8''${encodeURIComponent(name).replace(/'/g, "%27")}`,
        }),
        { expiresIn: 60 },
      ),
      expiresIn: 60,
    };
  }
  async start(key) {
    return (
      await this.client.send(
        new CreateMultipartUploadCommand({
          Bucket: this.bucket,
          Key: key,
          ContentType: "application/octet-stream",
          ServerSideEncryption: "AES256",
        }),
      )
    ).UploadId;
  }
  async part(key, uploadId, number, bytes) {
    return (
      await this.client.send(
        new UploadPartCommand({
          Bucket: this.bucket,
          Key: key,
          UploadId: uploadId,
          PartNumber: number,
          Body: bytes,
          ContentLength: bytes.length,
        }),
      )
    ).ETag;
  }
  async complete(key, uploadId, parts) {
    const r = await this.client.send(
      new CompleteMultipartUploadCommand({
        Bucket: this.bucket,
        Key: key,
        UploadId: uploadId,
        MultipartUpload: {
          Parts: parts.map((p) => ({ PartNumber: p.number, ETag: p.etag })),
        },
      }),
    );
    return r.VersionId || "";
  }
  async head(key, version) {
    const r = await this.client.send(
      new HeadObjectCommand({
        Bucket: this.bucket,
        Key: key,
        ...(version ? { VersionId: version } : {}),
      }),
    );
    return { size: r.ContentLength };
  }
  async abort(key, uploadId) {
    await this.client.send(
      new AbortMultipartUploadCommand({
        Bucket: this.bucket,
        Key: key,
        UploadId: uploadId,
      }),
    );
  }
  async get(key, version, range) {
    const r = await this.client.send(
      new GetObjectCommand({
        Bucket: this.bucket,
        Key: key,
        ...(version ? { VersionId: version } : {}),
        ...(range ? { Range: range } : {}),
      }),
    );
    return { body: r.Body, length: r.ContentLength, range: r.ContentRange };
  }
  async put(key, bytes) {
    await this.client.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: bytes,
        ServerSideEncryption: "AES256",
        ContentType: "application/json",
      }),
    );
  }
}

// Local mode is deliberately bound to loopback and rejects production mode.
export class LocalStorage {
  constructor(dir) {
    this.dir = dir;
    this.parts = new Map();
  }
  path(key) {
    return join(this.dir, createHash("sha256").update(key).digest("hex"));
  }
  async start(key) {
    await mkdir(this.dir, { recursive: true });
    this.parts.set(key, new Map());
    return key;
  }
  async part(key, id, n, bytes) {
    this.parts.get(key).set(n, Buffer.from(bytes));
    return createHash("md5").update(bytes).digest("hex");
  }
  async complete(key, id, parts) {
    await writeFile(
      this.path(key),
      Buffer.concat(parts.map((p) => this.parts.get(key).get(p.number))),
    );
    this.parts.delete(key);
    return "";
  }
  async head(key) {
    return { size: (await readFile(this.path(key))).length };
  }
  async abort(key) {
    this.parts.delete(key);
  }
  async get(key, version, range) {
    let b = await readFile(this.path(key));
    const total = b.length;
    let contentRange;
    if (range) {
      const m = /^bytes=(\d+)-(\d*)$/.exec(range);
      if (!m) throw Error("range");
      const start = Number(m[1]),
        end = m[2] ? Math.min(Number(m[2]), total - 1) : total - 1;
      if (start >= total || end < start) throw Error("range");
      b = b.subarray(start, end + 1);
      contentRange = `bytes ${start}-${end}/${total}`;
    }
    const { Readable } = await import("node:stream");
    return { body: Readable.from(b), length: b.length, range: contentRange };
  }
  async put(key, bytes) {
    await mkdir(this.dir, { recursive: true });
    await writeFile(this.path(key), bytes);
  }
}
