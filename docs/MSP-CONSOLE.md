# MSP console and client allowances

MSP settings is independent of the selected workspace. It opens the signed-in account's Clerk security profile, creates or opens one private MSP workspace, and edits default client terms. Workspace settings continues to manage the selected practice. Private workspaces use the existing dedicated-bucket provisioning flow, have server-assigned ownership, and are hidden from other MSP owners and practice members. Creating one can create a billable provider bucket; merely visiting settings does not provision anything.

The administrator Overview defaults to All clients, with a Selected workspace toggle. Client totals exclude private MSP storage; the private workspace is shown separately. Logical storage includes trash and unfinished upload reservations. It is not the provider's billable storage total.

Refresh inventory performs read-only account-wide bucket/version listing with the provisioning credential. It includes retained completed object versions in all visible buckets, including those outside the portal. It excludes unfinished multipart parts and is a point-in-time estimate, not monthly average storage or an invoice. Each request reads at most two pages; scans continue in bounded batches, retaining the previous completed snapshot. Cursor state is encrypted with the existing STORAGE_CREDENTIAL_ENCRYPTION_KEY; never rotate that key without migrating ciphertext. Bucket names are administrator-only. No customer filenames appear in inventory responses.

## Client plans

Plan & usage shows each client's storage allowance, actual supported per-file limit and monthly portal traffic. Default download allowances and prices begin unpublished. MSPs can publish default terms or a workspace override: monthly downloads, notice or hard-block behavior, USD download overage per decimal GB, additional monthly storage per decimal TB, and other services. A hard block requires an explicit allowance. Private MSP workspaces do not inherit client billing terms. Saving or publishing terms does not create invoices or charge cards. Operational support, retention and migration fees require an agreement and separate billing.

Traffic tracking begins when the meter release first starts, using UTC calendar months. Proxy uploads count received bytes; direct uploads count confirmed provider parts once, excluding retry traffic. Proxy downloads count streamed bytes, while direct downloads count the full file when a link is authorized, even if unused. Short-lived links can be reused before expiry. Hard limits govern new download authorizations, not exact traffic. Failed or repeated direct traffic and activity outside the portal require provider billing reconciliation. This meter is for visibility and service controls, not authoritative invoicing.

## Large-file transfer boundary

The configured cap is now **50 GiB per file**, with 16 MiB multipart parts. Cloud uploads and downloads bypass Vercel file-body limits through narrowly scoped signed links. The storage allowance remains 4 decimal TB per practice. See [Large transfers](LARGE-TRANSFERS.md) for origin setup, security boundaries, uploader updates and live acceptance requirements.

## Supplier costs (verified November 19, 2026)

Backblaze lists storage starting at $6.95/TB/month. Four TB actually stored is about $27.80/month before other charges; allocating a 4 TB portal quota does not prepay capacity. Free egress is generally three times monthly average account storage, then $0.01/GB. This is an account-wide supplier policy, not a separate fixed entitlement per client. Provider versions and incomplete uploads may cost storage, and hosting adds its own charges. Review the current pricing and account terms before publishing client rates.

- [Backblaze pricing](https://www.backblaze.com/cloud-storage/pricing)
- [Vercel function limits](https://vercel.com/docs/functions/limitations)

Migrations 002 and 003 are transactional and preserves existing workspace identities and file storage bindings. No new environment variables are required beyond the existing database, encryption and provisioning credentials. HIPAA readiness gates and outstanding BAA, restore, monitoring and transfer acceptance requirements continue to apply.
