# MSP console and client allowances

MSP settings is independent of the selected workspace. It opens the signed-in account's Clerk security profile, creates or opens one private MSP workspace, and edits default client terms. Workspace settings continues to manage the selected practice. Private workspaces use the existing dedicated-bucket provisioning flow, have server-assigned ownership, and are hidden from other MSP owners and practice members. Creating one can create a billable provider bucket; merely visiting settings does not provision anything.

The administrator Overview defaults to All clients, with a Selected workspace toggle. Client totals exclude private MSP storage; the private workspace is shown separately. Logical storage includes trash and unfinished upload reservations. It is not the provider's billable storage total.

Refresh inventory performs read-only account-wide bucket/version listing with the provisioning credential. It includes retained completed object versions in all visible buckets, including those outside the portal. It excludes unfinished multipart parts and is a point-in-time estimate, not monthly average storage or an invoice. Each request reads at most two pages; scans continue in bounded batches, retaining the previous completed snapshot. Cursor state is encrypted with the existing STORAGE_CREDENTIAL_ENCRYPTION_KEY; never rotate that key without migrating ciphertext. Bucket names are administrator-only. No customer filenames appear in inventory responses.

## Client plans

Plan & usage shows each client's storage allowance, actual supported per-file limit and monthly portal traffic. Default download allowances and prices begin unpublished. MSPs can publish default terms or a workspace override: monthly downloads, notice or hard-block behavior, USD download overage per decimal GB, additional monthly storage per decimal TB, and other services. A hard block requires an explicit allowance. Private MSP workspaces do not inherit client billing terms. Saving or publishing terms does not create invoices or charge cards. Operational support, retention and migration fees require an agreement and separate billing.

Traffic tracking begins when this release first starts, using UTC calendar months. Upload traffic includes received retries and rejected part checksums. Download traffic counts bytes passed through the portal's streaming meter, including ranges and retries; it is not proof of receipt. Concurrent hard limits reserve planned download bytes transactionally before provider access. Reservations expire after one hour if a worker never finalizes; a later attempt releases them. Crashes can leave actual bytes undercounted. Direct provider traffic, failed proxy paths, hosting overhead and API charges require separate billing reconciliation. This meter is for service visibility and controls, not authoritative invoicing.

## Pilot transfer boundary

Vercel and development previews currently enforce **4 MiB per file**, below Vercel's 4.5 MB request-body limit. The browser and API both enforce and display it. Large imaging files are not ready for production acceptance. A supported large-file transfer route, resumability and representative machine/uploader testing are required before removing the cap. The storage allowance remains 4 decimal TB per practice; capacity and per-file transfer limits are different.

## Supplier costs (verified November 19, 2026)

Backblaze lists storage starting at $6.95/TB/month. Four TB actually stored is about $27.80/month before other charges; allocating a 4 TB portal quota does not prepay capacity. Free egress is generally three times monthly average account storage, then $0.01/GB. This is an account-wide supplier policy, not a separate fixed entitlement per client. Provider versions and incomplete uploads may cost storage, and hosting adds its own charges. Review the current pricing and account terms before publishing client rates.

- [Backblaze pricing](https://www.backblaze.com/cloud-storage/pricing)
- [Vercel function limits](https://vercel.com/docs/functions/limitations)

Migration 002 is transactional and preserves existing workspace identities and file storage bindings. No new environment variables are required beyond the existing database, encryption and provisioning credentials. HIPAA readiness gates and outstanding BAA, restore, monitoring and transfer acceptance requirements continue to apply.
