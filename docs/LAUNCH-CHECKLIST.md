# Completion evidence - November 23, 2026

Completed automatically or verified in this session:
- Reproduced the provider inventory failure: file-version listing rejected an unexpected accountId parameter with HTTP 400. Removing only that parameter returned HTTP 200. Added a regression test preserving account parameters on account-level operations.
- Ran a full inventory using the corrected application service and the production database, through the locally authorized provider account. Completed four buckets with aggregate sizes only; no object names were printed.
- Added explicit provider/technical launch states and clearer administrator/client activation messages. Existing file-operation approval guards remain enforced.
- High-severity alert acknowledgment no longer bypasses readiness. Explicit resolution requires a fix-and-test reference; recurrence reopens the incident.
- Prepared an x64 Windows pilot installer with a SHA-256-verified Python 3.14.10 runtime from python.org, one-time enrollment over stdin, Windows-protected credentials, a SYSTEM startup task and synthetic-file checksums. The installer build is a pilot artifact without an Authenticode publisher signature. It is not installed or enrolled on the development computer.

Remaining operator/practice evidence:
- Bitwarden account created by the operator. Enable MFA, store the private recovery key, and test decryption using a copy retrieved from that vault. Retain a separately secured offline recovery copy. Do not record key custody until this passes.
- Finish independent portal monitoring: third Healthchecks check, GitHub HEALTHCHECKS_PORTAL_URL secret, test and scheduled workflow success, and actual missed-heartbeat/failure/recovery emails on a disposable check.
- Run live Clerk MFA enrollment, recovery and revocation with patrickdenatale@gmail.com; preserve the primary MSP administrator. Test all practice roles and membership removal with synthetic data.
- Confirm the practice computer's encryption, updates, local time and approved export source. Run the installer on Sorski's computer, then validate two actual nightly runs at 21:00 local time plus restore/restart/resume tests.
- Review the user-reported completed provider agreements/account approvals against their actual documents or dashboards. Record each confirmed flag only after that review. Source locations have not yet been supplied.
- The previously shared database-owner password was rotated on November 23 and the new owner connection verified. The protected .env.owner file was replaced; runtime credentials and the storage-encryption key were unchanged and production health passed. Complete review of the remaining provider credentials before recording the overall credential-review gate.
- Record final activation only after current technical checks, provider approvals and the actual practice pilot pass. Review evidence expires after 30 days.

See SORSKI-PILOT.md for the on-site workflow. Record real results, not intended results. A completed package build is not a live practice pilot.

Independent availability workflow logs confirm failure because HEALTHCHECKS_PORTAL_URL is missing from GitHub Actions secrets. The two Vercel monitor URLs do not satisfy this third independent monitor. Connected Drive searches located client agreement drafts but no matching completed storage/hosting/identity/database provider approval records; those activation flags remain unchanged pending evidence.
