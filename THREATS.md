# THREATS.md

How I think TrustVault can be broken, what I did about each, and what I knowingly left open.
Test ids (T-, R-, A-) point at the automated test that fails if the defence is removed.
I ran mutation checks: I removed each authorisation check in turn and confirmed at least one test fails (results at the bottom, including the three I could not kill and why).

Status: **Closed** = defended and tested. **Reduced** = partly defended. **Accepted** = I know, and here is why.

---

## 1. Reaching a document you were not granted

| # | Attack | What I did | Status | Test |
|---|---|---|---|---|
| 1.1 | Call the API directly; hidden buttons mean nothing | The UI is a convenience. One function, `permission.service.decide()`, is the only place access is computed, and it runs on every request against the database. | Closed | T-02 |
| 1.2 | A route where I forgot the check ("a route you did not think of") | Two structural defaults. (a) `app.js` authenticates and CSRF-checks every `/api` route unless it is in an explicit `PUBLIC` set of one. (b) The app **refuses to boot** if any route with a document `:id` lacks an `authorizeDocument()` guard. A new endpoint without a check is a startup failure, not a hole. | Closed | T-01 enumerates every registered route unauthenticated |
| 1.3 | IDOR: change the id in the URL | UUIDv4 ids (not guessable) **and** ownership/grant checked per request. Ids are validated by format before any query. | Closed | T-02, T-09 |
| 1.4 | Learn that a document exists from "403 vs 404" | Someone with no access gets the same 404 body as for an id that does not exist. 403 is only returned to someone who can already see the document. | Closed | T-02b |
| 1.5 | Search/filter leak: list, count or match titles of others' documents | The access predicate is part of the SQL `WHERE` in every search; filters are `AND`-ed after it and can only narrow. Search tested with `%`, owner, category, scope, trash. | Closed | T-03, T-18 |
| 1.6 | Admin as a backdoor | Admin has **no** implicit content access. Admin sees metadata (`/api/admin/documents`) and the audit, nothing that returns bytes or storage keys. Separation of duties: whoever manages accounts cannot also read salary letters. | Closed (by design) | T-04 |
| 1.7 | Role/grant escalation: a viewer with an `edit` grant | Roles are a ceiling. Viewer can never exceed read, enforced in `resolve()` even if an `edit` row is forced into the database, and at grant time. | Closed | T-07 |
| 1.8 | Mass assignment (`owner_id`, `role` in a body) | Handlers read named fields only; nothing is spread into a query. | Closed | T-10 |
| 1.9 | Reach a file on disk | Stored under random 192-bit names, outside the web root, `0600`, and the static server is an allow-list built at startup (there is no path to traverse). Encrypted at rest (AES-256-GCM). | Closed | T-11 |
| 1.10 | Old versions: grant someone today, they read what the owner removed yesterday | Non-owners get the **current version only**; earlier versions are owner-only. | Closed | T-08 |
| 1.11 | Read from the trash | A deleted document is invisible to everyone, including its owner, except for restore. Nobody has content access while it is in the trash. | Closed | R-11 |
| 1.12 | Suggestions as a side door to access | A suggestion is a row that grants nothing. The only path to a grant is the owner's explicit `PUT`. Accepting is bound to that document, that person and level `read`, and cannot be replayed. | Closed | A-13 |
| 1.13 | Enumerating people through the sharing directory | Owners only, 2+ character query, max 10 results, enabled non-admin accounts, id/email/name/role only. | **Accepted**: any owner can enumerate employees. Internal product; the alternative is typing exact emails. |  T-19 |

## 2. Taking access away

| # | Attack | What I did | Status | Test |
|---|---|---|---|---|
| 2.1 | "Their link still works" | There are no links, signed URLs, share tokens or cached grants. Every request re-reads the grant row. Nothing was *issued* that can outlive a revocation. The cost: one indexed query per request, and no offline/CDN delivery. | Closed | R-01, R-02 |
| 2.2 | Their session keeps working after being disabled or after a password change | Sessions are rows, not JWTs. Disabling deletes them and revokes every grant they held; a password change signs out every other device. | Closed | R-07, R-08, R-15 |
| 2.3 | Revoke lands while a slow upload/grant is in flight | The guard runs when the request starts **and again inside the write transaction**, which also re-validates the session. A request authorised at the door but written after revocation is refused, its encrypted blob removed. | Closed | R-06, R-14 |
| 2.4 | Grant outlives its purpose | Optional expiry, evaluated live (no sweeper to be late). Must be in the future and ≤ 1 year. | Closed | R-04, R-05 |
| 2.5 | Stolen cookie after logout | Logout deletes the server-side row. Idle (30 min) and absolute (12 h) limits are server-side. | Closed | R-09, R-10 |
| 2.6 | Bytes already in flight / already downloaded | **Accepted.** Once a person has downloaded a file, no system can take it back. Revocation stops the next request, not a copy. The audit shows who had it (A-01) so the owner can judge the exposure. |
| 2.7 | Demoting a role while someone holds documents | Role change ends their sessions; owners with live documents cannot be made viewers; the last active admin cannot be demoted/disabled. | Closed | R-13 |

## 3. Proving who reached it (audit)

| # | Attack | What I did | Status | Test |
|---|---|---|---|---|
| 3.1 | Quietly edit or delete a row | Rows are chained with HMAC-SHA256 under a key the database does not hold. Editing, inserting or removing a row breaks the chain. SQL triggers also reject `UPDATE`/`DELETE` from the app's own connection. | Closed | A-04, A-06 |
| 3.2 | Drop the triggers and recompute the hashes | Needs the HMAC key (a plain SHA-256 recomputation is detected). Missing triggers are themselves reported by `verify`. | Closed vs DB-only attacker | A-06, A-07 |
| 3.3 | Delete the **tail** (a chain cannot see that) | Every commit also appends `seq hash` to a separate anchor file; verification fails if an anchored event is missing. | **Reduced.** An attacker who owns the host and the anchor file *and* the key can rewrite everything. Fix is operational: ship the anchor to storage the app cannot rewrite (WORM bucket / remote syslog). I did not build the shipper. | A-08 |
| 3.4 | A change happens but is not recorded | Success events are written in the **same transaction** as the change. Downloads are recorded **before** the first byte is sent; if the record cannot be written, nothing is sent. | Closed | A-03 |
| 3.5 | Refused attempts disappear | Denials are written on their own, outside any rolled-back transaction: wrong user, wrong level, unknown id, expired/revoked grant (with the reason), no session, wrong role, CSRF failures, rejected uploads, failed logins. | Closed | A-02 |
| 3.6 | Secrets in the log | Passwords, hashes and storage keys are never logged; test greps the dump. | Closed | A-09 |
| 3.7 | Someone reads the log and nobody knows | Viewing and verifying the audit are themselves audited. | Closed | A-10 |
| 3.8 | A user deleted later makes old rows unreadable | Rows snapshot actor email and id; no foreign key to users. | Closed | |
| 3.9 | Log flooding (many refusals to bloat the DB / bury real events) | Per-IP rate limit (600/min) and a 10 MB body cap. | **Accepted** that a patient attacker can still add rows; each costs them a request and flags them in the alerts. No log rotation/archival built. |
| 3.10 | Audit gap: probing with a malformed id | A malformed id gets 400 and is not logged (only well-formed ids are). | **Accepted**: low value; the rate limiter still sees it. |
| 3.11 | "Download" logged but the client aborted | Logged as a download. I record the attempt that was served, which is the conservative reading for a leak investigation. | Accepted |

## 4. Authentication and sessions

| # | Attack | What I did | Status | Test |
|---|---|---|---|---|
| 4.1 | Brute force / credential stuffing | scrypt (N=32768); per-IP login rate limit; per-account lockout (5 failures → 15 min). | Reduced | T-17 |
| 4.2 | Account enumeration | Identical 401 body for unknown user, wrong password, locked, disabled; the same hashing work is done either way. The precise reason is only in the audit. | Closed | T-17 |
| 4.3 | Lockout as a denial of service against a named person | **Accepted.** An attacker can lock an account for 15 minutes. I chose it over allowing unlimited guessing; per-IP limiting would not stop a distributed attempt. |
| 4.4 | CSRF | `SameSite=Strict` HttpOnly cookie, **plus** a per-session token required on every non-GET, **plus** `Origin` must match `Host`. JSON/octet-stream only. | Closed | T-15 |
| 4.5 | Session fixation | A fresh random 256-bit token at every login; stored only as a hash. | Closed | |
| 4.6 | XSS | Strict CSP (`default-src 'none'; script-src 'self'; style-src 'self'`, no inline anything); the UI builds the DOM with `textContent` only (a title of `<b>x</b>` renders literally, checked in a real browser). | Closed. A residual: the CSRF token lives in `sessionStorage`, readable by script; but script injection is already game-over, and the CSP is the defence. | T-16 |
| 4.7 | Cookie sent over HTTP | `Secure` + `__Host-` prefix + HSTS when `COOKIE_SECURE=1`. **You must set it behind TLS.** | **Accepted by config**: off by default so it runs on localhost. |
| 4.8 | Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY`. | Closed | T-16 |
| 4.9 | Weak passwords | ≥12 chars, ≤128, not a trivial list, not containing the email name. | Reduced |  |
| 4.10 | No MFA, no password reset, no email | **Not built.** Reset needs email infrastructure, which is a larger attack surface than this scope can defend; admin creates accounts. MFA is the first thing I would add. | Accepted |
| 4.11 | Unicode look-alike emails (`аlice@…`) | Email uniqueness is case-insensitive ASCII only. | **Accepted**; accounts are admin-created, so the admin is the check. |
| 4.12 | `X-Forwarded-For` spoofing to dodge limits/falsify audit IPs | Ignored unless `TRUST_PROXY=1`, and then only the last hop is used. | Closed (when configured) | |

## 5. Uploads

| # | Attack | What I did | Status | Test |
|---|---|---|---|---|
| 5.1 | Executable/HTML/SVG disguised as a document | Allow-list of extensions; the **content** must match (magic bytes; Office files must be zip with the right parts; text must be valid UTF-8 with no NUL). Extension and content must agree. | Closed | T-13 |
| 5.2 | Stored XSS through a downloaded file | Served only as `attachment`, with the type **we verified** (never the client's), `nosniff`, and `Content-Security-Policy: sandbox`. | Closed | T-14 |
| 5.3 | Macros / PDF scripts | `.docm`/`vbaProject.bin` refused; PDFs with `/JavaScript`, `/JS`, `/Launch`, `/EmbeddedFile` refused. | **Reduced**: pattern-based, can be evaded by obfuscated PDFs (names can be hex-escaped). No antivirus. A real deployment needs a scanner or content disarm. | T-13 |
| 5.4 | CSV/Excel formula injection | **Accepted.** Files are stored byte-for-byte; a `=cmd` cell in an uploaded CSV will run when someone opens it in Excel. Fixing means altering the owner's data. |
| 5.5 | Oversized bodies / slowloris | `Content-Length` checked up front and bytes counted as they stream (chunked too); header/request timeouts; per-user upload rate. | Closed | T-13 |
| 5.6 | Zip bombs, image parser exploits | Nothing is ever decompressed or parsed server-side. | Closed (by design) | |
| 5.7 | Filename tricks (`../`, bidi override, control chars, header injection) | Basename only; control and bidi characters stripped; stored under a random key; disposition header built with ASCII fallback + `filename*`. | Closed | T-13 |
| 5.8 | Ciphertext tampered with or swapped between records | AES-GCM with a per-file key derived from the random file name (HKDF) and the name as AAD, plus a SHA-256 of plaintext. A failure is refused and written as `integrity_failure` (a critical alert). | Closed | T-12, T-20 |

## 6. Everything else

| # | Attack | What I did | Status |
|---|---|---|---|
| 6.1 | SQL injection | Parameters everywhere, `LIKE` wildcards escaped; the filters are tested with injection strings. (A-11) | Closed |
| 6.2 | Verb tunnelling / wrong method | Strict method matching, 405 otherwise. | Closed |
| 6.3 | Prototype pollution | Bodies are `JSON.parse`d and only named fields are read; no deep merge. | Closed |
| 6.4 | Secrets in the repo | `.env` is git-ignored; startup **fails** without both keys (no defaults); the two keys must differ. | Closed |
| 6.5 | Database/file permissions | Data dir `0700`, DB and files `0600`. | Closed |
| 6.6 | Lost `FILE_ENC_KEY` | **Accepted**, with the cost spelled out: every document is unrecoverable. `npm run init` refuses to overwrite an existing `.env`. Key rotation is not built. |
| 6.7 | Host compromise (root on the box) | **Accepted.** Keys sit in `.env` next to the data; an attacker with the host reads documents. A KMS/HSM and separate audit host is the production answer. |
| 6.8 | Single process | **Accepted.** SQLite + in-memory rate limiter ⇒ one instance. Transactions are synchronous so a request cannot interleave into another's write. |
| 6.9 | A malicious *owner* forwards what they were rightly given | **Cannot be prevented by software.** Mitigations: everything is attributable, per-document audit, expiry. |
| 6.10 | Admin tampering with accounts (e.g. creating an account for themselves) | They can create an *account*, but cannot grant themselves *documents*: only an owner can. It is recorded (`user_created`). |
| 6.13 | Self-registering as administrator | Allowed only with the server-side `ADMIN_REGISTRATION_CODE` (≥12 chars, constant-time compared); disabled when unset; failures audited. Admins still have no content access (1.6). | Closed | R-16 |
| 6.11 | Admin sees titles and filenames | **Accepted**: metadata is how an admin does their job, but a title like "Redundancy plan" is itself sensitive. |
| 6.12 | Backups | **Not handled.** Backups of the DB and `private_uploads` hold encrypted data, but the audit chain must be backed up with its anchor. |
| 6.13 | Time-of-check/time-of-use between auth and decrypt | Single synchronous section; the bytes are sent only after the final check. |

---

## What I chose not to build (and why)

- **External sharing / guest links.** The classic way "a file meant for one client is visible to another". A link is a bearer token and is exactly what "revoke immediately" fights. The safe design is a guest *account* with the `viewer` role, which already works.
- **Groups and folder inheritance.** They are how "access to a folder so they can see one file, and now see forty" happens. I chose per-document grants only: more clicks, but you can always answer "who can open this?" from one table.
- **An LLM in the product.** The suggester is a deterministic rule ("shares similar documents with you"), so the demonstration is of the boundary: suggest, a person decides, both audited. Swapping in a model changes nothing about what it can do (nothing).
- **MFA, password reset, SSO.** See 4.10.
- **Antivirus, DLP, watermarking.** See 5.3.

## Mutation check

For each check below I removed it from a copy of the source and ran the suite:
`decide()` always-allow · level ranking · search access predicate (dropped; and grant branch dropped) · old-version owner rule · in-transaction re-check on upload and on grant · role gates · CSRF · Origin · session expiry · disable→kill sessions · disable→revoke grants · password change→kill sessions · logout deletion · viewer ceiling · trash hiding · magic bytes · extension allow-list · "audit before send" · denial audit · HMAC coverage · triggers · anchor comparison · expiry validation · suggestion level · upload role gate · lockout.

**Killed by a test:** all of these. The first run left seven alive, which showed real gaps, and I added tests for them: *a grantee is never shown the document in search* (a bug that would hide shared documents, not leak them, but untested), *the sharing directory is owner-only*, *a revocation mid-grant*, *suggestions cannot be widened on acceptance* (hidden behind the role ceiling until I used an owner-role target), *ciphertext swap*.

**Survivors I did not kill, and why:**
1. *Disabling a user deletes their sessions.* Redundant: `lookup()` also rejects disabled users, so the removal does not change behaviour. R-15 asserts the rows are gone, but a mutation of the whole block is covered by the second layer.
2. *The SHA-256 check in `storage.read`.* Redundant with the GCM tag, which already rejects any change. Kept as a second layer.
3. *"Last admin" guard on disabling.* Unreachable: the actor must be an active admin and cannot disable themselves, so the target can never be the last one. Kept as defence in depth for when a second code path appears.
