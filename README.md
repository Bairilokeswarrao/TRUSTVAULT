# TrustVault

Confidential document sharing where **the server decides every access** and **every access, including refused ones, is on a tamper-evident record**.

Zero third-party dependencies: Node 22 (`node:http`, `node:sqlite`, `node:crypto`). Nothing to install, nothing to patch.

## Run it

```bash
cd backend
npm run init     # writes .env with two random keys (never overwrites)
npm run seed     # admin + demo owners/viewer, random passwords printed ONCE
npm start        # http://127.0.0.1:3000
npm test         # 49 tests, ~4 s
```

Behind TLS set `COOKIE_SECURE=1` (Secure/`__Host-` cookie + HSTS); behind a proxy you control set `TRUST_PROXY=1`.
Seeded demo accounts are for evaluation. Use `npm run seed -- --admin-only` for a real deployment.

## Motion layer (animated UI)

The whole front end uses a "lamp login" animation style: a pull-cord lamp that switches on, a cone of warm light, drifting fireflies, and content that fades into the light.

* `frontend/css/animations.css`: all keyframes and animated states. Every rule is gated on `html.fx`, so the site still works without JS.
* `frontend/js/fx.js`: fireflies, staggered entrances, count-up numbers, button ripples, page-leave transition, the login lamp.
* Login: the lamp lights after about a second; click the cord (or tab into the form) to toggle it. A wrong password shakes the card.
* App pages (Dashboard, Documents, Sharing, Administration): same dark amber "lamp-lit room" theme as the sign-in screen, whatever the OS theme. A pendant lamp hangs from the top bar, flickers on after load and casts a cone of light over the page; click it to switch it off/on (remembered in this browser). Top bar slides in, nav underline draws, cards/tables/alerts stagger in, stat numbers count up, fireflies drift.
* Respects `prefers-reduced-motion` (everything lands in its final state, no movement).
* CSP-safe: external same-origin files only, no inline styles or scripts, no new asset types. The static server needed no change.

## Roles (what each can do)

| | admin | owner | viewer |
|---|---|---|---|
| Upload documents | no | **yes** | no |
| Open a document | only if an owner granted it | own + granted | granted, **read only** |
| Grant / revoke / delete / restore | no | own documents | no |
| See the global audit, verify its integrity, alerts | **yes** | no | no |
| See the audit of one document | no | own documents | no |
| Create / disable accounts, change roles | **yes** | no | no |
| Metadata list of all documents (no content) | **yes** | no | no |

**Registering as administrator.** The sign-up form offers *Administrator*, but it only works when the server operator sets `ADMIN_REGISTRATION_CODE` (12+ characters, in `backend/.env`) and the registrant enters it. With no code set, admin sign-up is disabled. Wrong codes are refused (403) and audited (`access_denied`, reason `admin_registration`). Owners and viewers still need no code.

An administrator deliberately cannot read content: the person who manages accounts and reads the audit is not the person who reads your salary letter.

## Permission model

Per-document grants. One table (`grants`), two levels, granted to named people, owner-only, optional expiry.

* **read**: see metadata, download the *current* version
* **edit**: read + upload a new version, rename/recategorise
* **owner** (implicit, the uploader): all of the above + share, revoke, delete, restore, read the document's audit
* Roles are a **ceiling**: a viewer account can never exceed read, even if a bad row exists.

Computed in one place (`services/permission.service.js`) on every request. Nothing is cached or signed, so there is nothing to outlive a revocation. Revoking costs one indexed read per request; that is the price of "immediately".

## How a document is stored

`private_uploads/<48 hex random>`: AES-256-GCM, a per-file key derived (HKDF) from the master key and the file name, the name bound as authenticated data. The database holds metadata and the plaintext SHA-256. The folder is not under the web root; the static server serves only an allow-list of the front-end files built at startup.

## How the audit is protected

HMAC-chained rows + append-only triggers + an external anchor file + same-transaction writes for successes, record-before-send for downloads. Details and the residual risk are in **THREATS.md §3**. Administrators can run *Verify* from the UI.

## Search

By name, owner, category and date range, plus "mine / shared / trash". The access predicate is always part of the query.

## AI

Where it would sit: helping an owner decide who should see a document. `POST /api/documents/:id/suggestions` suggests people (rule-based: who you already share similar documents with). A suggestion **grants nothing**; the owner accepts or rejects; the suggestion, the decision and any resulting grant are all audited. Plug a model in behind that endpoint and the boundary does not move.

## Layout

```
backend/src  app.js server.js  config/  models/  middleware/  routes/  services/
backend/tests  document-access  permission-revocation  audit-integrity (+ helpers)
frontend     login dashboard documents permissions audit (CSP: no inline script/style)
THREATS.md   PROMPTS.md
```

## Deploy (container)

```bash
docker build -t trustvault .
docker run -d --name trustvault -p 3000:3000 -v tv-data:/data \
  -e FILE_ENC_KEY=$(openssl rand -hex 32) -e AUDIT_HMAC_KEY=$(openssl rand -hex 32) \
  -e COOKIE_SECURE=1 -e TRUST_PROXY=1 trustvault      # behind a TLS-terminating proxy you control
docker exec -it trustvault node --disable-warning=ExperimentalWarning src/seed.js --admin-only
```

Keep the two keys somewhere safe: losing `FILE_ENC_KEY` loses every document, and changing `AUDIT_HMAC_KEY` makes the existing audit trail fail verification. The audit anchor (`/data/audit-anchor.log`) should be shipped off the host (see THREATS.md 3.3). `/healthz` is the only unauthenticated non-page endpoint.
