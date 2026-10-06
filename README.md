# Secure QR Login

QR credential login for Frappe/ERPNext v16, built on the existing Frappe
authentication and permission systems.

A user scans a personal QR code at the login page. The code resolves to an
existing **Frappe User** and creates an ordinary Frappe session. Authorization is
untouched: the signed-in user gets exactly the roles, User Permissions, permission
levels and company restrictions they already had.

> **The QR authenticates. It never authorizes.**
> This app writes no roles, no User Permissions and no permission levels. Session
> creation reuses `LoginManager.login_as()`, the same path Frappe's own one-time
> login link uses.

---

## Contents

- [How it works](#how-it-works)
- [Security design](#security-design)
- [Roles](#roles)
- [Install](#install)
- [Configuration](#configuration)
- [User guide](#user-guide)
- [Testing](#testing)
- [File structure](#file-structure)
- [Operations](#operations)
- [Known limitations](#known-limitations)

---

## How it works

```
ERPNext login page
  -> "Login with QR"
  -> camera scanner opens
  -> scan  ADXQR1.<43-char token>
  -> POST /api/method/adx_secure_qr_login.api.qr_auth.qr_exchange
       rate limit (per IP, and per IP+token)
       parse payload, look up credential by SHA-256(token)
       check status (Active / Expired / Revoked / Superseded)
       recompute expiry server-side
       check the User is enabled and is a System User
       [if 2FA enabled] require the authenticator code
       destroy any prior session on this browser
       LoginManager.login_as(user)   <- a normal Frappe session
  -> browser redirected to /desk
```

Every failure returns the **same** generic message and HTTP 200. The real reason
goes to the audit trail, never to the caller, so the endpoint cannot be used to
enumerate credentials or users.

### Architecture

| Layer | Module | Responsibility |
|---|---|---|
| Token | `security/tokens.py` | CSPRNG generation, SHA-256 hashing, payload grammar |
| Validation | `security/validation.py` | status / expiry / user-state checks, brute-force counters |
| Authorization | `security/rbac.py` | role predicates and asserts that work for non-Administrator users |
| Sessions | `security/session_guard.py` | destroys the prior occupant's session on a shared terminal |
| API | `api/qr_auth.py` | the guest login endpoint |
| Scoping | `permissions/*.py` | row-level `permission_query_conditions` and `has_permission` |

---

## Security design

**Design A — bearer credential.** The QR contains 256 bits of CSPRNG entropy
(`secrets.token_urlsafe(32)`). Only `sha256(token)` is stored, so a database dump
yields nothing usable.

| Property | Implementation |
|---|---|
| Token generation | `secrets.token_urlsafe(32)`, 43 chars, URL-safe |
| Storage | `sha256` hex only; plaintext exists solely in the minting response |
| Lookup | by hash, never by docname |
| Expiry | recomputed server-side on **every** attempt; date-granular |
| Revocation | immediate; the stored QR image is deleted too |
| Regeneration | old token is superseded before the new one is minted |
| Rate limiting | per-IP and per-(IP+token) fixed windows, plus a per-credential failure counter |
| Replay | a valid token **is** replayable until it expires or is revoked (see below) |
| Audit | every attempt recorded with an internal reason code |
| Session | prior session destroyed before the new one is created |

### Replay risk — read this

A printed QR is a **bearer credential**. Anyone holding the card can sign in as
the named user until it expires or is revoked. There is no way around that
without a second factor or terminal binding.

Mitigations in place: bounded validity, instant revocation, generation counters,
per-use audit, optional "notify the user on each use", and rate limiting.

**Operationally:** keep validity short, revoke promptly when a card is lost, and
consider the notification setting for high-value accounts. If your threat model
needs to defeat a lost card outright, see [Known limitations](#known-limitations).

### A Frappe trap worth knowing about

`frappe.get_all()` does **not** check permissions. Its own docstring says so: it
lists via `db_query` and *"Will not check for permissions"*. In particular it
ignores `permission_query_conditions`, which is the hook all the row-level
scoping in `permissions/` lives behind.

Every read that returns scoped data therefore goes through **`frappe.get_list()`**.
Getting this wrong is not a subtle degradation — it hands a QR Manager the whole
estate's audit trail, IP addresses included, and it looks correct in testing
because a fresh Administrator session sees the same rows either way.

`frappe.db.sql` has the same property by construction, so the dashboard's grouped
queries are only used for callers who are already unrestricted
(`rbac.is_qr_admin()`), and every other path routes through the permission layer.

### Stored QR images

Each credential's QR is rendered once and kept as a **private File** so a lost
card can be re-printed — the plaintext token is never persisted, so without this
re-printing would be impossible.

The PNG is a faithful rendering of the token: **anyone who can read the file can
OCR the token back out**. It is stored private and gated by credential read
permission. If your policy forbids that, set the QR to regenerate-only and drop
the download/print buttons.

---

## Roles

### QR Manager

- Generate, regenerate, revoke credentials for ordinary System Users
- Read and export the audit trail for users they manage
- View the security dashboard
- **Cannot** delete credentials (protects audit references)
- **Cannot** act on `Administrator`, `System Manager` or `QR Admin` accounts

### QR Admin

- Everything a Manager can do, across all users
- Configure QR Security Settings
- Receive and trigger the weekly report
- View the complete audit trail
- **Still cannot** issue a credential for `Administrator` itself

### Normal ERPNext User

- Sign in with their own QR
- See only their own credentials
- **Cannot** generate, revoke or list anyone else's
- **Cannot** see the audit trail, dashboard or settings

Authorization is enforced server-side on every endpoint. Hiding a UI button is
never the control — the endpoint matrix in [Testing](#testing) proves a plain
`Sales User` is refused by direct RPC call.

---

## Install

On an existing site:

```bash
bench --site <site> install-app adx_secure_qr_login
bench --site <site> migrate
bench build --app adx_secure_qr_login
```

`migrate` creates the roles, syncs the DocTypes and runs the patches that grant
the QR roles to Administrator. Then log in and open **Secure QR Login** from the
app switcher.

Grant roles to staff from **User** → *Roles*:

```bash
bench --site <site> add-role "QR Manager" jane@example.com
bench --site <site> add-role "QR Admin" admin@example.com
```

---

## Configuration

**QR Security Settings** (QR Admin only).

| Field | Default | Meaning |
|---|---|---|
| `qr_login_enabled` | 1 | Master switch for QR login |
| `show_login_option` | 1 | Draw the "Login with QR" button |
| `default_validity_days` | 30 | Validity of a newly minted credential |
| `max_validity_days` | 90 | Hard ceiling; a larger request is clamped |
| `max_active_credentials_per_user` | 3 | Concurrent active credentials per user |
| `revoke_prior_on_regenerate` | 1 | Supersede the previous credential on regenerate |
| `notify_user_on_use` | 0 | Email the holder on every successful scan |
| `destroy_prior_session` | 1 | Shared-terminal safety, see below |
| `idle_timeout_minutes` | 0 | 0 disables the client-side idle warning |
| `rate_limit_attempts` | 10 | Attempts per window, per IP and per token |
| `rate_limit_window_seconds` | 300 | Window length |
| `max_failed_attempts_per_credential` | 5 | Locks one credential after N failures |
| `require_2fa_on_qr_login` | 1 | Still require TOTP for users who have 2FA |
| `require_https` | 1 | Refuse QR login over cleartext HTTP, see below |
| `allow_self_download` | 1 | Whether a plain user may re-download their own QR image |
| `manager_company_scope_enabled` | 1 | Confine a QR Manager to their own companies |
| `audit_logging_enabled` | 1 | Master switch for the audit trail |
| `weekly_report_enabled` | 1 | Send the scheduled weekly report |
| `weekly_report_day` | Monday | Day the report covers |
| `weekly_report_timezone` | Asia/Kolkata | Timezone the send time is interpreted in |
| `weekly_report_recipient_role` | QR Admin | Role whose members receive the report |
| `audit_retention_days` | 365 | Audit rows older than this are purged daily |

### HTTPS requirement

With `require_https` enabled, `qr_exchange` refuses any request that did not
arrive over TLS. The credential in the payload is a bearer token: on the wire in
cleartext it is equivalent to handing the account over, so this fails closed.

Two paths are accepted as secure:

- the request scheme is `https` (including via `X-Forwarded-Proto` through a
  correctly configured reverse proxy), and
- loopback over plain HTTP (`127.0.0.1`, `localhost`, `::1`) — `bench serve` has
  no certificate, and without this the QR login button cannot be exercised in
  development at all. The alternative would be an insecure default that someone
  forgets to turn off in production.

Background contexts (scheduler, `bench execute`) have no network hop and are not
subject to the check.

### Manager company scope

`manager_company_scope_enabled` confines a QR Manager to the companies they can
already see, derived from their own User Permissions on Company — the same engine
that governs ERPNext. It applies to three things at once:

- generating, regenerating and revoking credentials for a user who sits outside
  those companies;
- which audit rows a Manager can list; and
- the credential and authentication totals on the security dashboard.

A user with **no** Company User Permission is unrestricted, mirroring ERPNext's
own behaviour for such a user rather than inventing a new rule. QR Admin is
global and is never narrowed.

### Revocation and live sessions

Revoking a credential does more than block the next login. With
`revoke_active_sessions` on the credential (the default) it also terminates every
live Frappe session belonging to that user — both the `Sessions` rows and their
redis keys — and records a `Session Revoked` event.

Without that, a credential revoked at 09:05 leaves whoever scanned it at 09:00
authenticated until the session expires, which by default is ten days.

The same happens when an account is **disabled**: a `User` `on_update` hook closes
its QR sessions and records `User Disabled`. Re-enabling an account creates no
new credential (spec 12).

A QR Admin can also force-logout any user without touching their credential,
which is the right action when an account is suspected compromised but the QR
must stay valid:

```python
frappe.call("adx_secure_qr_login.api.qr_manage.terminate_user_sessions",
            {"user": "john@example.com", "reason": "suspected compromise"})
```

### Audit events

All twelve event types from the specification are recorded, each with a call
site, not just a value in a Select list:

| Event | Recorded when |
|---|---|
| `QR Generated` | a credential is minted |
| `QR Downloaded` | the stored QR image is served |
| `QR Regenerated` | a credential is superseded |
| `QR Revoked` | a credential is revoked |
| `QR Expired` | the scheduled sweep flips a lapsed credential |
| `QR Login Success` | a session is established |
| `Invalid Credential` / `Expired Credential` / `Revoked Credential` / `Inactive User` | a rejected scan |
| `User Disabled` | an account transitions Active → Disabled |
| `Rate Limited` | a limit is hit |
| `Session Revoked` | sessions are terminated by revocation, disablement or admin action |
| `Security Setting Changed` | a security-relevant setting is edited |
| `Unauthorized QR Management` | a blocked management call |

Two properties worth relying on:

- `Security Setting Changed` names the fields that moved and the actor who moved
  them, and **switching audit logging off is itself recorded before it takes
  effect**.
- `Session Revoked` stores a *hashed* session reference (`sid:<12 hex>`), never the
  raw sid. A raw sid is a resumable bearer credential in its own right.

`company` on an audit row is the affected user's **own** default company, not the
site-wide default — an absent default leaves the field empty rather than
stamping every row with one company.

### Sending the report on demand

**QR Security Settings → Send Weekly Report Now**, or:

```python
frappe.call("adx_secure_qr_login.reports.weekly_security_report.send_report_now")
```

Pass `reference` (any date inside the week) to reproduce a week that was missed.
The manual path ignores the `weekly_report_enabled` toggle — that switch means
"don't do this every Monday", not "you may never do this" — but it still uses the
configured recipient list, so a manual run cannot mail the security summary
anywhere the configuration does not sanction. QR Admin only.

### Shared-terminal behaviour

Frappe's default `session_expiry` is **240 hours (10 days)**. On a kiosk that is a
long time for one person's authority to remain valid after they walk away.

With `destroy_prior_session` enabled (the default), each QR login deletes any
existing session on that browser before issuing the new one — both the `Sessions`
row and its redis key. `LoginManager.clear_active_sessions()` does **not** do this:
it only clears sessions of the *same* user, which is the opposite of the
shared-terminal case.

### Two-factor authentication

With `require_2fa_on_qr_login` enabled, a user who has TOTP enabled must still
enter their authenticator code after scanning. The scan returns
`{status: "otp_required", tmp_id, verification}` and no session is created until
the code is accepted. Disable the setting only if a QR scan is intended to
*replace* TOTP — that is a real reduction in security, so it should be a
deliberate decision.

---

## User guide

### Generate a QR

1. Open **QR Login Credential** → **New**.
2. Choose the **User**.
3. Optionally set validity days and a device label.
4. **Save**. The QR is shown **once**, with the code in a one-time dialog.

Download it or print it immediately — it cannot be displayed again.

### Download / print

- **Download QR** — the stored PNG, filename carries only the non-secret prefix.
- **Print QR** — a card showing the holder's name, account, expiry date, status
  and QR. It never prints a password, a raw token, a hash or an internal id.

Both are hidden for revoked, expired and superseded credentials, which print as a
notice instead of a dead-but-scannable code.

### Sign in

1. Go to the ERPNext login page.
2. Click **Login with QR**.
3. Allow camera access and scan, or expand **Enter code manually** and paste the
   code.
4. On success the browser lands on the desk. On failure the message is
   deliberately generic — if your card was lost or expired, ask an administrator.

If the browser blocks the camera (a non-HTTPS origin, for example), the panel
explains it and the manual entry field still works.

### Revoke

**QR Login Credential** → **Revoke** → supply a reason. The credential stops
working immediately and its stored QR image is deleted.

### Regenerate

**QR Login Credential** → **Regenerate**. The previous token is superseded before
the new one is minted, so a failure can never leave two live credentials. The new
QR is shown once.

### Review

**QR Login Audit** lists every attempt. QR Admins see everything; QR Managers see
only rows for users they manage. Internal reason codes
(`EXPIRED_CREDENTIAL`, `REVOKED_CREDENTIAL`, …) are recorded here even though the
login page shows a single generic message.

---

## Testing

19 automated tests run by Frappe's own runner:

```bash
bench --site <site> set-config allow_tests true
bench --site <site> run-tests --app adx_secure_qr_login \
      --module adx_secure_qr_login.tests.test_qr_login
```

Coverage: token uniqueness and hashing, payload rejection, every validation
rejection reason, disabled users, regeneration invalidation, endpoint
authorization for a plain user, privilege-escalation blocking, audit immutability
and secret scrubbing, settings clamping, and dashboard/report reconciliation.

Beyond that, the acceptance evidence is 302 assertions across 13 suites plus two
focused suites for the newer controls (60 assertions for the audit events, session
termination and manager scope; 15 for the dashboard figures and filters). Each
asserts observable state — a row that exists, a session that is gone, a call that
raises — rather than that a function is defined.

Two traps that produced false failures while writing them, both worth knowing if
you extend the suites:

- a shared `127.0.0.1` across suites makes a deliberate rate-limit saturation
  poison everything that runs after it; each simulated browser needs a distinct
  `X-Forwarded-For`;
- `QR Security Settings` is a **Single**. `frappe.db.get_value` / `set_value` on
  it raise or silently do nothing; use `get_singles_dict` / `set_single_value`.

---

## File structure

```
adx_secure_qr_login/
├── hooks.py                     app metadata, assets, scheduler, permission hooks
├── install.py  uninstall.py     role bootstrap and teardown
├── tasks.py                     scheduled maintenance (expiry refresh, retention purge)
├── patches.txt + patches/       v0_0_1 roles, v0_0_2 desk-user fix, v0_0_3
│                                dashboard, v0_0_4 settings backfill
├── api/
│   ├── qr_auth.py               guest login endpoint + availability flag
│   ├── qr_manage.py             generate / regenerate / revoke / download / list /
│   │                            force-logout
│   └── qr_stats.py              dashboard and report figures
├── security/
│   ├── tokens.py                CSPRNG, hashing, payload grammar
│   ├── validation.py            status / expiry / user-state, brute-force counters
│   ├── rbac.py                  role predicates, asserts, manager company scope
│   ├── session_guard.py         shared-terminal destruction, revocation kills
│   │                            sessions, hashed session references
│   ├── session_events.py        User-disabled and admin force-logout events
│   ├── qr_image.py              PyQRCode rendering, private File persistence
│   └── print_hooks.py           transient QR image for print formats
├── permissions/
│   ├── credential_conditions.py subject-based row scoping
│   └── audit_conditions.py      role-based audit scoping
├── reports/weekly_security_report.py
├── tests/test_qr_login.py
└── secure_qr_login/
    ├── constants.py             roles, events, reason codes, user-facing messages
    ├── doctype/                 qr_login_credential, qr_login_audit, qr_security_settings
    ├── print_format/            QR Login Credential Card
    └── workspace/               Secure QR Login
```

**No Frappe or ERPNext core file is modified.** Everything is reached through
documented hooks and public APIs.

---

## Operations

Scheduled jobs:

| When | Job | Purpose |
|---|---|---|
| Mon 08:00 | `send_weekly_report` | Weekly security summary by email |
| Every 2h at :07 | `refresh_expiry_status` | Flip lapsed credentials to Expired |
| Hourly | `refresh_expiry_status` | Same, for sites without cron |
| Daily 00:45 | `purge_expired_audit` | Delete audit rows past retention |

Neither maintenance job is a security control. Authentication recomputes status
and expiry on every attempt, so a lapsed credential is rejected even if the jobs
have not run.

The weekly report emails QR Admins (`weekly_report_recipient_role`) plus any
addresses in `weekly_report_recipients`. It requires a configured **outgoing
Email Account**; without one the run is logged and skipped rather than failing
silently.

All figures come from live queries on the credential and audit tables. The
dashboard and the report call the same functions, so they cannot disagree — a
test asserts that equality directly.

---

## Known limitations

1. **A lost printed card is a valid credential until expiry or revocation.** This
   is inherent to a bearer credential. To defeat it you would need terminal
   binding or a second factor; neither is implemented.
2. **Expiry is date-granular**, not minute-granular — a credential is valid
   through the end of its expiry day.
3. **Stored QR images are as sensitive as the token** (see above).
4. **The login page integration is DOM injection.** It does not modify
   `frappe/www/login.html`, so a Frappe upgrade cannot shadow it, but a change to
   the login page's markup could stop the button appearing. The availability
   endpoint fails silently by design — the page simply omits the option.
5. **Camera scanning requires a secure context** (HTTPS, or localhost). The
   manual code field is the fallback.
6. **The audit trail is purged by retention policy.** Security history older than
   `audit_retention_days` is deleted; the purge logs what it removed.
7. **There is no upload-a-QR-image fallback.** The specification recommends one
   "where compatible"; it was left out deliberately. A file picker on a shared
   terminal lets someone present a QR image that came from somewhere else, which
   is precisely the property a QR login is meant to bind to the device in the
   holder's hand. Camera plus manual code entry are the fallbacks. This is a
   documented deviation, not an oversight — reverse it if your terminals are
   individually controlled.
8. **A static QR is not a second factor.** It is one authentication method, not
   two. With `require_2fa_on_qr_login` enabled a user who has TOTP must still
   enter it; without 2FA configured, a scanned QR is the whole proof of
   possession. Do not describe it as equivalent to MFA.
