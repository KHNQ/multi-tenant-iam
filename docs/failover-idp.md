# Failover identity provider (System 2)

This system can stand in for the primary IdP (Keycloak 26, "System 1"). It
serves the same realms at Keycloak's paths, issues tokens with the same
contract and the same `sub`, and keeps working when Keycloak is down. It can
also become the IdP of record when Keycloak is retired.

The administration console in `frontend/` (Vue) runs on it: the
backend-for-frontend it was written against (a Spring BFF in front of
Keycloak) is re-implemented here with the same paths, payloads and cookies,
and the console has the System 2 additions its handoff asked for (standby
banner, mode and last sync, synchronisation and signing keys, access test).

- [How it fits together](#how-it-fits-together)
- [Installing](#installing)
- [Configuration](#configuration)
- [Connecting to Keycloak](#connecting-to-keycloak-synchronisation)
- [Passwords: importing Keycloak's hashes](#passwords-importing-keycloaks-hashes)
- [Client secrets for failover](#client-secrets-for-failover)
- [Applications](#configuring-applications)
- [Standby and primary](#standby-and-primary)
- [Signing keys and rotation](#signing-keys-and-rotation)
- [Health, metrics and alerts](#health-metrics-and-alerts)
- [The console](#the-console)
- [Decisions on the open questions](#decisions-on-the-open-questions)
- [Limitations](#limitations)
- [Testing](#testing)

## How it fits together

```
 browser ──► /realms/{realm}/protocol/openid-connect/*   src/idp/protocol.js   (sign-in, tokens, logout)
 apps    ──► /realms/{realm}/.well-known, /certs          src/idp/keys.js       (per-realm RS256 keys)
 console ──► /ui/  +  /api/*  +  /oauth2/…, /logout       src/bff/              (the console's BFF)
 operator ─► /health/*, /metrics, /admin/sync/credentials src/idp/operations.js
                     │
                     ▼
               Redis (idp:* keys)  ◄── src/idp/sync.js ◄── Keycloak Admin REST API (read-only)
```

| Module | Responsibility |
| --- | --- |
| `src/idp/store.js` | realms, users, roles, clients, client scopes, groups — one hash per kind per realm, replaced atomically by sync |
| `src/idp/mappers.js` | the token contract: Keycloak's claim mappers and client scopes, as data |
| `src/idp/tokens.js` | access / ID / UserInfo from **current** data |
| `src/idp/sessions.js` | SSO sessions, single-use codes, rotating refresh tokens |
| `src/idp/sync.js` | one-way synchronisation from Keycloak |
| `src/idp/credentials.js` | imported Argon2 hashes, passwords set here |
| `src/idp/mode.js` | standby / primary |
| `src/bff/*` | the console's API (`/api/*`), sign-in and sign-out |

### Endpoints (per realm)

| Endpoint | Path |
| --- | --- |
| Discovery | `GET /realms/{realm}/.well-known/openid-configuration` |
| Realm document | `GET /realms/{realm}` |
| Authorization | `GET/POST /realms/{realm}/protocol/openid-connect/auth` |
| Token | `POST /realms/{realm}/protocol/openid-connect/token` |
| JWKS | `GET /realms/{realm}/protocol/openid-connect/certs` |
| UserInfo | `GET/POST /realms/{realm}/protocol/openid-connect/userinfo` |
| Logout | `GET/POST /realms/{realm}/protocol/openid-connect/logout` |
| Revocation | `POST /realms/{realm}/protocol/openid-connect/revoke` |
| Introspection | `POST /realms/{realm}/protocol/openid-connect/token/introspect` |

The issuer is `{PUBLIC_URL}/realms/{realm}` (or `IDP_PUBLIC_URL`), equal byte
for byte to `iss` in every token. A token of one realm is not accepted at
another realm's endpoints.

### Protocol behaviour

- `response_type=code` only; `response_mode` `query`, `form_post` (MapDashboard's .NET default) or `fragment`.
- PKCE with `S256` is required of every client, confidential ones included; `plain` and a missing challenge are refused.
- `redirect_uri` and `post_logout_redirect_uri` must equal a registered value. Two exceptions, as in RFC 8252: the port is ignored for `http://127.0.0.1` and `http://[::1]`; private-use schemes (`com.samta.pydemo:/callback`) are allowed. Wildcards are never honoured — `https://mapdashboard.internal/*` registered matches only that literal string.
- Codes live 60 s, are single-use and bound to the client, redirect URI, PKCE challenge and session. A code used twice ends the session it bought.
- Confidential clients authenticate with `client_secret_basic` or `client_secret_post`. Secrets are stored as SHA-256 hashes only.
- Refresh tokens rotate on every use (`revokeRefreshToken`, reuse 0). A retired refresh token presented again revokes the whole session. Refresh is refused after `ssoSessionIdleTimeout` (1800 s) without use, after `ssoSessionMaxLifespan` (36000 s), and once the account is disabled, deleted, locked or re-secured. Roles in a refreshed token are rebuilt from current data; `sub`, `iss`, `azp` and `sid` never change.
- `client_credentials` only for confidential clients with a service account; `sub` is the service account's id, `preferred_username` `service-account-{clientId}`.
- Logout ends the SSO session and every refresh token of it, and redirects only to a registered post-logout URI (else an error page). Without `id_token_hint` the user is asked to confirm first.
- SSO: a second client of the same realm signs in without a password prompt. `prompt=login`, `prompt=none` and `max_age` are honoured.
- Password grant, implicit flow, device flow, dynamic registration and consent are not implemented.
- The sign-in pages run no script (a nonce'd one-liner auto-submits `form_post`), are framed by nobody, and are in English and Persian (right to left; `ui_locales=fa`).

### The token contract

Claims are produced by **mappers** attached to a client or to a client scope,
as in Keycloak (§5.3 of the specification). A client's default scopes always
apply; its optional scopes when requested. The supported mapper types:

| Type | Keycloak mapper | Example |
| --- | --- | --- |
| `hardcoded` | `oidc-hardcoded-claim-mapper` | `tenant = tenant-alpha`, `authz_version = 0` (int) |
| `user-attribute` | `oidc-usermodel-attribute-mapper` | `tenants` (multivalued) |
| `user-property` | `oidc-usermodel-property-mapper` | `preferred_username`, `email`, `email_verified` |
| `full-name` | `oidc-full-name-mapper` | `name` |
| `realm-roles` | `oidc-usermodel-realm-role-mapper` | `realm_access.roles` |
| `client-roles` | `oidc-usermodel-client-role-mapper` | `resource_access.${client_id}.roles`, `md_roles` |
| `audience` | `oidc-audience-mapper` | `business-api` (custom) or another client's id |
| `audience-resolve` | `oidc-audience-resolve-mapper` | every other client the user holds roles of |
| `allowed-origins`, `acr`, `sub`, `auth-time`, `group-membership` | the corresponding built-ins | |

Roles are **effective** roles: direct mappings, group (and parent group)
mappings, and everything composites contain. Keycloak's default roles
(`default-roles-{realm}`, `offline_access`, `uma_authorization`, account roles)
appear as they do there. A one-element `aud` is written as a string, an empty
one is omitted — as Keycloak writes it. Absent `access/id/userinfo.token.claim`
flags mean *false*, an absent introspection flag *true* — as in Keycloak 25+.

## Installing

### Docker

```sh
docker build -t iam-failover-idp:1.1 .        # where there is network access
docker save iam-failover-idp:1.1 | gzip > iam-failover-idp-1.1.tar.gz
# on the server (no Internet needed):
docker load < iam-failover-idp-1.1.tar.gz
cp .env.example .env                           # then edit, see below
IAM_IMAGE=iam-failover-idp:1.1 docker compose up -d
```

The images are `node:22-bookworm-slim` and `redis:7.4-alpine`, both from
Docker Hub. Redis runs with AOF (`appendfsync everysec`). Put the reverse proxy
(TLS with the `step-ca` certificate for e.g. `iam2.internal`) in front of port
3000 and set `TRUST_PROXY` to its subnet.

### On one machine, to try it: `./boot.sh`

`boot.sh` checks the prerequisites (Node 22, npm, curl, Redis), creates or
completes `.env` with generated secrets, installs packages, builds the console,
starts Redis, the registry, the mock services and the gateway, prepares test
data and prints the addresses and accounts to use.

| Command | |
| --- | --- |
| `./boot.sh` | **demo**: no Keycloak; this system is primary; demo tenants `samta` and `tenant-alpha`; `padmin`'s one-time password in `.run/boot/demo/`, demo accounts in `.run/boot/demo/demo-accounts.txt` |
| `./boot.sh failover` | a stand-in Keycloak (`test/idp/fake-keycloak.js`, port 8180) is synchronised in **standby**; its password hashes are imported, so `padmin / Padmin-Passw0rd-1` and every `<User>-Passw0rd-1` work; client secrets for MapDashboard and the wiztest service account in `.run/boot/failover/client-secrets.txt` |
| `./boot.sh keycloak` | your real Keycloak from `KEYCLOAK_*` in `.env`, in standby |
| `./boot.sh keycloak-stop` / `keycloak-start` | take the stand-in Keycloak down and back: sign-in keeps working, sync turns stale |
| `./boot.sh idp <command>` | the operator CLI against the running profile (`mode`, `rotate-key`, `client-secret`, …) |
| `./boot.sh status` / `logs` / `stop` | what runs and the IdP's mode; the combined log; stop everything |
| `./boot.sh reset <profile> --yes` | wipe a profile's data |

Each profile has its own Redis database (demo 1, failover 2, keycloak 3), so
they never mix with each other or with `start.sh` (database 0). If port 3000
is taken, the gateway moves to the first free port from 3100 (`GATEWAY_PORT`
chooses one).

### Without Docker

```sh
npm ci
npm run build:ui            # builds frontend/dist, served at /ui/
./start.sh                  # Redis, registry, mock services, gateway (reads .env)
```

## Configuration

Everything is environment (`.env.example` lists all of it). The essentials:

| Setting | |
| --- | --- |
| `JWT_SECRET` | required. Also the root from which the keys sealing signing keys, password hashes and the console's client secret at rest are derived — keep it stable and identical on every instance. |
| `PUBLIC_URL` | `https://iam2.internal`. Issuers are `{PUBLIC_URL}/realms/{realm}`; the console's callback is `{PUBLIC_URL}/login/oauth2/code/keycloak`. |
| `REDIS_URL` | the shared Redis. |
| `TRUST_PROXY` | the reverse proxy's subnet, so client addresses, `https` and Secure cookies are right. |
| `KEYCLOAK_*` | synchronisation (next section). With these set the first mode is `standby`. |
| `IDP_CREDENTIAL_IMPORT_TOKEN`, `IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS` | the password-hash import. |
| `IDP_MODE` | seeds the mode on the very first boot only. |
| `MAPDASHBOARD_PERMISSION_CATALOG_URL` | where the console reads the permissions MapDashboard declares. |
| `METRICS_TOKEN` | enables `/metrics`. |

Session cookies are `HttpOnly`, `SameSite=Lax`, `Secure` when `PUBLIC_URL` is
https, and scoped to `/realms/{realm}/` — one per realm.

## Connecting to Keycloak (synchronisation)

1. In Keycloak (realm `master`, or the realm named by `KEYCLOAK_SYNC_TOKEN_REALM`) create a confidential client with service accounts enabled, e.g. `iam-failover-sync`.
2. Give its service account, for every realm to synchronise, the `realm-management` roles **`view-realm`, `view-users`, `view-clients`, `query-groups`** — and no `manage-*` role.
3. Set `KEYCLOAK_URL`, `KEYCLOAK_SYNC_CLIENT_ID`, `KEYCLOAK_SYNC_CLIENT_SECRET` and `KEYCLOAK_SYNC_REALMS=platform,samta,tenant-alpha,tenant-beta` (test realms are left out by listing only these; with the list empty, every visible realm except `KEYCLOAK_SYNC_EXCLUDE` is taken). If Keycloak's certificate is from the internal CA, set `NODE_EXTRA_CA_CERTS` to its root.

Every `KEYCLOAK_SYNC_INTERVAL_SECONDS` (300) — and on demand,
`POST /api/admin/idp/sync` from a platform admin's console session — each realm
is read **completely** (realm settings, roles and composites, clients with
mappers, scopes and roles, client scopes, groups, users with role mappings and
group memberships, service accounts) and then applied in one Redis
transaction. A failure anywhere leaves the realm exactly as it was; nothing is
deleted unless a complete snapshot no longer contains it. Users removed in
Keycloak are deleted here and their sessions end; users disabled there have
their sessions here ended at the same sync. Only one instance syncs at a time,
and only in standby. `npm run idp -- sync-status` shows the last result per realm.

What is not synchronised: password hashes (next section), client secrets
(generated here), signing keys (this system's own), sessions. Mapper types the
engine does not support are listed in the realm's sync status and logged.

## Passwords: importing Keycloak's hashes

The Admin API does not expose hashes, so they are exported from Keycloak's
database (`credential.secret_data`, `credential.credential_data`) by a script
on your server and posted here:

```http
POST /admin/sync/credentials
Authorization: Bearer <IDP_CREDENTIAL_IMPORT_TOKEN>
Content-Type: application/json

[
  {
    "realm": "samta",
    "userId": "8f1e2a7c-3b4d-4e5f-9a0b-1c2d3e4f5a6b",
    "type": "password",
    "credentialData": { "hashIterations": 5, "algorithm": "argon2",
                        "additionalParameters": { "hashLength": ["32"], "memory": ["7168"], "type": ["id"], "version": ["1.3"], "parallelism": ["1"] } },
    "secretData": { "value": "<base64>", "salt": "<base64>", "additionalParameters": {} },
    "createdDate": 1792000000000
  }
]
```

Answer: `{ "imported": n, "unchanged": n, "rejected": [{ "realm", "userId", "reason" }] }`.

- Accepted only with the token, from an address in `IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS`, over HTTPS (or loopback), in standby mode. With either setting unset the endpoint answers 404.
- Users must have been synchronised first (otherwise `unknown user`).
- Each hash becomes a PHC string with **its own** parameters (`$argon2id$v=19$m=7168,t=5,p=1$salt$hash`) and is verified with `argon2.verify`; users sign in with the same password as in Keycloak. Other algorithms (`pbkdf2-sha512`, …) are rejected with the reason; nothing is ever rehashed in standby.
- Re-posting the same credential (same `createdDate`) is a no-op; a different one replaces it and ends that user's sessions (the password changed in Keycloak).
- Hashes are sealed (AES-256-GCM) at rest and never logged or returned.

A minimal export query (PostgreSQL), joined to realm names:

```sql
SELECT r.name AS realm, c.user_id AS "userId", c.type, c.credential_data AS "credentialData",
       c.secret_data AS "secretData", c.created_date AS "createdDate"
FROM credential c JOIN user_entity u ON u.id = c.user_id JOIN realm r ON r.id = u.realm_id
WHERE c.type = 'password' AND r.name IN ('platform','samta','tenant-alpha','tenant-beta');
```

## Client secrets for failover

Secrets are never copied from Keycloak (§7.4). For each confidential client,
issue this system's own secret and give it to the application's failover
configuration:

- in the console: *Applications → (client) → Rotate secret* — shown once; allowed in standby, because it touches only this system;
- or `npm run idp -- client-secret samta samta-mapdashboard-web-poc` (printed once).

The console's own client (`iam-admin-ui`) is handled automatically: its secret
is generated here and kept sealed in Redis, and its callback
`{PUBLIC_URL}/login/oauth2/code/keycloak` and post-logout
`{PUBLIC_URL}/logout/complete` are added to the client's **local overlay** —
redirect URIs, origins and the secret that belong to this system and that
synchronisation never overwrites.

## Configuring applications

Each application trusts both issuers; nothing else changes.

| Application | System 2 settings |
| --- | --- |
| MapDashboard | Authority `https://iam2.internal/realms/samta`, the System 2 client secret; refresh against the issuer of the session. `md_roles` is produced by the `mapdashboard-roles` scope exactly as in System 1. |
| IAM BFF (Spring) | issuer `https://iam2.internal/realms/platform`, System 2 secret for `iam-admin-ui`, and `https://iam2.internal/login/oauth2/code/keycloak` added to the client's redirect URIs in Keycloak (it is then synchronised). |
| React reference | add `https://iam2.internal/realms/tenant-alpha` to the trusted issuers. CORS is answered for the client's web origins. |
| Native samples | trust the second issuer; loopback ports and the custom scheme work as registered. |
| Resource servers | trust both JWKS URLs; validate `iss` against both issuers. |

## Standby and primary

| | standby | primary |
| --- | --- | --- |
| synchronisation | on | off |
| sign-in, refresh, logout | yes | yes |
| console changes | refused (`409 standby_read_only`); the console shows a banner and disables editing | allowed |
| allowed anyway | ending sessions, an emergency lock/unlock of an account, issuing this system's client secrets, key rotation, drift checks | — |

An emergency lock in standby is held here, on top of the synchronised state,
so the next sync does not undo it.

Switch (audited; every instance follows within seconds):

```sh
npm run idp -- mode primary          # or: POST /api/admin/idp/mode {"mode":"primary"} as a platform admin
npm run idp -- mode standby
```

Going back to standby means Keycloak is the source of truth again: the next
sync replaces the synchronised realms, including changes made here while
primary. Realms created here (source `local`) are never overwritten.

## Signing keys and rotation

Every realm has its own RSA-2048 key, `kid` = RFC 7638 thumbprint, private
half sealed at rest. These keys are never shared with Keycloak.

```sh
npm run idp -- keys samta                 # list (active / passive)
npm run idp -- rotate-key samta           # new active key; the old one stays in JWKS as passive
# wait at least the access token lifetime (300 s) plus clock skew, then:
npm run idp -- retire-key samta <old kid>
```

The same from the console API: `POST /api/admin/idp/realms/{realm}/keys/rotate`
and `DELETE /api/admin/idp/realms/{realm}/keys/{kid}`. Tokens signed with a
passive key verify until it is retired.

## Health, metrics and alerts

| Endpoint | |
| --- | --- |
| `GET /health/live` | the process is up |
| `GET /health/ready` | Redis answers and every realm has an active signing key (503 otherwise) |
| `GET /health/sync` | `{ mode, lastSuccessfulSync, oldestAgeSeconds, stale, realms: { samta: { users, ageSeconds, ok, error } } }` — 503 when stale |

Metrics (`/metrics`, with `METRICS_TOKEN`): `iam_idp_login_attempts_total`,
`iam_idp_logins_total`, `iam_idp_login_failures_total{reason}`,
`iam_idp_refresh_total{outcome}`, `iam_idp_logouts_total`,
`iam_idp_sync_errors_total`, `iam_idp_sync_age_seconds{realm}`,
`iam_idp_sync_stale`, `iam_idp_standby`. The process also logs a warning
(`alert: IdpSyncStale`) every 10 minutes while sync is stale. A Prometheus rule:

```yaml
- alert: IdpSyncStale
  expr: max(iam_idp_sync_age_seconds) > 1800 or iam_idp_sync_stale == 1
  for: 5m
  labels: { severity: warning }
  annotations: { summary: "Failover IdP has not synchronised from Keycloak for over 30 minutes" }
```

Audit log entries (category `idp` / `bff`) cover sign-in, failed sign-in,
refresh, reuse, logout, synchronisation, credential import (counts only), mode
changes, key rotation and every console change. Passwords, tokens and secrets
are never logged.

## The console

`frontend/` is served at `/ui/` (build it with `npm run build:ui`; the path
is `CONSOLE_UI_DIR`). Its contract, served by `src/bff`:

| Path | |
| --- | --- |
| `GET /oauth2/authorization/keycloak?returnTo=` | sign-in: code + PKCE against realm `platform` as `iam-admin-ui` |
| `GET /login/oauth2/code/keycloak` | callback; the ID token is verified (issuer, audience, nonce) |
| `POST /logout` (`_csrf`, `returnTo`) | ends the console session and the IdP session (`end_session` with `id_token_hint`) |
| `GET /api/me`, `GET /api/status` | the operator, evaluated per request from current roles; dependency states |
| `/api/tenants/{tenant}/users…`, `…/clients…`, `…/groups…`, `…/roles…`, `…/effective-access`, `…/sessions…` | tenant administration |
| `/api/tenants/{tenant}/applications/{clientId}/…` | application roles (`role:*`) and permissions (`perm:*`), previews with fingerprints, permission imports |
| `/api/admin/tenants…` | the tenant catalogue; approving provisions a realm |
| `/api/admin/idp…` | mode, sync now, key rotation (platform admins) |

The browser never receives a token: an `HttpOnly` session cookie, and an
`XSRF-TOKEN` cookie echoed in the `X-XSRF-TOKEN` header on writes (double
submit; on `/api` only the header is accepted, never a `_csrf` parameter).
Every write needs an `Idempotency-Key` (`400 idempotency_key_required`
otherwise): the same key and request replays the first outcome, the same key
with another request is `409 idempotency_key_reuse`, and one still running is
`409 idempotency_in_progress`. Keys are scoped per operator and per tenant.

Lists use one envelope — `{ tenant, count, first, limit, total, hasMore, <items> }`
— with `?first=` and `?max=` (clamped to 100; `limit` says what was applied).
`total` is withheld for clients and roles, as in the original contract, and
`hasMore` is then inferred from a full page. Errors are
`{ error, fields?, correlationId }` with `X-Correlation-Id`; `fields` names the
rule, never the submitted value. A credential reset answers `204` with no body;
granting an administrative role is `403`, and a grant batch is all or nothing.

What the console adds for System 2 (frontend/src):

| Where | What |
| --- | --- |
| every page | in standby, a banner — "This is the backup system. Make changes in the primary system." — and editing controls disabled (`standby.js`, from `mode` in `/api/me`). Ending sessions, the enable/disable emergency lock, issuing this system's client secrets and drift checks stay available. |
| Overview | operating mode and last successful synchronisation in *Platform status* |
| ⚙ Platform → Synchronisation | mode (with a confirmed switch), per-tenant sync status, *Synchronise now* |
| ⚙ Platform → Signing keys | each tenant's active and passive keys, confirmed rotation and retirement |
| Users → (user) → Access test | for a chosen application and scope: whether the user can sign in (each check: account enabled, password set, application enabled and browser sign-in, secret issued here, MapDashboard's `role:*` in `md_roles`) and the exact access token, ID token and UserInfo claims. Nothing is issued. Backed by `POST /api/tenants/{t}/users/{id}/access-test`. |

Who the operator is and what they may
do is evaluated on every request: `platform-admin` sees every tenant;
`tenant-admin` only those in the account's `tenants` attribute;
`approve-permissions:{clientId}` may approve permission imports. The console
session ends when the IdP session behind it does.

Console administrators are accounts of realm `platform`; the console itself
does not grant administrative roles. In primary mode they are managed with:

```sh
npm run idp -- create-user platform alice alice@example.org   # one-time password printed once
npm run idp -- grant-role platform alice tenant-admin          # or platform-admin
npm run idp -- set-tenants alice tenant-alpha,samta
```

If the platform realm was bootstrapped here and Keycloak is connected later,
`npm run idp -- forget-realm platform --yes` lets the next synchronisation
bring Keycloak's copy (a realm created here is otherwise never overwritten).

A fresh deployment without Keycloak creates realm `platform` with the console
client and a first administrator, `padmin`, whose one-time password is in
`.run/initial-console-admin-password` (mode 0600, never logged); it must be
replaced at the first sign-in. To try the console without Keycloak:

```sh
npm run idp -- seed-demo     # demo realms samta and tenant-alpha, prints the demo passwords once
```

## Decisions on the open questions

| §15 | Decision taken here |
| --- | --- |
| 1. Password hashes | Implemented as specified (import endpoint); authorisation to read Keycloak's DB is yours to confirm. |
| 2. Storage | Redis only, with AOF and the existing encrypted off-host backups (`npm run backup`). Audit logs go to files and the log forwarder. Standalone Redis remains a single point of failure (README §7). |
| 3. Domain | Whatever `PUBLIC_URL` says; examples use `iam2.internal`. |
| 5. Identity brokering | **Option 2**: not supported during failover. A `samta` user needs an account in `platform` to use the console. |
| 6. `poc-cli` / password grant | Not implemented (`unsupported_grant_type`). |

## Limitations

- Required actions other than `UPDATE_PASSWORD` are kept and shown, not enforced at sign-in. `UPDATE_PASSWORD` on a synchronised account in standby stops the sign-in with a message (the change belongs in the primary system).
- `offline_access` is accepted as a scope but issues an ordinary (session-bound) refresh token, not an offline one.
- Lists are paged by the server but the console, as delivered, shows only the first page (20 users, 50 clients); a search narrows it.
- No MFA (none in System 1); the sign-in flow is a sequence of steps, so one can be added.
- Groups are synchronised and honoured; the console's group screen exists but is out of its menu, as before.

## Testing

```sh
npm test                 # unit tests (Jest), including the token contract and Argon2 import
npm run test:idp         # acceptance: real gateway + throwaway Redis + a stand-in Keycloak
                         # (needs redis-server on PATH)
npm --prefix frontend test
```

`test/idp/acceptance.test.js` follows §13: discovery per realm, PKCE for
public and confidential clients, refused `plain`/missing PKCE and unregistered
redirects, rotation and reuse revocation, idle and maximum lifetimes, a user
disabled or deleted by sync, logout, client credentials, two published keys,
the MapDashboard / React / native token contracts, Keycloak down and failing
halfway with nothing lost, standby refusing changes, primary mode, and the
console end to end. `test/idp/fresh.test.js` covers a deployment with no
Keycloak at all.
