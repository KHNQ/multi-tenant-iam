/**
 * Operating the identity provider: health, metrics, and the credential import.
 *
 *   GET  /health/live            the process is up
 *   GET  /health/ready           Redis answers and every realm has an active signing key
 *   GET  /health/sync            mode, last successful sync, per-realm age
 *   POST /admin/sync/credentials password hashes exported from the primary IdP's
 *                                database, by the operator's export script
 *
 * The import is the one place a password hash crosses the network. It is
 * accepted only with IDP_CREDENTIAL_IMPORT_TOKEN, only from an address in
 * IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS, only over HTTPS unless the caller is on
 * the loopback interface, and only in standby mode; with either setting
 * missing the endpoint does not exist. Nothing it receives is logged.
 */

const express = require('express');
const { sameSecret, parseCidrList, addressAllowed } = require('./util');

const STALE_AFTER_SECONDS = 30 * 60;
const MAX_IMPORT_ENTRIES = 50_000;

function createOperations({ store, keyring, sessions, credentials, mode, sync, log, metrics, redis, env = process.env }) {
  const router = express.Router();
  const importToken = env.IDP_CREDENTIAL_IMPORT_TOKEN || null;
  const importFrom = parseCidrList(env.IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS);
  const importJson = express.json({ limit: env.IDP_CREDENTIAL_IMPORT_MAX_BODY || '25mb' });

  async function syncHealth() {
    const [current, status, realms] = await Promise.all([mode.get(), sync.status(), store.listRealms()]);
    const now = Date.now();
    const perRealm = {};
    let oldest = null;
    let lastSuccessfulSync = null;
    for (const realm of realms) {
      const s = status.realms[realm.name];
      const users = (await store.listUsers(realm.name)).filter((u) => !u.serviceAccountClientId).length;
      const ageSeconds = s?.lastSuccess ? Math.round((now - Date.parse(s.lastSuccess)) / 1000) : null;
      perRealm[realm.name] = { source: realm.source, users, ageSeconds, ok: s ? s.ok : null, error: s?.error || null, lastSuccess: s?.lastSuccess || null };
      if (realm.source === 'sync' && ageSeconds !== null) {
        oldest = oldest === null ? ageSeconds : Math.max(oldest, ageSeconds);
        if (!lastSuccessfulSync || s.lastSuccess < lastSuccessfulSync) lastSuccessfulSync = s.lastSuccess;
      }
    }
    const stale = status.configured && current.mode === 'standby'
      && (oldest === null || oldest > STALE_AFTER_SECONDS || Object.values(perRealm).some((r) => r.source === 'sync' && r.ok === false));
    return {
      mode: current.mode, modeSince: current.since, syncConfigured: status.configured,
      lastSuccessfulSync, oldestAgeSeconds: oldest, stale: Boolean(stale), realms: perRealm,
    };
  }

  router.get('/health/live', (req, res) => res.set('Cache-Control', 'no-store').json({ status: 'UP' }));

  router.get('/health/ready', async (req, res) => {
    const checks = {};
    try {
      checks.redis = (await Promise.race([redis.ping(), new Promise((_, reject) => { setTimeout(() => reject(new Error('timeout')), 1000).unref(); })])) === 'PONG';
    } catch {
      checks.redis = false;
    }
    if (checks.redis) {
      const names = await store.listRealmNames();
      checks.signingKeys = Object.fromEntries(await Promise.all(names.map(async (name) => [name, await keyring.ready(name)])));
    }
    const up = checks.redis && Object.values(checks.signingKeys || {}).every(Boolean);
    res.status(up ? 200 : 503).set('Cache-Control', 'no-store').json({ status: up ? 'UP' : 'DOWN', checks });
  });

  router.get('/health/sync', async (req, res) => {
    const health = await syncHealth();
    res.status(health.stale ? 503 : 200).set('Cache-Control', 'no-store').json(health);
  });

  // ── credential import ─────────────────────────────────────────────────────

  router.post('/admin/sync/credentials', async (req, res, next) => {
    if (!importToken || !importFrom) return res.status(404).json({ error: 'Not found' });
    if (!addressAllowed(importFrom, req.ip)) {
      log.audit('idp', 'Credential import refused: the caller\'s address is not allowed', { from: req.ip });
      return res.status(403).json({ error: 'access_denied' });
    }
    const loopback = /^(127\.|::1$|::ffff:127\.)/.test(req.ip || '');
    if (!req.secure && !loopback) return res.status(403).json({ error: 'https_required' });
    const presented = (req.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    if (!presented || !sameSecret(presented, importToken)) {
      log.audit('idp', 'Credential import refused: invalid token', { from: req.ip });
      return res.status(401).json({ error: 'invalid_token' });
    }
    if (!(await mode.isStandby())) return res.status(409).json({ error: 'primary_mode', error_description: 'Synchronisation is off in primary mode' });
    return importJson(req, res, next);
  }, async (req, res) => {
    const entries = req.body;
    if (!Array.isArray(entries)) return res.status(400).json({ error: 'invalid_request', error_description: 'The body must be a JSON array' });
    if (entries.length > MAX_IMPORT_ENTRIES) return res.status(413).json({ error: 'too_many_entries' });

    let imported = 0;
    let unchanged = 0;
    const rejected = [];
    const realms = new Map();
    for (const entry of entries) {
      const userId = typeof entry?.userId === 'string' ? entry.userId : null;
      const reject = (reason) => rejected.push({ realm: entry?.realm ?? null, userId, reason });
      if (!entry || typeof entry !== 'object' || !userId || typeof entry.realm !== 'string') { reject('realm and userId are required'); continue; }
      if (entry.type !== 'password') { reject(`credential type '${entry.type}' is not imported`); continue; }
      if (!realms.has(entry.realm)) realms.set(entry.realm, await store.getRealm(entry.realm));
      const realm = realms.get(entry.realm);
      if (!realm) { reject('unknown realm'); continue; }
      if (realm.source === 'local') { reject('the realm is managed in this system'); continue; }
      const user = await store.getUser(entry.realm, userId);
      if (!user) { reject('unknown user (synchronise users before their credentials)'); continue; }

      const existing = await credentials.read(entry.realm, userId);
      const createdDate = Number(entry.createdDate) || null;
      if (existing && existing.source === 'sync' && createdDate && existing.createdDate === createdDate) { unchanged++; continue; }
      const outcome = await credentials.importKeycloak(entry.realm, userId, {
        credentialData: entry.credentialData, secretData: entry.secretData, createdDate,
      });
      if (outcome.problem) { reject(outcome.problem); continue; }
      imported++;
      // A different password than the one this system held: the account was
      // re-secured in the primary system, so its sessions here end too.
      if (existing) {
        await store.bumpSecurityVersion(entry.realm, userId);
        await sessions.endAllForUser(entry.realm, userId);
      }
    }
    log.audit('idp', `Credential import: ${imported} imported, ${unchanged} unchanged, ${rejected.length} rejected`, { imported, unchanged, rejected: rejected.length, from: req.ip });
    return res.json({ imported, unchanged, rejected });
  });

  // ── metrics and the staleness alert ───────────────────────────────────────

  metrics.gauge('iam_idp_sync_age_seconds', 'Seconds since each synchronised realm was last synchronised successfully', ['realm'], async () => {
    const health = await syncHealth();
    return Object.entries(health.realms).filter(([, r]) => r.source === 'sync' && r.ageSeconds !== null)
      .map(([realm, r]) => ({ labels: { realm }, value: r.ageSeconds }));
  });
  metrics.gauge('iam_idp_standby', '1 while this system is the standby IdP, 0 when it is primary', [], async () => ((await mode.get()).mode === 'standby' ? 1 : 0));
  metrics.gauge('iam_idp_sync_stale', '1 when synchronisation is configured and the last success is over 30 minutes old', [], async () => ((await syncHealth()).stale ? 1 : 0));

  let warnedAt = 0;
  async function watchStaleness() {
    try {
      const health = await syncHealth();
      if (health.stale && Date.now() - warnedAt > 10 * 60 * 1000) {
        warnedAt = Date.now();
        log.warn('idp', `Synchronisation is stale: the oldest realm was last synchronised ${health.oldestAgeSeconds ?? 'never'} seconds ago`, {
          oldestAgeSeconds: health.oldestAgeSeconds, alert: 'IdpSyncStale',
        });
      }
    } catch { /* the next tick will say */ }
  }
  const watcher = setInterval(watchStaleness, 60_000);
  watcher.unref();

  return { router, syncHealth };
}

module.exports = { createOperations, STALE_AFTER_SECONDS };
