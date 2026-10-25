/**
 * Standby or primary.
 * ─────────────────────────────────────────────────────────────────────────────
 *   standby  the primary IdP is the source of truth. Its data is synchronised
 *            here; sign-in, refresh and logout work (including while the
 *            primary is down), but administrative changes are refused so the
 *            two systems cannot diverge. Ending sessions and locking an
 *            account in an emergency remain possible.
 *   primary  this system is the IdP of record: synchronisation stops and the
 *            administration panel can change everything.
 *
 * The mode lives in Redis so every gateway instance agrees on it. IDP_MODE
 * only seeds it the first time; afterwards it is changed deliberately (the
 * admin API or `npm run idp -- mode primary`) and every change is audited.
 */

const KEY = 'idp:mode';
const MODES = new Set(['standby', 'primary']);
const CACHE_MS = 2000;

function createMode({ redis, log, initial }) {
  let cached = null;
  let readAt = 0;

  async function init() {
    const seed = MODES.has(initial) ? initial : 'standby';
    if (await redis.set(KEY, JSON.stringify({ mode: seed, since: new Date().toISOString(), by: 'configuration' }), 'NX')) {
      log.audit('idp', `Operating mode initialised to '${seed}'`, { mode: seed });
    }
    return get({ fresh: true });
  }

  async function get({ fresh = false } = {}) {
    if (!fresh && cached && Date.now() - readAt < CACHE_MS) return cached;
    const raw = await redis.get(KEY);
    let parsed = null;
    try { parsed = raw ? JSON.parse(raw) : null; } catch { parsed = null; }
    cached = parsed && MODES.has(parsed.mode) ? parsed : { mode: 'standby', since: null, by: null };
    readAt = Date.now();
    return cached;
  }

  async function set(mode, actor) {
    if (!MODES.has(mode)) throw new Error(`mode must be one of: ${[...MODES].join(', ')}`);
    const previous = (await get({ fresh: true })).mode;
    const record = { mode, since: new Date().toISOString(), by: actor || 'unknown', previous };
    await redis.set(KEY, JSON.stringify(record));
    cached = record;
    readAt = Date.now();
    log.audit('idp', `Operating mode changed from '${previous}' to '${mode}' by ${actor}`, { mode, previous, actor });
    return record;
  }

  const isStandby = async () => (await get()).mode === 'standby';

  return { init, get, set, isStandby, KEY };
}

module.exports = { createMode, MODES };
