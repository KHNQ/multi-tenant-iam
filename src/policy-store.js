/**
 * The Casbin policy in Redis — shared, versioned, and changed atomically.
 * ─────────────────────────────────────────────────────────────────────────────
 * Every gateway instance enforces from its own in-memory copy of the policy
 * and keeps the durable copy in Redis. Two things have to be true for several
 * instances to behave as one:
 *
 * 1. A CHANGE IS ONE STEP. The previous adapter removed a rule by reading the
 *    whole list, filtering it in Node, and writing it back (DEL, then RPUSH
 *    for each row). Between that read and that write another instance could
 *    add a rule — and have it overwritten — or make the same removal and
 *    leave half a list behind. Each change is now a single Lua script, which
 *    Redis runs to completion before anything else: there is no "between".
 *
 * 2. EVERY INSTANCE CAN TELL IT IS BEHIND. Nothing told the other instances
 *    that a change had happened; they enforced what they loaded at boot until
 *    they were restarted. The same script that changes the list increments a
 *    version counter, so the version moves if, and only if, the policy did.
 *    An instance remembers the version of the copy it holds and compares it
 *    with Redis's — for free, on the round trip every request already makes
 *    (see authenticate()) — and reloads before going any further if it is
 *    behind. The snapshot it loads is read together with its version, in one
 *    script, so the two always describe the same state.
 *
 * Storage layout:
 *   casbin:policies           List of JSON strings, one row each:
 *                             { "ptype": "p"|"g", "rule": ["sub","obj","act"] }
 *   casbin:policies:version   integer, incremented with every change
 *   casbin:policies:changed   when the last change was made (ms, Redis's clock)
 *   casbin:conditions         Hash: "sub\nobj\nact" -> the attribute condition
 *                             that policy row carries, if it has one (abac.js)
 *
 * A row and its condition are written, and removed, by the same script as
 * each other: there is never a moment at which a conditional policy exists
 * without its condition, which would be a moment at which it grants to
 * everyone holding the role.
 *
 * Why a List?
 *   - Preserves insertion order (useful for debugging, and the order
 *     getRolesForUser reports roles in)
 *   - Simple to inspect with `redis-cli LRANGE casbin:policies 0 -1`
 *
 * A row is identified by its exact JSON text, which is why every writer goes
 * through encodeRow() below: one serialisation, so equal rows are equal bytes.
 */

const { Helper } = require('casbin');

const POLICY_KEY = 'casbin:policies';
const VERSION_KEY = 'casbin:policies:version';
const CHANGED_AT_KEY = 'casbin:policies:changed';
const CONDITIONS_KEY = 'casbin:conditions';

const KEYS = [POLICY_KEY, VERSION_KEY, CONDITIONS_KEY, CHANGED_AT_KEY];

const encodeRow = (ptype, rule) => JSON.stringify({ ptype, rule });

/**
 * Which policy row a condition belongs to. Newline-joined rather than JSON:
 * the scripts build the same key in Lua, whose JSON encoder escapes "/" and
 * would not produce the same text.
 */
const conditionField = (rule) => rule.slice(0, 3).join('\n');

// KEYS[1] = the list, KEYS[2] = the version counter, KEYS[3] = the conditions
// hash, KEYS[4] = the time of the last change — in every script.
const CURRENT_VERSION = "tonumber(redis.call('GET', KEYS[2]) or '0')";

// Moves the version and stamps the change with Redis's own clock, so that how
// long an instance took to catch up can be measured without trusting the
// clocks of two different machines to agree.
const BUMP = `
local function now_ms()
  local t = redis.call('TIME')
  return t[1] * 1000 + math.floor(t[2] / 1000)
end
local function bump()
  redis.call('SET', KEYS[4], string.format('%.0f', now_ms()))
  return redis.call('INCR', KEYS[2])
end
`;

// LPOS (Redis 6.0.6+) answers "is this row present" without copying the list
// into Lua; on an older server the script falls back to scanning it.
const ROW_EXISTS = `
local function row_exists(key, row)
  local found = redis.pcall('LPOS', key, row)
  if type(found) == 'table' and found.err then
    for _, existing in ipairs(redis.call('LRANGE', key, 0, -1)) do
      if existing == row then return true end
    end
    return false
  end
  return found ~= false
end
`;

// RPUSH in slices: Lua's unpack() cannot spread an unbounded table.
const PUSH_ALL = `
local function push_all(key, rows)
  for i = 1, #rows, 500 do
    redis.call('RPUSH', key, unpack(rows, i, math.min(i + 499, #rows)))
  end
end
`;

const SCRIPTS = {
  // -> { version, rows, conditions, changedAt, now }: the policy, the version
  // that describes it, and when that version was written.
  policySnapshot: `
    ${BUMP}
    return {
      ${CURRENT_VERSION},
      redis.call('LRANGE', KEYS[1], 0, -1),
      redis.call('HGETALL', KEYS[3]),
      tonumber(redis.call('GET', KEYS[4]) or '0'),
      now_ms(),
    }
  `,

  // ARGV[1] = row, ARGV[2] = its condition field, ARGV[3] = its condition
  // ('' for none). Adds it unless it is already there -> { added, version }.
  // The duplicate check is part of the same step on purpose: two instances
  // adding one rule at the same moment must leave ONE row, because removing
  // "the" rule later has to remove it entirely.
  policyAdd: `
    ${ROW_EXISTS}
    ${BUMP}
    if row_exists(KEYS[1], ARGV[1]) then return { 0, ${CURRENT_VERSION} } end
    redis.call('RPUSH', KEYS[1], ARGV[1])
    if ARGV[3] ~= '' then redis.call('HSET', KEYS[3], ARGV[2], ARGV[3]) else redis.call('HDEL', KEYS[3], ARGV[2]) end
    return { 1, bump() }
  `,

  // ARGV[1] = row, ARGV[2] = its condition field. Removes every copy of it,
  // and its condition with it -> { removed, version }.
  policyRemove: `
    ${BUMP}
    local removed = redis.call('LREM', KEYS[1], 0, ARGV[1])
    if removed == 0 then return { 0, ${CURRENT_VERSION} } end
    redis.call('HDEL', KEYS[3], ARGV[2])
    return { removed, bump() }
  `,

  // ARGV[1] = ptype, ARGV[2] = first field index (0-based), ARGV[3..] = values
  // to match from that index on; '' matches anything (Casbin's convention).
  // -> { removed, version }
  policyRemoveFiltered: `
    ${PUSH_ALL}
    ${BUMP}
    local first = tonumber(ARGV[2])
    local keep, removed = {}, 0
    for _, row in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
      local ok, parsed = pcall(cjson.decode, row)
      local matches = ok and type(parsed) == 'table' and parsed.ptype == ARGV[1] and type(parsed.rule) == 'table'
      if matches then
        for i = 3, #ARGV do
          if ARGV[i] ~= '' and parsed.rule[first + (i - 3) + 1] ~= ARGV[i] then
            matches = false
            break
          end
        end
      end
      if matches then
        removed = removed + 1
        if parsed.ptype == 'p' and parsed.rule[3] then
          redis.call('HDEL', KEYS[3], parsed.rule[1] .. '\\n' .. parsed.rule[2] .. '\\n' .. parsed.rule[3])
        end
      else
        keep[#keep + 1] = row
      end
    end
    if removed == 0 then return { 0, ${CURRENT_VERSION} } end
    redis.call('DEL', KEYS[1])
    push_all(KEYS[1], keep)
    return { removed, bump() }
  `,

  // ARGV = every row. Replaces the whole policy -> version.
  policyReplaceAll: `
    ${PUSH_ALL}
    ${BUMP}
    redis.call('DEL', KEYS[1])
    push_all(KEYS[1], ARGV)
    return bump()
  `,
};

/**
 * A Casbin adapter (loadPolicy / savePolicy / addPolicy / removePolicy /
 * removeFilteredPolicy) that also knows which version of the policy the
 * enforcer it serves is holding.
 *
 * @param {import('ioredis').Redis} redis
 */
function createPolicyStore(redis) {
  for (const [name, lua] of Object.entries(SCRIPTS)) {
    redis.defineCommand(name, { numberOfKeys: KEYS.length, lua });
  }

  // The condition to store with the next row addPolicy() is asked to add.
  // Casbin's adapter interface has no room for one, and it has to go in with
  // the row — in the same script — so it is parked here by withCondition().
  // That is safe because every use of the enforcer is serialised (withCasbin).
  let pendingCondition = null;

  const parseConditions = (flat) => {
    const conditions = new Map();
    for (let i = 0; i < flat.length; i += 2) {
      try { conditions.set(flat[i], JSON.parse(flat[i + 1])); } catch { /* unreadable: treated as absent */ }
    }
    return conditions;
  };

  const store = {
    /** Version of the policy this instance's enforcer currently holds. */
    loadedVersion: 0,

    /** condition field -> parsed condition, for the policy rows that carry one. */
    conditions: new Map(),

    /** The condition on this policy row, or undefined. */
    conditionFor(rule) {
      return store.conditions.get(conditionField(rule));
    },

    /**
     * Runs `add` (an enforcer.addPolicy call) so that the row it adds is
     * stored together with `condition`. Pass null for an unconditional row.
     */
    async withCondition(condition, add) {
      pendingCondition = condition || null;
      try {
        return await add();
      } finally {
        pendingCondition = null;
      }
    },

    /**
     * Called after each reload with what it showed: how far behind this
     * instance was, on Redis's clock. Set by whoever wants to measure it.
     * @type {((seconds: number) => void)|null}
     */
    onReload: null,

    /** Version of the policy in Redis right now. */
    async currentVersion() {
      return Number(await redis.get(VERSION_KEY)) || 0;
    },

    /**
     * Called by enforcer.loadPolicy(): fills the (already cleared) model from
     * one consistent snapshot, and records which version that snapshot is.
     */
    async loadPolicy(model) {
      const [version, rows, conditions, changedAt, now] = await redis.policySnapshot(...KEYS);

      for (const row of rows) {
        let parsed;
        try {
          parsed = JSON.parse(row);
        } catch {
          console.warn('[Casbin] Skipping malformed policy entry:', row);
          continue;
        }
        // Helper.loadPolicyLine expects a CSV string like "p, sub, obj, act"
        // or "g, user, role"
        Helper.loadPolicyLine([parsed.ptype, ...parsed.rule].join(', '), model);
      }

      store.conditions = parseConditions(conditions);
      const previous = store.loadedVersion;
      store.loadedVersion = version;
      console.log(`[Casbin] Loaded ${rows.length} policy entries from Redis (version ${version})`);
      // Catching up on someone else's change (not the first load at boot).
      if (store.onReload && previous > 0 && version !== previous && changedAt > 0) {
        store.onReload(Math.max(0, now - changedAt) / 1000);
      }
    },

    /** Called by enforcer.savePolicy(): replaces the stored policy with the model's. */
    async savePolicy(model) {
      const rows = [];
      for (const [ptype, assertions] of Object.entries(model.model)) {
        for (const [, assertion] of Object.entries(assertions)) {
          for (const rule of assertion.policy) rows.push(encodeRow(ptype, rule));
        }
      }
      store.loadedVersion = await redis.policyReplaceAll(...KEYS, ...rows);
      return true;
    },

    /** Called by enforcer.addPolicy() / addRoleForUser(). */
    async addPolicy(sec, ptype, rule) {
      const condition = ptype === 'p' ? pendingCondition : null;
      const field = conditionField(rule);
      const [added, version] = await redis.policyAdd(
        ...KEYS, encodeRow(ptype, rule), field, condition ? JSON.stringify(condition) : '',
      );
      if (added && ptype === 'p') {
        if (condition) store.conditions.set(field, condition); else store.conditions.delete(field);
      }
      noteOwnChange(added, version);
    },

    /** Called by enforcer.removePolicy() / deleteRoleForUser(). */
    async removePolicy(sec, ptype, rule) {
      const field = conditionField(rule);
      const [removed, version] = await redis.policyRemove(...KEYS, encodeRow(ptype, rule), field);
      if (ptype === 'p') store.conditions.delete(field);
      noteOwnChange(removed, version);
    },

    /** Called by enforcer.removeFilteredPolicy() / deleteRolesForUser() and friends. */
    async removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues) {
      const [removed, version] = await redis.policyRemoveFiltered(...KEYS, ptype, fieldIndex, ...fieldValues);
      // Which rows went is the script's business; re-read what is left.
      if (removed && ptype === 'p' && store.conditions.size > 0) {
        const left = await redis.hgetall(CONDITIONS_KEY);
        store.conditions = parseConditions(Object.entries(left).flat());
      }
      noteOwnChange(removed, version);
    },
  };

  /**
   * Casbin applies a change to its in-memory model right after the adapter
   * has stored it. If the store went from the version this instance holds
   * straight to the next one, that change is the only thing that happened,
   * so memory and Redis agree again and the instance is at the new version.
   *
   * Any other outcome — the version jumped by more than one, or did not move
   * because another instance had already made the same change — means
   * somebody else has written too. The held version is left where it is, the
   * next freshness check sees the gap, and the instance reloads.
   */
  function noteOwnChange(changed, version) {
    if (changed && version === store.loadedVersion + 1) store.loadedVersion = version;
  }

  return store;
}

module.exports = { createPolicyStore, POLICY_KEY, VERSION_KEY };
