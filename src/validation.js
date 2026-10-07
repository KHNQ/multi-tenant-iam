/**
 * Request validation — one way of doing it, for every route in both services.
 * ─────────────────────────────────────────────────────────────────────────────
 * Each route declares the shape it accepts:
 *
 *     app.post('/admin/roles',
 *       authenticateJWT, requireAdmin,
 *       validate({ body: { username: v.accountName, role: v.roleName } }),
 *       handler);
 *
 * and the handler then only ever sees input that has that shape. Before this,
 * every handler checked (or forgot to check) its own input in its own way, so
 * the same field could be trimmed in one route and not another, length-limited
 * nowhere, and a body that was not an object at all reached destructuring and
 * became a 500.
 *
 * What a handler receives after validate():
 *   - req.body holds ONLY the declared fields, each trimmed/normalised as its
 *     rule says. Undeclared fields are dropped, not passed along.
 *   - req.params and req.query have been checked against their rules.
 *   - anything else has already been answered with a 400 that names the field.
 *
 * The naming rules themselves (what a username, a role, a tenant id may look
 * like) stay in tenancy.js; this file is about applying them uniformly.
 */

const { validateTenantId, validateRoleName, validateUsername } = require('./tenancy');
const { validateCondition, validateAttributes } = require('./abac');

const pass = (value) => ({ value });
// `standalone` messages are already a full sentence; the others read as a
// predicate and get the field name put in front ("role must be a string").
const fail = (message, standalone = false) => ({ error: message, standalone });

// C0 controls and DEL: never meaningful in any field here, and the way one
// value gets to look like two in a log line or a stored row.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/**
 * @param {object} [o]
 * @param {number} [o.min] minimum length after trimming (0 allows '')
 * @param {number} [o.max]
 * @param {boolean} [o.trim] passwords are the one thing that must not be
 * @param {RegExp} [o.pattern]
 * @param {string} [o.patternMessage]
 */
function string({ min = 1, max = 256, trim = true, pattern, patternMessage } = {}) {
  return (raw) => {
    if (typeof raw !== 'string') return fail('must be a string');
    const value = trim ? raw.trim() : raw;
    if (CONTROL_CHARS.test(value)) return fail('must not contain control characters');
    if (value.length < min) return fail(min <= 1 ? 'must not be empty' : `must be at least ${min} characters`);
    if (value.length > max) return fail(`must be at most ${max} characters`);
    if (pattern && !pattern.test(value)) return fail(patternMessage || 'is not in a valid format');
    return pass(value);
  };
}

/** Runs one of tenancy.js's naming rules, which return null or a full sentence. */
function named(rule, max) {
  const base = string({ max });
  return (raw) => {
    const checked = base(raw);
    if (checked.error) return checked;
    const problem = rule(checked.value);
    return problem ? fail(problem, true) : checked;
  };
}

function oneOf(allowed, { lowercase = false } = {}) {
  return (raw) => {
    if (typeof raw !== 'string') return fail('must be a string');
    const value = lowercase ? raw.trim().toLowerCase() : raw.trim();
    return allowed.includes(value) ? pass(value) : fail(`must be one of: ${allowed.join(', ')}`);
  };
}

function boolean() {
  return (raw) => (typeof raw === 'boolean' ? pass(raw) : fail('must be true or false'));
}

function arrayOf(item, { max = 200 } = {}) {
  return (raw) => {
    if (!Array.isArray(raw)) return fail('must be an array');
    if (raw.length > max) return fail(`must have at most ${max} entries`);
    const values = [];
    for (const entry of raw) {
      const checked = item(entry);
      if (checked.error) return fail(`has an invalid entry — it ${checked.error}`);
      values.push(checked.value);
    }
    return pass(values);
  };
}

/** Absent (or null) is fine and stays absent; present must satisfy the rule. */
function optional(rule) {
  const wrapped = (raw) => (raw === undefined || raw === null ? pass(undefined) : rule(raw));
  wrapped.optional = true;
  return wrapped;
}

function httpUrl({ allowEmpty = false } = {}) {
  const base = string({ min: allowEmpty ? 0 : 1, max: 2048 });
  return (raw) => {
    const checked = base(raw);
    if (checked.error || checked.value === '') return checked;
    let url;
    try { url = new URL(checked.value); } catch { return fail('must be a valid HTTP URL'); }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return fail('must be a valid HTTP URL');
    return checked;
  };
}

// --- THE RULES ROUTES USE ---

const HTTP_ACTIONS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

// A policy resource is a path or a keyMatch pattern over one. Whitespace,
// commas and quotes are excluded because policy rows are round-tripped
// through Casbin's CSV line parser, where they would split or re-quote a row.
const RESOURCE_PATH = /^\/[^\s,"'\\]*$/;

const v = {
  string,
  oneOf,
  boolean,
  arrayOf,
  optional,
  httpUrl,

  /** A username being CHOSEN (signup): the strict naming rule. */
  newUsername: named(validateUsername, 64),
  /**
   * A username being LOOKED UP. Deliberately looser than newUsername: accounts
   * created before the naming rule existed must still be reachable, if only so
   * an admin can delete them.
   */
  accountName: string({ max: 128 }),
  /** A password being SET. Bounded both ways: short is guessable, unbounded is a hashing DoS. */
  newPassword: string({ min: 8, max: 128, trim: false }),
  /** A password being PRESENTED: any string, never rejected for being weak. */
  presentedPassword: string({ max: 1024, trim: false }),

  roleName: named(validateRoleName, 63),
  /** A tenant/service id being CHOSEN: format plus the reserved-name list. */
  newTenantId: named(validateTenantId, 63),
  /** A tenant/service id being LOOKED UP. */
  tenantId: string({ max: 63, pattern: /^[a-z0-9][a-z0-9_-]*$/, patternMessage: 'is not a valid tenant or service id' }),

  /** Role, `t:{tenant}:{role}` or `user:{username}` — resolved by the handler. */
  policySubject: string({ max: 200, pattern: /^[^\s,"'\\]+$/, patternMessage: 'must not contain spaces, commas or quotes' }),
  resourcePath: string({ max: 512, pattern: RESOURCE_PATH, patternMessage: "must be a path starting with '/', without spaces, commas or quotes" }),
  action: oneOf(HTTP_ACTIONS, { lowercase: true }),

  requestId: string({ max: 64, pattern: /^[0-9a-fA-F-]{8,64}$/, patternMessage: 'is not a valid request id' }),
  requestStatus: oneOf(['pending', 'approved', 'rejected', 'cancelled']),

  /** An attribute condition on a policy (abac.js). Bounded: it is evaluated on the request path. */
  condition: (raw) => {
    const problem = validateCondition(raw);
    if (problem) return fail(problem, true);
    return JSON.stringify(raw).length > 4000 ? fail('condition is too large') : pass(raw);
  },
  /** Attributes being set on an account or a tenant. */
  attributes: (raw) => {
    const problem = validateAttributes(raw);
    return problem ? fail(`attributes ${problem}`, true) : pass(raw);
  },

  shortText: string({ max: 120 }),
  /** Free text that may legitimately be empty (a description being cleared). */
  text: (max = 500) => string({ min: 0, max }),
  endpoints: arrayOf(string({ max: 512, pattern: RESOURCE_PATH, patternMessage: "must be a path starting with '/'" })),
};

// --- THE MIDDLEWARE ---

function checkObject(rules, source, problems, { collect }) {
  const clean = {};
  for (const [field, rule] of Object.entries(rules)) {
    const raw = source[field];
    if (raw === undefined || raw === null) {
      if (!rule.optional) problems.push({ field, message: `${field} is required` });
      continue;
    }
    const checked = rule(raw);
    if (checked.error) {
      problems.push({ field, message: checked.standalone ? checked.error : `${field} ${checked.error}` });
    } else if (collect && checked.value !== undefined) {
      clean[field] = checked.value;
    }
  }
  return clean;
}

/**
 * @param {object} shape
 * @param {object} [shape.body]   field -> rule. Presence of this key means the
 *   route takes a JSON object; pass `{}` for "an object, no fields I care about".
 * @param {object} [shape.params] field -> rule
 * @param {object} [shape.query]  field -> rule
 */
function validate({ body, params, query } = {}) {
  return (req, res, next) => {
    const problems = [];

    if (params) checkObject(params, req.params || {}, problems, { collect: false });
    if (query) checkObject(query, req.query || {}, problems, { collect: false });

    if (body) {
      const source = req.body === undefined || req.body === null ? {} : req.body;
      if (typeof source !== 'object' || Array.isArray(source)) {
        problems.push({ field: 'body', message: 'The request body must be a JSON object' });
      } else {
        const clean = checkObject(body, source, problems, { collect: true });
        if (problems.length === 0) req.body = clean;
      }
    }

    if (problems.length > 0) {
      return res.status(400).json({
        error: problems.map((p) => p.message).join('; '),
        details: problems,
      });
    }
    return next();
  };
}

/**
 * Turns body-parser's own failures into the same JSON error shape as
 * everything else, instead of letting them fall through as a 500. Mount it
 * right after express.json().
 */
// eslint-disable-next-line no-unused-vars
function bodyParseErrors(err, req, res, next) {
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'The request body is not valid JSON' });
  }
  if (err?.type === 'entity.too.large') {
    return res.status(413).json({ error: 'The request body is too large' });
  }
  return next(err);
}

/** Largest JSON body either service accepts. */
const JSON_BODY_LIMIT = '64kb';

module.exports = { v, validate, bodyParseErrors, JSON_BODY_LIMIT, HTTP_ACTIONS };
