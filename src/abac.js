/**
 * Attribute-based conditions on policies.
 * ─────────────────────────────────────────────────────────────────────────────
 * The RBAC model answers "does this account hold a role that may do this to
 * that path". Some rules cannot be said that way: "finance staff may read
 * finance services", "only at clearance 3 or above", "only from the office
 * network", "only during working hours". Those depend on ATTRIBUTES — of the
 * caller, of the resource, of the request — not on who was put in which role.
 *
 * So a policy may carry a condition. Without one it behaves exactly as before
 * (and a deployment that writes no conditions has plain RBAC, at no cost).
 * With one, the policy grants only while the condition holds:
 *
 *     role engineer may GET /reports/*
 *       when  subject.department == resource.department
 *        and  subject.clearance  >= 2
 *
 * A condition is DATA, not code: a small JSON tree that this file validates
 * when it is written and interprets when it is evaluated. Nothing is ever
 * eval()'d, so a tenant admin writing a condition cannot make the gateway run
 * anything.
 *
 *   Condition  := { "all": [Condition, …] }      every one holds
 *               | { "any": [Condition, …] }      at least one holds
 *               | { "not": Condition }
 *               | { "attr": "subject.department", "op": "eq", "value": V }
 *
 *   V          := a string, number or boolean
 *               | a list of those            (for in / nin / cidr)
 *               | { "ref": "resource.department" }    another attribute
 *
 * What a condition can see:
 *
 *   subject.*    id, username, and the attributes a PLATFORM admin has set on
 *                the account (PUT /admin/users/:username/attributes)
 *   resource.*   service, path, and the attributes set on the tenant that
 *                owns the service (PATCH /tenants/:tenantId)
 *   request.*    method, ip
 *   env.*        time (ISO 8601), hour (0–23) and weekday (0 = Sunday), in UTC
 *
 * An attribute that is absent satisfies nothing: every comparison against it
 * is false, including "ne" and "nin". A rule that says "department is not
 * finance" should not be met by an account nobody has described.
 */

const net = require('net');

const NAMESPACES = ['subject', 'resource', 'request', 'env'];
const ATTRIBUTE_PATH = /^(subject|resource|request|env)\.[a-zA-Z][a-zA-Z0-9_]{0,31}$/;
const OPERATORS = ['eq', 'ne', 'in', 'nin', 'gt', 'gte', 'lt', 'lte', 'startsWith', 'cidr', 'exists'];

const MAX_DEPTH = 5;
const MAX_NODES = 40;
const MAX_LIST = 50;

const isScalar = (value) => ['string', 'number', 'boolean'].includes(typeof value)
  && (typeof value !== 'string' || value.length <= 256)
  && (typeof value !== 'number' || Number.isFinite(value));

const isReference = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === 1 && typeof value.ref === 'string';

function isCidr(text) {
  if (typeof text !== 'string') return false;
  const [address, prefix] = text.split('/');
  const family = net.isIP(address);
  if (!family) return false;
  if (prefix === undefined) return true;
  const bits = Number(prefix);
  return /^\d+$/.test(prefix) && bits <= (family === 4 ? 32 : 128);
}

/**
 * @returns {string|null} what is wrong with the condition, or null if it is well formed
 */
function validateCondition(condition) {
  let nodes = 0;

  function check(node, depth) {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) return 'must be an object';
    if (depth > MAX_DEPTH) return `is nested more than ${MAX_DEPTH} levels deep`;
    if ((nodes += 1) > MAX_NODES) return `has more than ${MAX_NODES} parts`;

    const keys = Object.keys(node);

    for (const group of ['all', 'any']) {
      if (group in node) {
        if (keys.length !== 1) return `'${group}' cannot be combined with other keys`;
        if (!Array.isArray(node[group]) || node[group].length === 0) return `'${group}' must be a non-empty list`;
        for (const child of node[group]) {
          const problem = check(child, depth + 1);
          if (problem) return problem;
        }
        return null;
      }
    }
    if ('not' in node) {
      if (keys.length !== 1) return "'not' cannot be combined with other keys";
      return check(node.not, depth + 1);
    }

    if (keys.some((key) => !['attr', 'op', 'value'].includes(key))) {
      return `has an unknown key (allowed: all, any, not, or attr/op/value)`;
    }
    if (typeof node.attr !== 'string' || !ATTRIBUTE_PATH.test(node.attr)) {
      return `names an attribute that is not of the form {${NAMESPACES.join('|')}}.name`;
    }
    if (!OPERATORS.includes(node.op)) return `uses an unknown operator (allowed: ${OPERATORS.join(', ')})`;

    const { op, value } = node;
    if (op === 'exists') {
      return value === undefined || typeof value === 'boolean' ? null : "'exists' takes true or false";
    }
    if (isReference(value)) {
      if (!ATTRIBUTE_PATH.test(value.ref)) return 'refers to an attribute that is not of the form namespace.name';
      return ['in', 'nin', 'cidr'].includes(op) ? `'${op}' needs a list, not a reference` : null;
    }
    if (['in', 'nin', 'cidr'].includes(op)) {
      if (!Array.isArray(value) || value.length === 0 || value.length > MAX_LIST) return `'${op}' needs a list of 1–${MAX_LIST} values`;
      if (op === 'cidr') return value.every(isCidr) ? null : "'cidr' needs a list of IP addresses or CIDR blocks";
      return value.every(isScalar) ? null : `'${op}' needs a list of strings, numbers or booleans`;
    }
    if (!isScalar(value)) return `'${op}' needs a string, number or boolean (or a { "ref": … })`;
    if (['gt', 'gte', 'lt', 'lte'].includes(op) && typeof value === 'boolean') return `'${op}' cannot compare a boolean`;
    return null;
  }

  const problem = check(condition, 1);
  return problem ? `condition ${problem}` : null;
}

function lookup(context, path) {
  const [namespace, name] = path.split('.');
  const bag = context?.[namespace];
  return bag && Object.prototype.hasOwnProperty.call(bag, name) ? bag[name] : undefined;
}

function inNetworks(address, blocks) {
  const family = net.isIP(address);
  if (!family) return false;
  const list = new net.BlockList();
  for (const block of blocks) {
    const [base, prefix] = block.split('/');
    const baseFamily = net.isIP(base);
    list.addSubnet(base, prefix === undefined ? (baseFamily === 4 ? 32 : 128) : Number(prefix), baseFamily === 4 ? 'ipv4' : 'ipv6');
  }
  return list.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

// Ordering is only defined between two numbers or two strings.
const comparable = (a, b) => typeof a === typeof b && (typeof a === 'number' || typeof a === 'string');

function compare(op, actual, expected) {
  switch (op) {
    case 'eq': return actual === expected;
    case 'ne': return actual !== expected;
    case 'in': return expected.includes(actual);
    case 'nin': return !expected.includes(actual);
    case 'gt': return comparable(actual, expected) && actual > expected;
    case 'gte': return comparable(actual, expected) && actual >= expected;
    case 'lt': return comparable(actual, expected) && actual < expected;
    case 'lte': return comparable(actual, expected) && actual <= expected;
    case 'startsWith': return typeof actual === 'string' && typeof expected === 'string' && actual.startsWith(expected);
    case 'cidr': return typeof actual === 'string' && inNetworks(actual, expected);
    default: return false;
  }
}

/**
 * Does the condition hold in this context? Anything it cannot evaluate —
 * a missing attribute, a type that does not compare — makes it not hold.
 *
 * @param {object} condition one that validateCondition() has accepted
 * @param {{ subject?: object, resource?: object, request?: object, env?: object }} context
 */
function evaluateCondition(condition, context) {
  try {
    if ('all' in condition) return condition.all.every((child) => evaluateCondition(child, context));
    if ('any' in condition) return condition.any.some((child) => evaluateCondition(child, context));
    if ('not' in condition) return !evaluateCondition(condition.not, context);

    const actual = lookup(context, condition.attr);
    if (condition.op === 'exists') return (actual !== undefined) === (condition.value !== false);
    if (actual === undefined) return false;

    const expected = isReference(condition.value) ? lookup(context, condition.value.ref) : condition.value;
    if (expected === undefined) return false;
    return compare(condition.op, actual, expected);
  } catch {
    return false;
  }
}

const ATTRIBUTE_NAME = /^[a-zA-Z][a-zA-Z0-9_]{0,31}$/;

/**
 * Checks a bag of attributes being set on an account or a tenant.
 * @returns {string|null}
 */
function validateAttributes(attributes) {
  if (attributes === null || typeof attributes !== 'object' || Array.isArray(attributes)) return 'must be an object of name: value pairs';
  const names = Object.keys(attributes);
  if (names.length > 20) return 'may hold at most 20 attributes';
  for (const name of names) {
    if (!ATTRIBUTE_NAME.test(name)) return `has an invalid attribute name '${name}' (letters, digits and '_', starting with a letter)`;
    if (!isScalar(attributes[name])) return `'${name}' must be a string, number or boolean`;
  }
  return null;
}

module.exports = { validateCondition, evaluateCondition, validateAttributes };
