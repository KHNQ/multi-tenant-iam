/**
 * Keycloak's password policy language, enforced wherever a password is set
 * here (an administrator's reset, a user replacing a temporary password).
 *
 *   "length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined)"
 *
 * Unknown policies are ignored rather than refused: a policy the primary system
 * adds later must not stop this one from working, and the primary system
 * enforced it when the password was chosen there.
 */

const DEFAULT_POLICY = 'length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined)';

function parsePolicy(text) {
  const rules = [];
  for (const part of String(text || '').split(/\s+and\s+/i)) {
    const match = /^\s*([A-Za-z]+)\s*(?:\(([^)]*)\))?\s*$/.exec(part);
    if (!match) continue;
    const raw = match[2];
    const number = Number.parseInt(raw, 10);
    rules.push({ name: match[1], value: Number.isFinite(number) ? number : raw });
  }
  return rules;
}

const count = (password, pattern) => (password.match(pattern) || []).length;

/** @returns {string|null} what is wrong with the password, as a sentence fragment */
function passwordProblem(policyText, password, { username, email } = {}) {
  if (typeof password !== 'string' || !password) return 'must not be empty';
  if (password.length > 256) return 'must be at most 256 characters';
  for (const { name, value } of parsePolicy(policyText)) {
    const n = Number.isFinite(value) ? value : 1;
    switch (name) {
      case 'length': if (password.length < n) return `must be at least ${n} characters`; break;
      case 'maxLength': if (password.length > n) return `must be at most ${n} characters`; break;
      case 'upperCase': if (count(password, /\p{Lu}/gu) < n) return `must contain at least ${n} uppercase letter(s)`; break;
      case 'lowerCase': if (count(password, /\p{Ll}/gu) < n) return `must contain at least ${n} lowercase letter(s)`; break;
      case 'digits': if (count(password, /\p{Nd}/gu) < n) return `must contain at least ${n} digit(s)`; break;
      case 'specialChars': if (count(password, /[^\p{L}\p{Nd}]/gu) < n) return `must contain at least ${n} special character(s)`; break;
      case 'notUsername':
        if (username && password.toLowerCase() === String(username).toLowerCase()) return 'must not be the same as the username';
        break;
      case 'notEmail':
        if (email && password.toLowerCase() === String(email).toLowerCase()) return 'must not be the same as the email address';
        break;
      case 'notContainsUsername':
        if (username && password.toLowerCase().includes(String(username).toLowerCase())) return 'must not contain the username';
        break;
      default:
        break;
    }
  }
  return null;
}

module.exports = { parsePolicy, passwordProblem, DEFAULT_POLICY };
