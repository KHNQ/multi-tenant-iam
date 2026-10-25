/**
 * Passwords: the hashes imported from the primary system, and new ones set here.
 * ─────────────────────────────────────────────────────────────────────────────
 * Keycloak stores an Argon2 hash as raw base64 (`secret_data.value`, `.salt`)
 * with its parameters alongside (`credential_data`). Those are turned into a
 * standard PHC string —
 *
 *     $argon2id$v=19$m=7168,t=5,p=1$<salt>$<hash>
 *
 * — and verified like any other Argon2 hash, so a user signs in here with the
 * very password they use there. The parameters are read from each user's own
 * credential, never assumed: hashes made before the primary system changed its
 * settings keep theirs. An algorithm this system cannot verify (pbkdf2, say) is
 * not imported, and the import report says so.
 *
 * Stored hashes are sealed (AES-GCM) at rest. Nothing here is ever logged.
 */

const argon2 = require('argon2');

const ARGON2_TYPES = { id: 'argon2id', i: 'argon2i', d: 'argon2d' };
const VERSIONS = { '1.3': 19, '19': 19, '1.0': 16, '16': 16 };

const first = (value) => (Array.isArray(value) ? value[0] : value);
const unpad = (b64) => String(b64).replace(/=+$/, '');
const isBase64 = (value) => typeof value === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length >= 8;

/**
 * @param {object} credentialData Keycloak's credential_data (object or JSON string)
 * @param {object} secretData     Keycloak's secret_data (object or JSON string)
 * @returns {{ phc: string } | { problem: string }}
 */
function phcFromKeycloak(credentialData, secretData) {
  let data;
  let secret;
  try {
    data = typeof credentialData === 'string' ? JSON.parse(credentialData) : credentialData;
    secret = typeof secretData === 'string' ? JSON.parse(secretData) : secretData;
  } catch {
    return { problem: 'credential_data or secret_data is not valid JSON' };
  }
  if (!data || !secret) return { problem: 'credential_data and secret_data are required' };
  if (data.algorithm !== 'argon2') return { problem: `unsupported algorithm '${data.algorithm}'` };

  const extra = data.additionalParameters || {};
  const type = ARGON2_TYPES[first(extra.type) || 'id'];
  if (!type) return { problem: `unsupported argon2 type '${first(extra.type)}'` };
  const version = VERSIONS[String(first(extra.version) || '1.3')];
  if (!version) return { problem: `unsupported argon2 version '${first(extra.version)}'` };
  const memory = Number.parseInt(first(extra.memory), 10);
  const parallelism = Number.parseInt(first(extra.parallelism), 10);
  const iterations = Number.parseInt(data.hashIterations, 10);
  const hashLength = Number.parseInt(first(extra.hashLength), 10);
  for (const [name, value, min, max] of [
    ['memory', memory, 8, 4 * 1024 * 1024], ['parallelism', parallelism, 1, 64],
    ['hashIterations', iterations, 1, 100], ['hashLength', hashLength, 16, 128],
  ]) {
    if (!Number.isInteger(value) || value < min || value > max) return { problem: `argon2 ${name} '${value}' is out of range` };
  }
  if (!isBase64(secret.value) || !isBase64(secret.salt)) return { problem: 'secret_data must carry base64 value and salt' };
  if (Buffer.from(secret.value, 'base64').length !== hashLength) return { problem: 'the hash length does not match hashLength' };

  return { phc: `$${type}$v=${version}$m=${memory},t=${iterations},p=${parallelism}$${unpad(secret.salt)}$${unpad(secret.value)}` };
}

function createCredentials({ store, sealer }) {
  // Verifying against this when the account does not exist (or has no
  // password here) costs about what a real verification does, so the answer
  // takes as long whether or not the name is known.
  const dummy = argon2.hash('not-a-password-' + Math.random(), { type: argon2.argon2id });

  async function read(realm, userId) {
    const sealed = await store.getCredential(realm, userId);
    if (!sealed) return null;
    try { return JSON.parse(sealer.unseal(sealed)); } catch { return null; }
  }

  /** @returns {Promise<boolean>} */
  async function verify(realm, userId, password) {
    const credential = userId ? await read(realm, userId) : null;
    if (!credential?.phc) {
      await argon2.verify(await dummy, password).catch(() => false);
      return false;
    }
    try {
      return await argon2.verify(credential.phc, password);
    } catch {
      return false;
    }
  }

  async function write(realm, userId, credential) {
    await store.setCredential(realm, userId, sealer.seal(JSON.stringify(credential)));
  }

  /** A password chosen here (primary mode, or a local account). */
  async function setPassword(realm, userId, password, { temporary = false } = {}) {
    const phc = await argon2.hash(password, { type: argon2.argon2id });
    await write(realm, userId, { type: 'password', algorithm: 'argon2', phc, createdDate: Date.now(), source: 'local', temporary });
  }

  /** An imported hash. */
  async function importKeycloak(realm, userId, { credentialData, secretData, createdDate }) {
    const built = phcFromKeycloak(credentialData, secretData);
    if (built.problem) return built;
    await write(realm, userId, { type: 'password', algorithm: 'argon2', phc: built.phc, createdDate: createdDate || Date.now(), source: 'sync' });
    return { ok: true };
  }

  const has = (realm, userId) => store.hasCredential(realm, userId);

  return { verify, setPassword, importKeycloak, has, read };
}

module.exports = { createCredentials, phcFromKeycloak };
