/**
 * How a service talks to the registry about itself.
 * ─────────────────────────────────────────────────────────────────────────────
 * Four separate operations, because they are four separate things:
 *
 *   register     once. Creates the record; the registry answers with a service
 *                token, which is the proof of owning that name from then on.
 *                The registry only creates records for callers it can
 *                authenticate, so this presents REGISTRY_ENROLLMENT_TOKEN —
 *                the credential the operator issues to services that are
 *                meant to register themselves.
 *   renew        every later start. POST /services/:name/heartbeat with the
 *                token — "I am up again". Carries no configuration and cannot
 *                change any.
 *   update       only when what this process serves differs from what is
 *                registered. An authenticated PATCH of exactly those fields.
 *   deregister   on shutdown. An authenticated DELETE.
 *
 * The token therefore has to outlive the process. It is kept in a file only
 * its owner can read (SERVICE_TOKEN_DIR, default .run/service-tokens/), or
 * supplied as SERVICE_TOKEN for a single-service process whose deployment
 * manages secrets itself.
 */

const fs = require('fs');
const path = require('path');

const TOKEN_DIR = process.env.SERVICE_TOKEN_DIR || path.join(__dirname, '..', '.run', 'service-tokens');

const tokenFile = (name) => path.join(TOKEN_DIR, `${name}.token`);

function readToken(name) {
  try {
    const stored = fs.readFileSync(tokenFile(name), 'utf8').trim();
    if (stored) return stored;
  } catch { /* no token file yet */ }
  return process.env.SERVICE_TOKEN || null;
}

function storeToken(name, token) {
  fs.mkdirSync(TOKEN_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(tokenFile(name), `${token}\n`, { mode: 0o600 });
  fs.chmodSync(tokenFile(name), 0o600); // mode above is ignored if the file existed
}

function forgetToken(name) {
  fs.rmSync(tokenFile(name), { force: true });
}

const sameList = (a = [], b = []) => a.length === b.length && [...a].sort().join('\n') === [...b].sort().join('\n');

/**
 * @param {object} opts
 * @param {string} opts.registryUrl
 * @param {object} opts.log a logger from ./logger
 */
function createRegistryClient({ registryUrl, log }) {
  async function call(method, route, { token, enroll, body } = {}) {
    const response = await fetch(`${registryUrl}${route}`, {
      // Carries the service token: a redirect is an error, not a hop.
      redirect: 'error',
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'X-Service-Token': token } : {}),
        ...(enroll && process.env.REGISTRY_ENROLLMENT_TOKEN
          ? { 'X-Enrollment-Token': process.env.REGISTRY_ENROLLMENT_TOKEN } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    let data = null;
    try { data = await response.json(); } catch { /* no body */ }
    return { ok: response.ok, status: response.status, data };
  }

  /** The fields of `service` that differ from what the registry holds. */
  function drift(service, registered) {
    const changed = {};
    for (const field of ['baseUrl', 'catalogUrl', 'version', 'owner']) {
      if (service[field] !== undefined && service[field] !== registered[field]) changed[field] = service[field];
    }
    if (service.endpoints && !sameList(service.endpoints, registered.endpoints)) changed.endpoints = service.endpoints;
    return changed;
  }

  /**
   * One attempt at making the registry agree with `service`.
   * @returns {Promise<'renewed'|'updated'|'registered'>}
   */
  async function announceOnce(service) {
    const { name } = service;
    const token = readToken(name);

    if (token) {
      const renewal = await call('POST', `/services/${name}/heartbeat`, { token });
      if (renewal.ok) {
        const changed = drift(service, renewal.data.service);
        if (Object.keys(changed).length === 0) return 'renewed';

        const update = await call('PATCH', `/services/${name}`, { token, body: changed });
        if (!update.ok) throw new Error(update.data?.error || `update failed with HTTP ${update.status}`);
        return 'updated';
      }
      if (renewal.status === 403) {
        // The name exists and this token does not open it. Registering again
        // would be refused for the same reason, so say what is wrong instead.
        const refused = new Error(
          `the registry holds '${name}' under a different service token — it was registered by someone else, `
          + `or re-registered since ${tokenFile(name)} was written`,
        );
        refused.fatal = true;
        throw refused;
      }
      if (renewal.status !== 404) {
        throw new Error(renewal.data?.error || `renewal failed with HTTP ${renewal.status}`);
      }
      // 404: the registry no longer has the record. The token is for a
      // registration that is gone; start again.
      forgetToken(name);
    }

    const { name: _n, ...config } = service;
    const registration = await call('POST', '/register', { enroll: true, body: { name, ...config } });
    if (registration.ok) {
      if (registration.data.serviceToken) storeToken(name, registration.data.serviceToken);
      return 'registered';
    }
    if (registration.status === 401) {
      const unauthenticated = new Error(
        process.env.REGISTRY_ENROLLMENT_TOKEN
          ? 'the registry rejected REGISTRY_ENROLLMENT_TOKEN — it must be the same value the registry was started with'
          : 'the registry only registers new services for authenticated callers. Set REGISTRY_ENROLLMENT_TOKEN '
            + '(the value the registry was started with), or register this service through the gateway instead',
      );
      unauthenticated.fatal = true;
      throw unauthenticated;
    }
    if (registration.status === 409) {
      const taken = new Error(
        `'${name}' is already registered and this process holds no token for it. `
        + 'An existing record can only be changed by its owner: supply its token as SERVICE_TOKEN, '
        + 'or have the operator remove the stale record so it can be registered afresh '
        + '(README, Appendix A: "Self-registering services keep a token")',
      );
      taken.fatal = true;
      throw taken;
    }
    const failure = new Error(registration.data?.error || `HTTP ${registration.status}`);
    // A 4xx is the registry saying this request will never be accepted.
    failure.fatal = registration.status >= 400 && registration.status < 500;
    throw failure;
  }

  /**
   * Registers, renews or updates `service` so the registry matches it,
   * retrying while the registry is still coming up.
   *
   * @param {object} service { name, baseUrl, catalogUrl?, owner?, version?, endpoints? }
   * @returns {Promise<boolean>} whether the registry now has it
   */
  async function announce(service, { retries = 5, delayMs = 2000 } = {}) {
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const outcome = await announceOnce(service);
        log.audit('registration', `Service '${service.name}' ${outcome} with the Service Registry`, {
          name: service.name, outcome,
        });
        return true;
      } catch (err) {
        if (err.fatal) {
          log.error('registration', `Cannot register '${service.name}': ${err.message}`, { name: service.name });
          return false;
        }
        log.warn('registration', `Registration attempt ${attempt} failed: ${err.message}`, { attempt });
        if (attempt < retries) await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
    // Non-fatal: the service still runs, the registry just doesn't know about it.
    log.error('registration', `All registration attempts failed for '${service.name}'. Running unregistered.`);
    return false;
  }

  /** Removes the record on shutdown. Needs the token, like every other change. */
  async function deregister(name) {
    const token = readToken(name);
    if (!token) {
      log.warn('registration', `Not deregistering '${name}': no service token held for it`);
      return false;
    }
    try {
      const result = await call('DELETE', `/services/${name}`, { token });
      if (result.ok || result.status === 404) forgetToken(name);
      if (result.ok) log.audit('registration', `Deregistered '${name}' from the Service Registry`);
      else log.warn('registration', `Could not deregister '${name}': ${result.data?.error || result.status}`);
      return result.ok;
    } catch (err) {
      log.warn('registration', `Could not deregister '${name}': ${err.message}`);
      return false;
    }
  }

  return { announce, deregister };
}

module.exports = { createRegistryClient };
