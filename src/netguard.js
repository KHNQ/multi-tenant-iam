/**
 * Outbound destination control.
 * ─────────────────────────────────────────────────────────────────────────────
 * A service's baseUrl and catalogUrl are typed in by whoever registers it, and
 * any signed-in user may register one. The gateway then proxies to that URL and
 * the registry fetches it on a timer — so without a rule about where those
 * connections may go, "register a service" means "make the platform issue
 * requests from inside its own network to an address of my choosing": Redis on
 * localhost, the registry's own admin surface, a cloud metadata endpoint.
 *
 * The rule is an allowlist, and it is applied to the address a connection
 * actually goes to rather than to the text of the URL:
 *
 *   UPSTREAM_ALLOWED_CIDRS   networks a destination may be in. REQUIRED — with
 *                            none configured, nothing is reachable.
 *   UPSTREAM_ALLOWED_HOSTS   optional. If set, the URL's host must also match
 *                            one of these names ("api.internal", "*.svc.local").
 *   UPSTREAM_ALLOWED_PORTS   optional. If set, the port must be one of these
 *                            ("8080", "9000-9099").
 *
 * Checking the URL text alone is not enough, because a hostname is a promise
 * that can change: it can resolve to an allowed address when it is registered
 * and to 169.254.169.254 a minute later (DNS rebinding), or carry one public
 * and one internal A record. So the resolution is done here, every resolved
 * address is checked, and the socket is opened to exactly the address that was
 * checked — the name is never resolved a second time by something else.
 */

const dns = require('dns');
const http = require('http');
const https = require('https');
const net = require('net');

/** `err.code` on a connection refused by this guard rather than by the network. */
const DESTINATION_NOT_ALLOWED = 'EDESTNOTALLOWED';

function parseList(raw) {
  return String(raw || '').split(',').map((s) => s.trim()).filter(Boolean);
}

/** URL.hostname as a comparable name: no IPv6 brackets, no trailing dot, lower case. */
function normaliseHost(hostname) {
  return String(hostname || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
}

function parseNetworks(raw, source) {
  // net.BlockList is only a CIDR matcher; here it holds what is ALLOWED. It
  // also matches IPv4-mapped IPv6 (::ffff:127.0.0.1) against IPv4 rules, so
  // that spelling cannot be used to step around a rule.
  const networks = new net.BlockList();
  const labels = [];
  for (const entry of parseList(raw)) {
    const [address, prefixText] = entry.split('/');
    const family = net.isIP(address);
    const bits = family === 4 ? 32 : 128;
    const prefix = prefixText === undefined ? bits : Number(prefixText);
    if (!family || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) {
      throw new Error(`${source}: '${entry}' is not an IP address or CIDR block`);
    }
    networks.addSubnet(address, prefix, family === 4 ? 'ipv4' : 'ipv6');
    labels.push(`${address}/${prefix}`);
  }
  return { networks, labels };
}

function parsePorts(raw, source) {
  const ranges = parseList(raw).map((entry) => {
    const [from, to = from] = entry.split('-').map(Number);
    if (![from, to].every((p) => Number.isInteger(p) && p >= 1 && p <= 65535) || from > to) {
      throw new Error(`${source}: '${entry}' is not a port or port range`);
    }
    return [from, to];
  });
  return ranges.length ? ranges : null;
}

/**
 * @param {object} config
 * @param {string} [config.cidrs] comma-separated networks a destination may be in
 * @param {string} [config.hosts] comma-separated host names / `*.suffix` patterns
 * @param {string} [config.ports] comma-separated ports / `from-to` ranges
 */
function createDestinationGuard({ cidrs, hosts, ports } = {}) {
  const { networks, labels } = parseNetworks(cidrs, 'UPSTREAM_ALLOWED_CIDRS');
  const hostPatterns = parseList(hosts).map((h) => h.toLowerCase());
  const portRanges = parsePorts(ports, 'UPSTREAM_ALLOWED_PORTS');

  function addressAllowed(address) {
    const family = net.isIP(address);
    return family !== 0 && networks.check(address, family === 4 ? 'ipv4' : 'ipv6');
  }

  function hostAllowed(hostname) {
    if (hostPatterns.length === 0) return true;
    return hostPatterns.some((pattern) => (pattern.startsWith('*.')
      ? hostname.endsWith(pattern.slice(1))
      : hostname === pattern));
  }

  /**
   * Everything that can be decided from the URL itself. Returns null if it is
   * acceptable so far, otherwise the reason, phrased to follow the field name
   * ("baseUrl points at ...").
   *
   * A hostname passing here is not yet allowed — what it resolves to is
   * checked at connect time by `lookup`. A literal IP address never reaches
   * that lookup, so it is decided here in full.
   */
  function check(rawUrl) {
    let url;
    try { url = new URL(rawUrl); } catch { return 'is not a valid URL'; }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'must be an http:// or https:// URL';
    if (url.username || url.password) return 'must not carry credentials';

    const hostname = normaliseHost(url.hostname);
    if (!hostname) return 'has no host';

    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
    if (portRanges && !portRanges.some(([from, to]) => port >= from && port <= to)) {
      return `uses port ${port}, which is not an allowed destination port`;
    }
    if (!hostAllowed(hostname)) return `names '${hostname}', which is not an allowed destination host`;
    if (net.isIP(hostname) && !addressAllowed(hostname)) {
      return `points at ${hostname}, which is outside the allowed destination networks`;
    }
    return null;
  }

  /**
   * A drop-in for dns.lookup that only ever hands back addresses inside the
   * allowed networks. One address outside them fails the whole lookup: a name
   * with a public record and an internal one is not "mostly fine".
   */
  function lookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (typeof options === 'number') options = { family: options };

    dns.lookup(hostname, { ...options, all: true }, (err, results) => {
      if (err) return callback(err);

      const outside = results.find((r) => !addressAllowed(r.address));
      if (outside || results.length === 0) {
        const refused = new Error(
          `'${hostname}' resolves to ${outside ? outside.address : 'no address'}, which is outside the allowed destination networks`,
        );
        refused.code = DESTINATION_NOT_ALLOWED;
        refused.resolvedTo = outside ? outside.address : null;
        return callback(refused);
      }
      if (options.all) return callback(null, results);
      return callback(null, results[0].address, results[0].family);
    });
  }

  // Sockets opened through these agents connect to an address `lookup` has
  // approved, and to nothing else.
  const httpAgent = new http.Agent({ lookup });
  const httpsAgent = new https.Agent({ lookup });
  const agentFor = (url) => (new URL(url).protocol === 'https:' ? httpsAgent : httpAgent);

  /**
   * check() plus a resolution, for telling someone at registration time that
   * what they typed will not work. It is advice, not the control: the name is
   * resolved again, and checked again, on every connection.
   *
   * @returns {Promise<{ reason: string|null, unresolved?: string }>}
   */
  function inspect(rawUrl) {
    const reason = check(rawUrl);
    if (reason) return Promise.resolve({ reason });

    const hostname = normaliseHost(new URL(rawUrl).hostname);
    if (net.isIP(hostname)) return Promise.resolve({ reason: null });

    return new Promise((resolve) => {
      lookup(hostname, { all: true }, (err) => {
        if (!err) return resolve({ reason: null });
        if (err.code === DESTINATION_NOT_ALLOWED) {
          return resolve({
            reason: `names '${hostname}', which resolves to ${err.resolvedTo || 'no address'} — outside the allowed destination networks`,
          });
        }
        return resolve({ reason: null, unresolved: err.code || err.message });
      });
    });
  }

  return {
    check,
    inspect,
    lookup,
    agentFor,
    /** False when no network is allowed at all — i.e. every destination is refused. */
    configured: labels.length > 0,
    describe: () => `networks [${labels.join(', ') || 'none'}]`
      + `, hosts [${hostPatterns.join(', ') || 'any'}]`
      + `, ports [${portRanges ? portRanges.map(([a, b]) => (a === b ? a : `${a}-${b}`)).join(', ') : 'any'}]`,
  };
}

/** The guard both the gateway and the registry build from their environment. */
function createDestinationGuardFromEnv(env = process.env) {
  return createDestinationGuard({
    cidrs: env.UPSTREAM_ALLOWED_CIDRS,
    hosts: env.UPSTREAM_ALLOWED_HOSTS,
    ports: env.UPSTREAM_ALLOWED_PORTS,
  });
}

module.exports = {
  createDestinationGuard,
  createDestinationGuardFromEnv,
  DESTINATION_NOT_ALLOWED,
};
