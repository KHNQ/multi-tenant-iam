/**
 * Who is the client, as far as limits are concerned.
 * ─────────────────────────────────────────────────────────────────────────────
 * Every per-address limit in the gateway — sign-in attempts, signups, recovery
 * requests — is only as good as the address it is keyed by. Two things decide
 * that address, and both are handled here:
 *
 *   1. WHICH PROXIES ARE BELIEVED (TRUST_PROXY). Behind a load balancer the
 *      socket address is the balancer's, and the client's is in
 *      X-Forwarded-For — a header the CLIENT can also write. Express takes
 *      the right-most address that was not added by a trusted proxy, so the
 *      setting decides whether a client can choose its own address, and with
 *      it its own rate-limit bucket. A value that trusts everyone, or a whole
 *      address family, is refused at startup rather than run with.
 *
 *   2. HOW AN ADDRESS IS SPELLED. One IPv4 client can appear as "203.0.113.9"
 *      or "::ffff:203.0.113.9", and one IPv6 host normally has a whole /64 to
 *      pick addresses from. Keyed as written, either gives a client as many
 *      buckets as it has spellings. clientKey() folds them together.
 */

const net = require('net');

const NAMED_RANGES = ['loopback', 'linklocal', 'uniquelocal'];
const MAX_HOPS = 5;

class TrustProxyError extends Error {}

/** The IPv4-mapped space, ::ffff:0:0/96. */
function containsMappedSpace(address, prefix) {
  const list = new net.BlockList();
  list.addSubnet(address, prefix, 'ipv6');
  return list.check('::ffff:0.0.0.0', 'ipv6') && list.check('::ffff:255.255.255.255', 'ipv6');
}

function checkEntry(entry) {
  if (NAMED_RANGES.includes(entry)) return;

  const [address, prefixText, extra] = entry.split('/');
  const family = net.isIP(address);
  if (!family || extra !== undefined) {
    throw new TrustProxyError(`'${entry}' is not an address, a subnet, or one of ${NAMED_RANGES.join(', ')}`);
  }
  if (prefixText === undefined) return;

  const prefix = /^\d{1,3}$/.test(prefixText) ? Number(prefixText) : NaN;
  const bits = family === 4 ? 32 : 128;
  if (!(prefix >= 0 && prefix <= bits)) throw new TrustProxyError(`'${entry}' has an invalid prefix length`);

  // The smallest real private ranges are 10.0.0.0/8 and fc00::/7. Anything
  // wider is a large slice of the internet, and /0 is all of it.
  if ((family === 4 && prefix < 8) || (family === 6 && prefix < 7)) {
    throw new TrustProxyError(`'${entry}' trusts far more than a set of proxies — list the subnets your proxies actually connect from`);
  }
  // An IPv6 range that covers ::ffff:0:0/96 covers every IPv4 client too.
  if (family === 6 && prefix < 96 && containsMappedSpace(address, prefix)) {
    throw new TrustProxyError(`'${entry}' contains the IPv4-mapped range (::ffff:0:0/96), so it would trust every IPv4 client`);
  }
}

/**
 * Turns TRUST_PROXY into Express's 'trust proxy' setting, or throws.
 *
 *   unset / "0"          no proxy: the socket address is the client
 *   "1" … "5"            that many proxies in front, each appending one hop.
 *                        Only safe if the gateway cannot be reached except
 *                        through them — a client connecting directly is
 *                        then believed about its own address.
 *   "10.0.0.0/8,…"       the addresses the proxies connect FROM (preferred:
 *                        a client cannot be mistaken for one of them)
 *   "loopback", "linklocal", "uniquelocal"   Express's named ranges
 *
 * @param {string|undefined} raw
 * @returns {false | number | string[]}
 */
function parseTrustProxy(raw) {
  const value = (raw ?? '').trim();
  if (value === '' || value === '0') return false;

  if (/^\d+$/.test(value)) {
    const hops = Number(value);
    if (hops > MAX_HOPS) throw new TrustProxyError(`${hops} proxies in front of the gateway is almost certainly a mistake (at most ${MAX_HOPS})`);
    return hops;
  }
  if (['true', 'false', '*', 'all', 'yes'].includes(value.toLowerCase())) {
    throw new TrustProxyError(`'${value}' would trust every address, letting any client choose its own — give a hop count or the proxies' subnets`);
  }

  const entries = value.split(',').map((entry) => entry.trim()).filter(Boolean);
  if (entries.length === 0) throw new TrustProxyError('no addresses given');
  entries.forEach(checkEntry);
  return entries;
}

function expandIPv6(address) {
  let text = address.toLowerCase().split('%')[0];
  // An embedded IPv4 tail ("::1.2.3.4") becomes two hextets.
  const v4 = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const octets = v4[1].split('.').map(Number);
    text = text.slice(0, -v4[1].length)
      + `${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const [head, tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const fill = tail !== undefined ? 8 - left.length - right.length : 0;
  return [...left, ...Array(Math.max(0, fill)).fill('0'), ...right].map((h) => parseInt(h || '0', 16));
}

/**
 * The bucket an address is counted in: IPv4 as itself (also when written
 * IPv4-mapped), IPv6 by its /64.
 */
function clientKey(address) {
  if (typeof address !== 'string' || address === '') return 'unknown';
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return mapped[1];
  if (net.isIPv4(address)) return address;
  if (!net.isIPv6(address)) return address;

  const hextets = expandIPv6(address);
  // ::ffff:a.b.c.d written in hex is still that IPv4 client.
  if (hextets.slice(0, 5).every((h) => h === 0) && hextets[5] === 0xffff) {
    return [hextets[6] >> 8, hextets[6] & 255, hextets[7] >> 8, hextets[7] & 255].join('.');
  }
  return `${hextets.slice(0, 4).map((h) => h.toString(16)).join(':')}::/64`;
}

module.exports = { parseTrustProxy, clientKey, TrustProxyError };
