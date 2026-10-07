/**
 * Rate limiting on Redis counters, taken atomically.
 * ─────────────────────────────────────────────────────────────────────────────
 * Counting in Redis is what makes the limit hold across several gateway
 * instances. What makes it hold at all is that "count this request" and "is it
 * over the limit" are ONE operation:
 *
 *   - INCR and EXPIRE as two commands can be split by a crash or a dropped
 *     connection, leaving a counter with no expiry — a limit that never
 *     resets, i.e. a permanent lockout.
 *   - "read the count, do the work, then record the failure" lets any number
 *     of parallel requests all read a count below the limit before one of them
 *     has recorded anything. Five guesses per window becomes five hundred if
 *     they are sent at the same moment.
 *
 * So every request TAKES a slot first, in a single Lua script that increments,
 * sets the window on the first hit, and returns the new count. The caller is
 * over the limit if the count it was handed exceeds the maximum — there is no
 * gap between deciding and counting for another request to slip through. A
 * request that turns out to deserve its slot back (a successful login) returns
 * it afterwards.
 */

// The PTTL < 0 arm repairs a counter that somehow exists without an expiry.
const TAKE_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 or redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return { count, redis.call('PTTL', KEYS[1]) }
`;

// Never below zero, and never recreates a window that has already expired.
const REFUND_SCRIPT = `
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count > 0 then return redis.call('DECR', KEYS[1]) end
return 0
`;

/**
 * @param {import('ioredis').Redis} redis
 * @param {object} [opts]
 * @param {string} [opts.prefix] key namespace
 * @param {(bucket: string) => void} [opts.onLimited] told each time a request does not fit
 */
function createRateLimiter(redis, { prefix = 'ratelimit', onLimited } = {}) {
  redis.defineCommand('rateLimitTake', { numberOfKeys: 1, lua: TAKE_SCRIPT });
  redis.defineCommand('rateLimitRefund', { numberOfKeys: 1, lua: REFUND_SCRIPT });

  const keyFor = (bucket, id) => `${prefix}:${bucket}:${id}`;

  /**
   * Counts this request against the bucket and says whether it fits.
   *
   * @param {string} bucket what is being limited, e.g. 'login:ip'
   * @param {string} id     who, e.g. the address
   * @param {{ max: number, windowSeconds: number }} limit
   * @returns {Promise<{ allowed: boolean, count: number, retryAfterSeconds: number }>}
   */
  async function take(bucket, id, { max, windowSeconds }) {
    const [count, ttlMs] = await redis.rateLimitTake(keyFor(bucket, id), windowSeconds * 1000);
    if (count > max && onLimited) onLimited(bucket);
    return { allowed: count <= max, count, retryAfterSeconds: Math.max(1, Math.ceil(ttlMs / 1000)) };
  }

  /** Gives one slot back — the request it was taken for should not count. */
  async function refund(bucket, id) {
    await redis.rateLimitRefund(keyFor(bucket, id));
  }

  /** Forgets the bucket entirely. */
  async function reset(bucket, id) {
    await redis.del(keyFor(bucket, id));
  }

  /** Forgets every counter in `bucket` whose id starts with `idPrefix`. */
  async function resetPrefix(bucket, idPrefix) {
    const pattern = `${keyFor(bucket, idPrefix).replace(/[*?[\]\\]/g, '\\$&')}*`;
    let cursor = '0';
    do {
      const [next, keys] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 500);
      if (keys.length) await redis.del(...keys);
      cursor = next;
    } while (cursor !== '0');
  }

  return { take, refund, reset, resetPrefix };
}

module.exports = { createRateLimiter };
