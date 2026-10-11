const { createRateLimiter } = require('../../src/ratelimit');

/** Redis's MATCH glob, as a RegExp: \\x is a literal x, * and ? are wildcards. */
function globToRegExp(glob) {
  let source = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '\\') source += glob[++i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    else if (c === '*') source += '.*';
    else if (c === '?') source += '.';
    else source += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${source}$`);
}

/** Just enough of ioredis for the limiter's SCAN-based reset. */
function fakeRedis(keys) {
  return {
    deleted: [],
    patterns: [],
    defineCommand() {},
    async scan(cursor, match, pattern) {
      this.patterns.push(pattern);
      return ['0', keys.filter((k) => globToRegExp(pattern).test(k))];
    },
    async del(...k) { this.deleted.push(...k); },
  };
}

describe('resetPrefix — clearing every sign-in counter for an account', () => {
  test('clears the counters under the prefix, and escapes glob characters in it', async () => {
    const redis = fakeRedis(['ratelimit:login:source:alice|1.2.3.4', 'ratelimit:login:source:alice|::/64']);
    await createRateLimiter(redis).resetPrefix('login:source', 'a*b?[c]|');
    expect(redis.patterns[0]).toBe('ratelimit:login:source:a\\*b\\?\\[c\\]|*');
  });

  test('deletes that account\'s counters and nobody else\'s', async () => {
    const redis = fakeRedis([
      'ratelimit:login:source:alice|1.2.3.4', 'ratelimit:login:source:alice|::/64',
      'ratelimit:login:source:alicex|1.2.3.4', 'ratelimit:login:source:bob|1.2.3.4',
    ]);
    await createRateLimiter(redis).resetPrefix('login:source', 'alice|');
    expect(redis.deleted.sort()).toEqual(['ratelimit:login:source:alice|1.2.3.4', 'ratelimit:login:source:alice|::/64']);
  });
});
