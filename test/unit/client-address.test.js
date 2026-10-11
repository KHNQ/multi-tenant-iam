const { parseTrustProxy, clientKey, TrustProxyError } = require('../../src/client-address');

describe('TRUST_PROXY', () => {
  test.each([
    [undefined, false],
    ['', false],
    ['0', false],
    ['1', 1],
    ['5', 5],
    ['loopback', ['loopback']],
    ['10.0.0.0/8, 192.168.1.10', ['10.0.0.0/8', '192.168.1.10']],
    ['fc00::/7', ['fc00::/7']],
    ['::ffff:10.0.0.0/104', ['::ffff:10.0.0.0/104']],
  ])('%j is accepted as %j', (raw, expected) => {
    expect(parseTrustProxy(raw)).toEqual(expected);
  });

  test.each(['true', '*', 'all', '6', '0.0.0.0/0', '1.0.0.0/7', '::/0', '::/64', '10.0.0.0/33', 'banana', '1.2.3.4/8/9'])(
    '%j is refused',
    (raw) => { expect(() => parseTrustProxy(raw)).toThrow(TrustProxyError); },
  );
});

describe('clientKey — one bucket per client however it is written', () => {
  test.each([
    ['203.0.113.9', '203.0.113.9'],
    ['::ffff:203.0.113.9', '203.0.113.9'],
    ['::FFFF:cb00:7109', '203.0.113.9'],
    ['2001:db8:1:2:aaaa::1', '2001:db8:1:2::/64'],
    ['2001:db8:1:2::ffff', '2001:db8:1:2::/64'],
    ['2001:db8:1:3::1', '2001:db8:1:3::/64'],
    ['fe80::1%lo0', 'fe80:0:0:0::/64'],
    [undefined, 'unknown'],
  ])('%j -> %j', (address, key) => {
    expect(clientKey(address)).toBe(key);
  });
});
