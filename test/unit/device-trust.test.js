const { createDeviceTrust } = require('../../src/device-trust');

const secret = 'a-test-secret-that-is-long-enough-for-hkdf-0123456789';

describe('device tokens', () => {
  const trust = createDeviceTrust(secret);

  test('a token names the account and the device it was issued for', () => {
    const read = trust.read(trust.issue('acc-1'));
    expect(read.userId).toBe('acc-1');
    expect(typeof read.deviceId).toBe('string');
  });

  test('renewing keeps the device id', () => {
    const first = trust.read(trust.issue('acc-1'));
    expect(trust.read(trust.issue('acc-1', first.deviceId)).deviceId).toBe(first.deviceId);
  });

  test('a tampered token, one from another secret, or an expired one reads as nothing', () => {
    const token = trust.issue('acc-1');
    const [prefix, body, mac] = token.split('.');
    const otherBody = Buffer.from(JSON.stringify({ u: 'acc-2', d: 'x', exp: 9999999999 })).toString('base64url');
    expect(trust.read(`${prefix}.${otherBody}.${mac}`)).toBeNull();
    expect(trust.read(`${prefix}.${body}.${mac.slice(0, -2)}AA`)).toBeNull();
    expect(createDeviceTrust(`${secret}-other`).read(token)).toBeNull();
    expect(createDeviceTrust(secret, { ttlSeconds: -10 }).read(createDeviceTrust(secret, { ttlSeconds: -10 }).issue('acc-1'))).toBeNull();
    expect(trust.read('not a token')).toBeNull();
    expect(trust.read(undefined)).toBeNull();
  });
});
