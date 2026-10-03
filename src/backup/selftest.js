#!/usr/bin/env node
/**
 * Self-test of the backup and recovery procedure.
 * ─────────────────────────────────────────────────────────────────────────────
 * Runs the whole cycle — keys, backup, verification, decryption, restore — and
 * the ways it has to fail, against a Redis this script starts and throws away.
 * It never connects to the IAM's own Redis, so it is safe to run anywhere that
 * has redis-server and redis-cli on PATH.
 *
 *   npm run backup:selftest
 *
 * What it proves is the mechanism. That last night's actual backup restores is
 * what `npm run backup:drill` proves, on the host that holds the decryption key.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const {
  backup, verify, decrypt, drill, generateKeys, startScratchRedis, connect,
  KEY_FILES, FILE_SUFFIX, MANIFEST_SUFFIX, CANARY_KEY, LAST_SUCCESS_KEY,
} = require('./redis-backup');

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`  ✅ ${name}`);
  } catch (err) {
    results.push({ name, ok: false });
    console.log(`  ❌ ${name}\n     ${err.message}`);
  }
}
function assert(condition, message) { if (!condition) throw new Error(message); }
async function refuses(promise, pattern, what) {
  try {
    await promise;
  } catch (err) {
    assert(pattern.test(err.message), `${what}: refused, but for the wrong reason — ${err.message}`);
    return;
  }
  throw new Error(`${what}: was accepted`);
}

/**
 * Every key with its type and value, for an exact before/after comparison.
 * Read by type rather than with DUMP: a hash or set stored as a hash table
 * serializes in whatever order that process's table happens to iterate.
 */
async function contentsOf(redis) {
  const readers = {
    string: async (key) => (await redis.getBuffer(key)).toString('base64'),
    list: (key) => redis.lrange(key, 0, -1),
    hash: async (key) => Object.entries(await redis.hgetall(key)).sort(([a], [b]) => (a < b ? -1 : 1)),
    set: async (key) => (await redis.smembers(key)).sort(),
    zset: (key) => redis.zrange(key, 0, -1, 'WITHSCORES'),
  };
  const contents = new Map();
  for (const key of (await redis.keys('*')).sort()) {
    const type = await redis.type(key);
    if (!readers[type]) throw new Error(`selftest cannot compare a key of type ${type} (${key})`);
    contents.set(key, JSON.stringify([type, await readers[type](key)]));
  }
  return contents;
}

async function seed(redis) {
  const pipeline = redis.pipeline();
  for (let i = 0; i < 250; i++) {
    const id = crypto.randomUUID();
    pipeline.hset('users:ids', id, `selftest_user_${i}`);
    pipeline.hset(`user:selftest_user_${i}`, {
      id, role: 'user', status: 'active', tokenVersion: String(i % 7),
      password: `$argon2id$v=19$m=65536,t=3,p=4$${crypto.randomBytes(16).toString('base64')}$${crypto.randomBytes(32).toString('base64')}`,
    });
    pipeline.rpush('casbin:policies', JSON.stringify({ ptype: 'g', rule: [`u:${id}`, 'r:service_user'] }));
  }
  pipeline.rpush('casbin:policies', JSON.stringify({ ptype: 'p', rule: ['r:service_user', '/llm/*', 'get'] }));
  pipeline.set('casbin:policies:version', '42');
  pipeline.hset('casbin:conditions', 'r:service_user\n/llm/*\nget', JSON.stringify({ attr: 'user.department', op: 'eq', value: 'radiology' }));
  pipeline.sadd('tenant:selftest:perm:members', 'selftest_user_1', 'selftest_user_2');
  pipeline.zadd('selftest:sorted', 1, 'one', 2, 'two');
  pipeline.set('binary:value', crypto.randomBytes(4096)); // an RDB is not text; neither is this
  pipeline.set('expiring:value', 'x', 'EX', 86400);
  await pipeline.exec();
}

async function main() {
  console.log('\nBackup and recovery self-test (against a throwaway Redis)\n');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-backup-selftest-'));
  const dirs = Object.fromEntries(['source', 'keys', 'otherKeys', 'store', 'out'].map((name) => {
    fs.mkdirSync(path.join(work, name));
    return [name, path.join(work, name)];
  }));
  const keyFile = (dir, which) => path.join(dir, KEY_FILES[which]);
  let source;

  try {
    source = await startScratchRedis(dirs.source);
    const redisUrl = `redis://127.0.0.1:${source.port}`;
    await seed(source.redis);

    generateKeys(dirs.keys, { passphrase: 'selftest passphrase' });
    generateKeys(dirs.otherKeys);
    const passphrase = 'selftest passphrase';
    const settings = {
      redisUrl, directory: dirs.store, allowSameDevice: true, retentionCount: 3,
      encryptionKeyFile: keyFile(dirs.keys, 'encryption'), signingKeyFile: keyFile(dirs.keys, 'signing'),
    };
    const restorer = {
      verificationKeyFile: keyFile(dirs.keys, 'verification'),
      decryptionKeyFile: keyFile(dirs.keys, 'decryption'), passphrase,
    };
    let taken;
    let before;

    await test('A backup is taken from a running Redis', async () => {
      taken = await backup(settings);
      before = await contentsOf(source.redis);
      assert(fs.existsSync(taken.file), 'the backup file is missing');
      assert(taken.manifest.facts.accounts === 250, `accounts recorded: ${taken.manifest.facts.accounts}`);
      assert(await source.redis.get(CANARY_KEY) === taken.id, 'the canary was not written');
      assert(Number(await source.redis.get(LAST_SUCCESS_KEY)) > 0, 'the completion time was not recorded');
      assert(fs.readdirSync(dirs.store).every((name) => !name.endsWith('.partial')), 'a partial file was left behind');
    });

    await test('The same disk as Redis is refused as a destination', async () => {
      await refuses(backup({ ...settings, allowSameDevice: false }), /same disk as Redis/, 'a backup beside Redis\'s own data');
    });

    await test('The backup is not readable: no plaintext, and files are private', async () => {
      const bytes = fs.readFileSync(taken.file);
      assert(!bytes.includes('selftest_user_'), 'a username is visible in the backup file');
      assert(!bytes.includes('$argon2id$'), 'a password hash is visible in the backup file');
      assert(!bytes.includes('REDIS0'), 'the RDB header is visible in the backup file');
      assert((fs.statSync(taken.file).mode & 0o077) === 0, 'the backup file is readable by other users');
      const manifestText = fs.readFileSync(taken.file.replace(FILE_SUFFIX, MANIFEST_SUFFIX), 'utf8');
      assert(!manifestText.includes('selftest_user_'), 'the manifest names an account');
    });

    await test('The IAM host\'s own keys cannot decrypt what it wrote', async () => {
      const out = path.join(dirs.out, 'with-host-keys.rdb');
      for (const which of ['encryption', 'signing']) {
        await refuses(decrypt({ file: taken.file, out, decryptionKeyFile: keyFile(dirs.keys, which) }),
          /not a usable private key|not the key|could not be unwrapped/, `decrypting with the ${which} key`);
      }
      assert(!fs.existsSync(out), 'something was written');
    });

    await test('Verification needs no secret, and passes for an untouched backup', async () => {
      const manifest = await verify({ file: taken.file, verificationKeyFile: restorer.verificationKeyFile });
      assert(manifest.id === taken.id, 'wrong manifest');
    });

    await test('The wrong decryption key, or the wrong passphrase, gets nothing', async () => {
      const out = path.join(dirs.out, 'wrong-key.rdb');
      await refuses(decrypt({ file: taken.file, out, decryptionKeyFile: keyFile(dirs.otherKeys, 'decryption') }),
        /not the key/, 'another key pair');
      await refuses(decrypt({ file: taken.file, out, decryptionKeyFile: restorer.decryptionKeyFile, passphrase: 'not it' }),
        /wrong passphrase/, 'a wrong passphrase');
      assert(!fs.existsSync(out) && !fs.existsSync(`${out}.partial`), 'something was written');
    });

    await test('A single changed byte is detected — by the checksum, and by decryption on its own', async () => {
      const damaged = path.join(dirs.out, `damaged${FILE_SUFFIX}`);
      const bytes = fs.readFileSync(taken.file);
      bytes[Math.floor(bytes.length / 2)] ^= 0x01;
      fs.writeFileSync(damaged, bytes);
      fs.copyFileSync(taken.file.replace(FILE_SUFFIX, MANIFEST_SUFFIX), damaged.replace(FILE_SUFFIX, MANIFEST_SUFFIX));

      await refuses(verify({ file: damaged, verificationKeyFile: restorer.verificationKeyFile }), /does not match the SHA-256/, 'verifying a damaged file');
      const out = path.join(dirs.out, 'damaged.rdb');
      await refuses(decrypt({ file: damaged, out, ...restorer }), /failed authentication/, 'decrypting a damaged file');
      assert(!fs.existsSync(out) && !fs.existsSync(`${out}.partial`), 'unauthenticated plaintext was left on disk');
    });

    await test('A truncated backup is detected', async () => {
      const short = path.join(dirs.out, `short${FILE_SUFFIX}`);
      fs.writeFileSync(short, fs.readFileSync(taken.file).subarray(0, -200));
      await refuses(decrypt({ file: short, out: path.join(dirs.out, 'short.rdb'), ...restorer }), /failed authentication/, 'a truncated file');
    });

    await test('An altered manifest is detected', async () => {
      const copy = path.join(dirs.out, `edited${FILE_SUFFIX}`);
      fs.copyFileSync(taken.file, copy);
      const manifest = JSON.parse(fs.readFileSync(taken.file.replace(FILE_SUFFIX, MANIFEST_SUFFIX), 'utf8'));
      manifest.facts.accounts = 1; // nested, so this also checks the signature covers every level
      fs.writeFileSync(copy.replace(FILE_SUFFIX, MANIFEST_SUFFIX), JSON.stringify(manifest));
      await refuses(verify({ file: copy, verificationKeyFile: restorer.verificationKeyFile }), /signature does not verify/, 'an edited manifest');
    });

    await test('A backup forged with the public encryption key is refused', async () => {
      // Whoever can write to the backup store has, or can get, the encryption
      // key. They can make a perfectly decryptable backup of a Redis of their
      // own — with their own admin account in it. They cannot sign it.
      const forgedStore = path.join(dirs.out, 'forged');
      fs.mkdirSync(forgedStore);
      const forged = await backup({
        ...settings, directory: forgedStore, signingKeyFile: keyFile(dirs.otherKeys, 'signing'),
      });
      await decrypt({ file: forged.file, out: path.join(dirs.out, 'forged.rdb'), ...restorer }); // it does decrypt
      await refuses(verify({ file: forged.file, verificationKeyFile: restorer.verificationKeyFile }), /signature does not verify/, 'verifying the forgery');
      await refuses(drill({ file: forged.file, ...restorer }), /signature does not verify/, 'drilling the forgery');
    });

    await test('The drill restores the backup into a fresh Redis and finds the data intact', async () => {
      const result = await drill({ file: taken.file, ...restorer });
      const failed = result.checks.filter((c) => !c.ok).map((c) => `${c.name} (${c.detail})`);
      assert(result.ok, `checks failed: ${failed.join('; ')}`);
      assert(result.facts.accounts === 250, `accounts restored: ${result.facts.accounts}`);
      assert(fs.readdirSync(os.tmpdir()).every((name) => !name.startsWith('iam-restore-drill-')), 'the drill left its decrypted copy behind');
    });

    await test('Keys that expire between the backup and the drill do not fail it', async () => {
      // Most of what Redis holds for the IAM by count is short-lived: rate-limit
      // windows, revoked token ids, sign-in codes. A restore leaves the expired
      // ones behind, and that is not data loss.
      const pipeline = source.redis.pipeline();
      for (let i = 0; i < 400; i++) pipeline.set(`ratelimit:selftest:${i}`, '1', 'PX', 1500);
      await pipeline.exec();
      const busy = await backup(settings);
      await new Promise((resolve) => setTimeout(resolve, 2000));
      const result = await drill({ file: busy.file, ...restorer });
      assert(result.facts.dbsize < busy.manifest.facts.dbsize * 0.95, 'setup: the expiring keys were expected to be gone from the restored copy');
      assert(result.ok, `the drill failed: ${result.checks.filter((c) => !c.ok).map((c) => c.detail).join('; ')}`);
    });

    await test('The drill fails when what comes back is not a usable IAM database', async () => {
      // A genuine, correctly signed backup — of a database in which thirty
      // accounts have lost their records. Decrypting and loading are not the
      // test; the data is.
      for (let i = 0; i < 30; i++) await source.redis.del(`user:selftest_user_${i}`);
      const damaged = await backup(settings);
      const result = await drill({ file: damaged.file, ...restorer });
      assert(!result.ok, 'the drill passed a database with broken accounts');
      assert(result.checks.find((c) => c.name === 'accounts are intact').ok === false, 'the broken accounts were not what failed');
    });

    await test('A full restore reproduces the original exactly, key for key', async () => {
      const restoreDir = path.join(dirs.out, 'restore');
      fs.mkdirSync(restoreDir);
      await decrypt({ file: taken.file, out: path.join(restoreDir, 'dump.rdb'), ...restorer });
      const restored = await startScratchRedis(restoreDir);
      try {
        const after = await contentsOf(restored.redis);
        // The canary is part of the snapshot; the completion marker is written
        // after it, so it is the one key that legitimately differs.
        before.delete(LAST_SUCCESS_KEY);
        after.delete(LAST_SUCCESS_KEY);
        assert(after.size === before.size, `${after.size} keys restored, ${before.size} in the original`);
        const different = [...before.keys()].filter((key) => after.get(key) !== before.get(key));
        assert(different.length === 0, `keys that differ: ${different.slice(0, 5).join(', ')}`);
        assert(await restored.redis.ttl('expiring:value') > 0, 'the expiry was lost');
      } finally {
        await restored.stop();
      }
    });

    await test('Retention keeps the newest backups and their manifests, and nothing else', async () => {
      for (let i = 0; i < 3; i++) await backup(settings);
      const names = fs.readdirSync(dirs.store);
      const files = names.filter((name) => name.endsWith(FILE_SUFFIX));
      const manifests = names.filter((name) => name.endsWith(MANIFEST_SUFFIX));
      assert(files.length === 3 && manifests.length === 3, `${files.length} backups and ${manifests.length} manifests kept (expected 3 and 3)`);
      assert(!fs.existsSync(taken.file), 'the oldest backup was kept');
    });

    await test('The upload command ships both files and leaves nothing staged on the host', async () => {
      const remote = path.join(dirs.out, 'remote');
      const staging = path.join(dirs.out, 'staging');
      fs.mkdirSync(remote);
      fs.mkdirSync(staging);
      const shipped = await backup({
        ...settings, directory: undefined, stagingDir: staging,
        uploadCommand: `cp "$BACKUP_FILE" "$BACKUP_MANIFEST" "${remote}/"`,
      });
      assert(fs.readdirSync(staging).length === 0, 'the staged copy was left on the host');
      await verify({ file: path.join(remote, shipped.file), verificationKeyFile: restorer.verificationKeyFile });

      const lastSuccess = await source.redis.get(LAST_SUCCESS_KEY);
      await source.redis.del(LAST_SUCCESS_KEY);
      await refuses(backup({ ...settings, directory: undefined, stagingDir: staging, uploadCommand: 'exit 3' }), /exited with 3/, 'a failed upload');
      assert(await source.redis.get(LAST_SUCCESS_KEY) === null, 'a backup that never left the host was recorded as a success');
      assert(fs.readdirSync(staging).length === 0, 'a failed upload left the staged copy behind');
      await source.redis.set(LAST_SUCCESS_KEY, lastSuccess);
    });

    await test('Keys are never overwritten', async () => {
      let message = '';
      try { generateKeys(dirs.keys); } catch (err) { message = err.message; }
      assert(/already exists/.test(message), 'keygen replaced existing keys');
    });
  } finally {
    if (source) await source.stop();
    fs.rmSync(work, { recursive: true, force: true });
  }

  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n  ${results.length - failed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
