#!/usr/bin/env node
/**
 * Encrypted, off-host backups of the IAM's Redis — and the way back.
 * ─────────────────────────────────────────────────────────────────────────────
 * Everything the IAM knows is in Redis: accounts, password hashes, roles,
 * policies, tenants, the registry. Redis's own dump.rdb sits on the same disk
 * as Redis, in the clear, which protects against a restart and nothing else.
 * This tool makes the copy that survives losing the host:
 *
 *   backup    stream a point-in-time snapshot out of the running Redis
 *             (redis-cli --rdb, the replication protocol — Redis is not
 *             paused and its own dump file is not touched), encrypt it as it
 *             arrives, and put it somewhere that is not this host.
 *   verify    check a backup is the file that was written, by the host that
 *             was supposed to write it. Needs no secret.
 *   decrypt   turn a backup back into an RDB file.
 *   drill     prove a backup restores: decrypt it, load it into a throwaway
 *             Redis, and check the data that came back.
 *   keygen    make the keys.
 *
 * WHO HOLDS WHICH KEY is the point of the design:
 *
 *   The IAM host holds the ENCRYPTION key, which is public, and a SIGNING key.
 *   It can write backups. It cannot read one — not even yesterday's — so
 *   someone who takes the host, or the backup store, gets no history.
 *
 *   The DECRYPTION key lives off the host, with whoever performs restores.
 *   With it goes the VERIFICATION key, which is how a restore knows the file
 *   came from the IAM host: the encryption key being public, anyone who has it
 *   can produce a file that decrypts perfectly well. Restoring one of those
 *   would hand its author every account in the system.
 *
 * FILE FORMAT (.rdb.enc)
 *   8 bytes   magic "IAMRDB1\n"
 *   4 bytes   header length, big endian
 *   header    JSON: id, time, IV, the data key wrapped with RSA-OAEP-SHA256
 *   body      the RDB stream under AES-256-GCM, the header as associated data
 *   16 bytes  GCM tag
 * Beside it, <name>.manifest.json: size and SHA-256 of that file, what Redis
 * held when it was taken, and an Ed25519 signature over all of it.
 *
 * Configuration is read from the environment (and .env): see `usage` below.
 */

require('../local-env');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const Redis = require('ioredis');

const MAGIC = Buffer.from('IAMRDB1\n');
const TAG_BYTES = 16;
const FILE_SUFFIX = '.rdb.enc';
const MANIFEST_SUFFIX = '.manifest.json';

// Written into Redis just before the snapshot, so it is in the snapshot: a
// restored copy that carries this backup's id is this backup, and not an
// empty database or some other day's file under the right name.
const CANARY_KEY = 'iam:backup:canary';
// Written after the backup is safely off the host. The gateway reports it as
// iam_backup_last_success_timestamp_seconds, so backups that stop are noticed.
const LAST_SUCCESS_KEY = 'iam:backup:last-success';

const KEY_FILES = {
  encryption: 'backup-encryption-public.pem',
  decryption: 'backup-decryption-private.pem',
  signing: 'backup-signing-private.pem',
  verification: 'backup-verification-public.pem',
};

class BackupError extends Error {}

// ─── KEYS ────────────────────────────────────────────────────────────────────

const fingerprint = (publicKey) => crypto.createHash('sha256')
  .update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url');

function readKey(file, kind, what, passphrase) {
  if (!file) throw new BackupError(`${what} is not set`);
  let pem;
  try {
    pem = fs.readFileSync(file);
  } catch (err) {
    throw new BackupError(`Cannot read ${what} (${file}): ${err.code || err.message}`);
  }
  try {
    return kind === 'public' ? crypto.createPublicKey(pem) : crypto.createPrivateKey({ key: pem, passphrase });
  } catch (err) {
    throw new BackupError(`${file} is not a usable ${kind} key${kind === 'private' ? ' (wrong passphrase?)' : ''}: ${err.message}`);
  }
}

/**
 * Makes both key pairs. The two files that belong off the host are named so
 * that nobody has to remember which those are.
 */
function generateKeys(outDir, { passphrase } = {}) {
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  for (const name of Object.values(KEY_FILES)) {
    if (fs.existsSync(path.join(outDir, name))) {
      throw new BackupError(`${path.join(outDir, name)} already exists. Keys are never overwritten: a backup made for a key that is gone cannot be read.`);
    }
  }
  const sealed = passphrase ? { cipher: 'aes-256-cbc', passphrase } : {};
  const wrap = crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });
  const sign = crypto.generateKeyPairSync('ed25519');

  const write = (name, pem, mode) => fs.writeFileSync(path.join(outDir, name), pem, { mode, flag: 'wx' });
  write(KEY_FILES.encryption, wrap.publicKey.export({ type: 'spki', format: 'pem' }), 0o644);
  write(KEY_FILES.decryption, wrap.privateKey.export({ type: 'pkcs8', format: 'pem', ...sealed }), 0o600);
  write(KEY_FILES.signing, sign.privateKey.export({ type: 'pkcs8', format: 'pem' }), 0o600);
  write(KEY_FILES.verification, sign.publicKey.export({ type: 'spki', format: 'pem' }), 0o644);

  return {
    outDir,
    passphraseProtected: Boolean(passphrase),
    encryptionKeyFingerprint: fingerprint(wrap.publicKey),
    verificationKeyFingerprint: fingerprint(sign.publicKey),
  };
}

// ─── REDIS ───────────────────────────────────────────────────────────────────

function connect(redisUrl) {
  const redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1, retryStrategy: () => null });
  redis.on('error', () => {}); // failures surface from the command that hit them
  return redis;
}

/** redis-cli arguments for a redis:// URL. The password travels in the environment, not in `ps`. */
function cliConnection(redisUrl) {
  const url = new URL(redisUrl);
  const args = ['-h', url.hostname || '127.0.0.1', '-p', url.port || '6379'];
  if (url.protocol === 'rediss:') args.push('--tls');
  if (url.username) args.push('--user', decodeURIComponent(url.username));
  const env = { ...process.env };
  if (url.password) env.REDISCLI_AUTH = decodeURIComponent(url.password);
  return { args, env };
}

/** What Redis holds, in the terms the IAM cares about. Compared after a restore. */
async function readFacts(redis) {
  const [dbsize, accounts, policyRows, policyVersion] = await Promise.all([
    redis.dbsize(),
    redis.hlen('users:ids'),
    redis.llen('casbin:policies'),
    redis.get('casbin:policies:version'),
  ]);
  return { dbsize, accounts, policyRows, policyVersion: Number(policyVersion || 0) };
}

// ─── WRITING A BACKUP ────────────────────────────────────────────────────────

// What is signed: the manifest without its signature, keys in a fixed order at
// every depth, so that it reads the same after a trip through JSON.
const stable = (value) => {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort()
      .map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};
const canonical = ({ signature, ...signed }) => Buffer.from(stable(signed));

/**
 * Streams a snapshot out of Redis and writes it encrypted to `file`. The
 * snapshot is never on this host's disk in the clear: it goes from the socket
 * through the cipher to the file.
 */
async function writeEncryptedSnapshot({ redisUrl, file, header, dataKey, iv }) {
  const headerBytes = Buffer.from(JSON.stringify(header));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(headerBytes.length);

  const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
  cipher.setAAD(headerBytes);
  const sha256 = crypto.createHash('sha256');
  let plaintextBytes = 0;
  let firstBytes = Buffer.alloc(0);

  const { args, env } = cliConnection(redisUrl);
  const cli = spawn('redis-cli', [...args, '--rdb', '-'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let complaint = '';
  cli.stderr.on('data', (chunk) => { complaint = (complaint + chunk).slice(-2000); });
  const exited = new Promise((resolve, reject) => {
    cli.on('error', (err) => reject(new BackupError(err.code === 'ENOENT'
      ? 'redis-cli was not found on PATH — it is what takes the snapshot'
      : `redis-cli could not be started: ${err.message}`)));
    cli.on('close', resolve);
  });
  exited.catch(() => {}); // reported below; this only stops it being "unhandled" if the pipe fails first

  const out = fs.createWriteStream(file, { mode: 0o600, flags: 'wx' });
  const emit = (chunk) => { sha256.update(chunk); return chunk; };
  out.write(emit(Buffer.concat([MAGIC, length, headerBytes])));

  await pipeline(
    cli.stdout,
    async function* encrypt(source) {
      for await (const chunk of source) {
        plaintextBytes += chunk.length;
        if (firstBytes.length < 5) firstBytes = Buffer.concat([firstBytes, chunk]).subarray(0, 5);
        const sealed = cipher.update(chunk);
        if (sealed.length) yield emit(sealed);
      }
      const last = cipher.final();
      yield emit(Buffer.concat([last, cipher.getAuthTag()]));
    },
    out,
  );

  const code = await exited;
  // redis-cli can exit 0 having written an error to stdout; an RDB always
  // starts with the five bytes "REDIS".
  if (code !== 0 || firstBytes.toString('latin1') !== 'REDIS') {
    throw new BackupError(`Redis did not hand over a snapshot (redis-cli exit ${code}): ${complaint.trim().split('\n').pop() || 'no output'}`);
  }

  const handle = fs.openSync(file, 'r');
  try { fs.fsyncSync(handle); } finally { fs.closeSync(handle); }
  return { sha256: sha256.digest('hex'), sizeBytes: fs.statSync(file).size, plaintextBytes };
}

/**
 * Refuses a destination that is the disk Redis itself is on. It cannot prove
 * a directory is on another machine — a mount point is the operator's promise
 * — but it can catch the mistake that makes a backup worthless.
 */
async function assertOffHost(redis, redisUrl, directory, allowSameDevice) {
  const { hostname } = new URL(redisUrl);
  if (!['localhost', '127.0.0.1', '::1', '[::1]', os.hostname()].includes(hostname)) return;
  let redisDir;
  try { [, redisDir] = await redis.config('GET', 'dir'); } catch { return; } // CONFIG may be denied to this user
  let same = false;
  try { same = fs.statSync(redisDir).dev === fs.statSync(directory).dev; } catch { return; }
  if (!same) return;
  if (allowSameDevice) return 'the destination is on the same disk as Redis (allowed by BACKUP_ALLOW_SAME_DEVICE)';
  throw new BackupError(
    `${directory} is on the same disk as Redis's own data (${redisDir}). A backup there is lost with the host. `
    + 'Point BACKUP_DIR at a mounted remote volume, or use BACKUP_UPLOAD_COMMAND. (BACKUP_ALLOW_SAME_DEVICE=1 overrides this, for tests.)',
  );
}

function runShell(command, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, { shell: true, env, stdio: ['ignore', 'inherit', 'inherit'] });
    child.on('error', reject);
    child.on('close', (code) => (code === 0 ? resolve() : reject(new BackupError(`The upload command exited with ${code}`))));
  });
}

/** Keeps the newest `keep` backups in a directory; never one without its manifest's pair. */
function applyRetention(directory, keep) {
  const backups = fs.readdirSync(directory).filter((name) => name.endsWith(FILE_SUFFIX)).sort();
  const removed = [];
  for (const name of backups.slice(0, Math.max(0, backups.length - keep))) {
    fs.rmSync(path.join(directory, name), { force: true });
    fs.rmSync(path.join(directory, name.slice(0, -FILE_SUFFIX.length) + MANIFEST_SUFFIX), { force: true });
    removed.push(name);
  }
  return removed;
}

/**
 * @param {object} opts
 * @param {string} opts.redisUrl
 * @param {string} opts.encryptionKeyFile public key the snapshot is encrypted to
 * @param {string} opts.signingKeyFile    private key the manifest is signed with
 * @param {string} [opts.directory]       destination directory (an off-host mount)
 * @param {string} [opts.uploadCommand]   or: a shell command that ships $BACKUP_FILE and $BACKUP_MANIFEST
 * @param {string} [opts.stagingDir]      where the encrypted file waits for the upload command
 * @param {number} [opts.retentionCount]  backups to keep in `directory`
 * @param {boolean} [opts.allowSameDevice]
 */
async function backup(opts) {
  const { redisUrl, directory, uploadCommand } = opts;
  if (Boolean(directory) === Boolean(uploadCommand)) {
    throw new BackupError('Set exactly one of BACKUP_DIR (a mounted off-host volume) or BACKUP_UPLOAD_COMMAND');
  }
  const encryptionKey = readKey(opts.encryptionKeyFile, 'public', 'BACKUP_ENCRYPTION_KEY_FILE');
  const signingKey = readKey(opts.signingKeyFile, 'private', 'BACKUP_SIGNING_KEY_FILE');
  if (encryptionKey.asymmetricKeyType !== 'rsa') throw new BackupError('BACKUP_ENCRYPTION_KEY_FILE must be an RSA public key (see `keygen`)');
  if (signingKey.asymmetricKeyType !== 'ed25519') throw new BackupError('BACKUP_SIGNING_KEY_FILE must be an Ed25519 private key (see `keygen`)');

  const redis = connect(redisUrl);
  const warnings = [];
  let staged;
  try {
    await redis.connect().catch((err) => { throw new BackupError(`Cannot reach Redis at ${new URL(redisUrl).host}: ${err.message}`); });

    const target = directory || fs.mkdtempSync(path.join(opts.stagingDir || os.tmpdir(), 'iam-backup-'));
    if (directory) {
      if (!fs.existsSync(directory)) throw new BackupError(`BACKUP_DIR ${directory} does not exist (is the volume mounted?)`);
      const note = await assertOffHost(redis, redisUrl, directory, opts.allowSameDevice);
      if (note) warnings.push(note);
    } else {
      staged = target;
    }

    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();
    // Sorts by time, to the millisecond: retention and --latest go by name.
    const name = `iam-redis-${createdAt.replace(/[-:.]/g, '')}-${id.slice(0, 8)}`;
    const file = path.join(target, name + FILE_SUFFIX);
    const manifestFile = path.join(target, name + MANIFEST_SUFFIX);

    // The canary first, so it is inside the snapshot; the facts as close to it as possible.
    await redis.set(CANARY_KEY, id);
    const info = await redis.info('server');
    const serverField = (field) => (info.match(new RegExp(`^${field}:(.*)$`, 'm')) || [])[1]?.trim();
    const facts = await readFacts(redis);

    const dataKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const header = {
      format: 'iam-redis-backup', version: 1, id, createdAt,
      cipher: 'aes-256-gcm', iv: iv.toString('base64'),
      keyWrap: 'rsa-oaep-sha256', keyFingerprint: fingerprint(encryptionKey),
      wrappedKey: crypto.publicEncrypt(
        { key: encryptionKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, dataKey,
      ).toString('base64'),
    };

    const partial = `${file}.partial`;
    let written;
    try {
      written = await writeEncryptedSnapshot({ redisUrl, file: partial, header, dataKey, iv });
    } catch (err) {
      fs.rmSync(partial, { force: true });
      throw err;
    } finally {
      dataKey.fill(0);
    }
    fs.renameSync(partial, file);

    const manifest = {
      format: 'iam-redis-backup-manifest', version: 1,
      id, file: path.basename(file), createdAt, completedAt: new Date().toISOString(),
      sizeBytes: written.sizeBytes, sha256: written.sha256, plaintextBytes: written.plaintextBytes,
      keyFingerprint: header.keyFingerprint,
      signedBy: fingerprint(crypto.createPublicKey(signingKey)),
      redis: { version: serverField('redis_version'), runId: serverField('run_id') },
      facts,
      canary: { key: CANARY_KEY, value: id },
    };
    manifest.signature = crypto.sign(null, canonical(manifest), signingKey).toString('base64');
    fs.writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });

    let removed = [];
    if (uploadCommand) {
      await runShell(uploadCommand, { ...process.env, BACKUP_FILE: file, BACKUP_MANIFEST: manifestFile, BACKUP_ID: id });
    } else {
      removed = applyRetention(directory, opts.retentionCount || 30);
    }

    // Only now is it a backup: encrypted, signed, and somewhere else.
    await redis.set(LAST_SUCCESS_KEY, Math.floor(Date.now() / 1000));
    return { id, file: uploadCommand ? path.basename(file) : file, manifest, removed, warnings, shippedBy: uploadCommand ? 'upload command' : 'directory' };
  } finally {
    if (staged) fs.rmSync(staged, { recursive: true, force: true });
    redis.disconnect();
  }
}

// ─── READING ONE BACK ────────────────────────────────────────────────────────

const manifestPathFor = (file) => (file.endsWith(FILE_SUFFIX) ? file.slice(0, -FILE_SUFFIX.length) : file) + MANIFEST_SUFFIX;

function sha256OfFile(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (chunk) => hash.update(chunk)).on('error', reject)
      .on('end', () => resolve(hash.digest('hex')));
  });
}

function readHeader(file) {
  const handle = fs.openSync(file, 'r');
  try {
    const fixed = Buffer.alloc(MAGIC.length + 4);
    fs.readSync(handle, fixed, 0, fixed.length, 0);
    if (!fixed.subarray(0, MAGIC.length).equals(MAGIC)) throw new BackupError(`${file} is not an IAM Redis backup`);
    const headerLength = fixed.readUInt32BE(MAGIC.length);
    if (headerLength > 16384) throw new BackupError(`${file} has an implausible header`);
    const headerBytes = Buffer.alloc(headerLength);
    fs.readSync(handle, headerBytes, 0, headerLength, fixed.length);
    let header;
    try { header = JSON.parse(headerBytes.toString('utf8')); } catch { throw new BackupError(`${file} has an unreadable header`); }
    if (header.format !== 'iam-redis-backup' || header.version !== 1) throw new BackupError(`${file}: unsupported backup format`);
    return { header, headerBytes, bodyStart: fixed.length + headerLength };
  } finally {
    fs.closeSync(handle);
  }
}

/**
 * Is this the file the IAM host wrote? Checks the manifest's signature, then
 * that the file is the one the manifest describes. Needs only the public
 * verification key.
 */
async function verify({ file, verificationKeyFile }) {
  const verificationKey = readKey(verificationKeyFile, 'public', 'BACKUP_VERIFICATION_KEY_FILE');
  const manifestFile = manifestPathFor(file);
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  } catch (err) {
    throw new BackupError(`Cannot read the manifest ${manifestFile}: ${err.code || err.message}`);
  }
  if (manifest.format !== 'iam-redis-backup-manifest' || typeof manifest.signature !== 'string') {
    throw new BackupError(`${manifestFile} is not a backup manifest`);
  }
  if (!crypto.verify(null, canonical(manifest), verificationKey, Buffer.from(manifest.signature, 'base64'))) {
    throw new BackupError('The manifest signature does not verify: it was not written by the holder of the signing key, or it has been altered');
  }

  const { header } = readHeader(file);
  const { size } = fs.statSync(file);
  if (size !== manifest.sizeBytes) throw new BackupError(`The file is ${size} bytes; the manifest says ${manifest.sizeBytes}`);
  if ((await sha256OfFile(file)) !== manifest.sha256) throw new BackupError('The file does not match the SHA-256 in its manifest: it is damaged or has been replaced');
  if (header.id !== manifest.id) throw new BackupError('The file and the manifest describe different backups');
  return manifest;
}

/**
 * Decrypts a backup to `out`. Nothing appears at `out` unless the whole file
 * authenticated: GCM only vouches for the data at the very end, so the output
 * is written under another name until then.
 */
async function decrypt({ file, out, decryptionKeyFile, passphrase, force = false }) {
  const decryptionKey = readKey(decryptionKeyFile, 'private', 'BACKUP_DECRYPTION_KEY_FILE', passphrase);
  const { header, headerBytes, bodyStart } = readHeader(file);

  if (fingerprint(crypto.createPublicKey(decryptionKey)) !== header.keyFingerprint) {
    throw new BackupError(`This backup was encrypted for key ${header.keyFingerprint}, which is not the key in ${decryptionKeyFile}`);
  }
  if (fs.existsSync(out) && !force) throw new BackupError(`${out} already exists (pass --force to replace it)`);

  const { size } = fs.statSync(file);
  if (size < bodyStart + TAG_BYTES) throw new BackupError(`${file} is truncated`);
  const tag = Buffer.alloc(TAG_BYTES);
  const handle = fs.openSync(file, 'r');
  try { fs.readSync(handle, tag, 0, TAG_BYTES, size - TAG_BYTES); } finally { fs.closeSync(handle); }

  let dataKey;
  try {
    dataKey = crypto.privateDecrypt(
      { key: decryptionKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      Buffer.from(header.wrappedKey, 'base64'),
    );
  } catch {
    throw new BackupError('The data key could not be unwrapped with this decryption key');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, Buffer.from(header.iv, 'base64'));
  decipher.setAAD(headerBytes);
  decipher.setAuthTag(tag);

  const partial = `${out}.partial`;
  try {
    await pipeline(
      // `end` is inclusive; an empty body (start past end) reads nothing.
      size - TAG_BYTES > bodyStart ? fs.createReadStream(file, { start: bodyStart, end: size - TAG_BYTES - 1 }) : (async function* nothing() {})(),
      decipher,
      fs.createWriteStream(partial, { mode: 0o600 }),
    );
  } catch (err) {
    fs.rmSync(partial, { force: true });
    throw new BackupError(/authenticate/i.test(err.message)
      ? 'The backup failed authentication — it is damaged or has been altered'
      : `The backup could not be decrypted to ${out}: ${err.message}`);
  } finally {
    dataKey.fill(0);
  }
  fs.renameSync(partial, out);
  return { header, out, bytes: fs.statSync(out).size };
}

// ─── THE DRILL ───────────────────────────────────────────────────────────────

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => { const { port } = probe.address(); probe.close(() => resolve(port)); });
  });
}

/**
 * Starts a throwaway redis-server over the RDB in `dir`: loopback only, on a
 * free port, writing nothing back. Resolves once the data is loaded.
 */
async function startScratchRedis(dir) {
  const port = await freePort();
  const child = spawn('redis-server', [
    '--port', String(port), '--bind', '127.0.0.1', '--dir', dir, '--dbfilename', 'dump.rdb',
    '--save', '', '--appendonly', 'no', '--daemonize', 'no',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk) => { output = (output + chunk).slice(-4000); });
  child.stderr.on('data', (chunk) => { output = (output + chunk).slice(-4000); });
  let exitCode = null;
  let spawnError = null;
  child.on('error', (err) => { spawnError = err; });
  child.on('close', (code) => { exitCode = code ?? 1; });

  const redis = connect(`redis://127.0.0.1:${port}`);
  const stop = async () => {
    redis.disconnect();
    if (exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => { child.on('close', resolve); setTimeout(resolve, 5000).unref(); });
    }
  };

  const deadline = Date.now() + 120000;
  for (;;) {
    if (spawnError) {
      throw new BackupError(spawnError.code === 'ENOENT'
        ? 'redis-server was not found on PATH — the drill loads the backup into a throwaway one'
        : `redis-server could not be started: ${spawnError.message}`);
    }
    if (exitCode !== null) {
      throw new BackupError(`Redis refused to load the restored file (exit ${exitCode}):\n${output.trim().split('\n').slice(-4).join('\n')}`);
    }
    try {
      if (redis.status === 'wait' || redis.status === 'end') await redis.connect();
      if (/loading:0/.test(await redis.info('persistence'))) return { redis, port, stop };
    } catch { /* not up yet, or still loading */ }
    if (Date.now() > deadline) { await stop(); throw new BackupError('The throwaway Redis did not finish loading within two minutes'); }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
}

/** Looks at restored data the way the gateway would. */
async function inspectRestored(redis, manifest) {
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok: Boolean(ok), detail });

  const canary = await redis.get(CANARY_KEY);
  check('the restored data is this backup (canary)', canary === manifest.canary.value,
    canary === manifest.canary.value ? manifest.id : `found ${canary || 'nothing'}, expected ${manifest.canary.value}`);

  // Taken a moment before the snapshot, on a live system: allow that moment.
  // The total key count is reported but decides nothing: much of what Redis
  // holds here is meant to expire (rate-limit windows, revoked token ids,
  // sign-in codes), DBSIZE counts keys that have expired and not yet been
  // swept, and a restore rightly leaves those behind.
  const facts = await readFacts(redis);
  const near = (restored, recorded) => (recorded === 0 ? true : restored > 0 && restored >= Math.floor(recorded * 0.95));
  for (const [field, label] of [['accounts', 'accounts'], ['policyRows', 'policy rows']]) {
    check(`${label} came back`, near(facts[field], manifest.facts[field]), `${facts[field]} restored, ${manifest.facts[field]} when the backup was taken`);
  }
  check('the policy version came back', facts.policyVersion >= manifest.facts.policyVersion,
    `${facts.policyVersion} restored, ${manifest.facts.policyVersion} recorded`);

  // Accounts are usable: each id leads to a record that claims that id and has a password hash.
  const ids = await redis.hrandfield('users:ids', 200, 'WITHVALUES');
  let broken = 0;
  for (let i = 0; i < ids.length; i += 2) {
    const [id, password] = await redis.hmget(`user:${ids[i + 1]}`, 'id', 'password');
    if (id !== ids[i] || !/^\$(argon2|2[aby])/.test(password || '')) broken += 1;
  }
  check('accounts are intact', broken === 0, `${ids.length / 2} sampled, ${broken} without a matching record or password hash`);

  // Policies are readable: rows the policy store can parse.
  const rows = await redis.lrange('casbin:policies', 0, 499);
  const unreadable = rows.filter((row) => {
    try { const parsed = JSON.parse(row); return !(typeof parsed.ptype === 'string' && Array.isArray(parsed.rule)); } catch { return true; }
  }).length;
  check('policies are readable', unreadable === 0, `${rows.length} sampled, ${unreadable} unreadable`);

  const notes = [`${facts.dbsize} keys restored; ${manifest.facts.dbsize} were counted when the backup was taken, including ones due to expire`];
  return { checks, facts, notes };
}

/**
 * The recovery procedure, run for real against a throwaway Redis: verify,
 * decrypt, load, inspect. Touches neither the live Redis nor its files.
 */
async function drill({ file, verificationKeyFile, decryptionKeyFile, passphrase }) {
  const started = Date.now();
  const manifest = await verify({ file, verificationKeyFile });
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-restore-drill-'));
  let scratch;
  try {
    await decrypt({ file, out: path.join(work, 'dump.rdb'), decryptionKeyFile, passphrase });
    scratch = await startScratchRedis(work);
    const { checks, facts, notes } = await inspectRestored(scratch.redis, manifest);
    return {
      ok: checks.every((c) => c.ok), id: manifest.id, takenAt: manifest.createdAt,
      checks, facts, notes, seconds: (Date.now() - started) / 1000,
    };
  } finally {
    if (scratch) await scratch.stop();
    // The decrypted copy does not outlive the drill.
    fs.rmSync(work, { recursive: true, force: true });
  }
}

function latestIn(directory) {
  const names = fs.readdirSync(directory).filter((name) => name.endsWith(FILE_SUFFIX)).sort();
  if (!names.length) throw new BackupError(`No backups in ${directory}`);
  return path.join(directory, names[names.length - 1]);
}

// ─── COMMAND LINE ────────────────────────────────────────────────────────────

const usage = `
Usage: node src/backup/redis-backup.js <command>

  keygen [dir]              make the key pairs (default ./backup-keys). Set
                            BACKUP_KEY_PASSPHRASE to protect the decryption key.
  backup                    snapshot, encrypt, sign, ship
  verify  <file>            signature and checksum (no secret needed)
  decrypt <file> --out <f>  recover the RDB file     [--force]
  drill   <file> | --latest restore into a throwaway Redis and check it

Environment (.env is read):
  REDIS_URL                      default redis://localhost:7000
  BACKUP_ENCRYPTION_KEY_FILE     public  — on the IAM host        (backup)
  BACKUP_SIGNING_KEY_FILE        private — on the IAM host        (backup)
  BACKUP_VERIFICATION_KEY_FILE   public  — with the restorer      (verify, decrypt, drill)
  BACKUP_DECRYPTION_KEY_FILE     private — NEVER on the IAM host  (decrypt, drill)
  BACKUP_KEY_PASSPHRASE          passphrase of the decryption key, if it has one
  BACKUP_DIR                     destination: a mounted off-host volume, or
  BACKUP_UPLOAD_COMMAND          destination: a shell command that ships
                                 "$BACKUP_FILE" and "$BACKUP_MANIFEST"
  BACKUP_RETENTION_COUNT         backups kept in BACKUP_DIR (default 30)
`;

async function main(argv) {
  const [command, ...rest] = argv;
  const env = process.env;
  const flag = (name) => rest.includes(name);
  const option = (name) => (rest.includes(name) ? rest[rest.indexOf(name) + 1] : undefined);
  const positional = rest.filter((arg, i) => !arg.startsWith('--') && rest[i - 1] !== '--out')[0];
  const redisUrl = env.REDIS_URL || 'redis://localhost:7000';
  const say = (line) => process.stdout.write(`${line}\n`);

  switch (command) {
    case 'keygen': {
      const made = generateKeys(path.resolve(positional || 'backup-keys'), { passphrase: env.BACKUP_KEY_PASSPHRASE });
      say(`Keys written to ${made.outDir}\n`);
      say(`  Stay on the IAM host:   ${KEY_FILES.encryption}, ${KEY_FILES.signing}`);
      say(`  MOVE OFF this host now: ${KEY_FILES.decryption}, ${KEY_FILES.verification}`);
      say('                          (to whoever performs restores — a vault, an offline medium)\n');
      if (!made.passphraseProtected) say('  The decryption key has no passphrase. Set BACKUP_KEY_PASSPHRASE and run keygen in a new directory to make one that does.\n');
      say('  Lose the decryption key and every backup made for it is unreadable. Keep two copies.');
      return 0;
    }
    case 'backup': {
      const done = await backup({
        redisUrl,
        encryptionKeyFile: env.BACKUP_ENCRYPTION_KEY_FILE,
        signingKeyFile: env.BACKUP_SIGNING_KEY_FILE,
        directory: env.BACKUP_DIR,
        uploadCommand: env.BACKUP_UPLOAD_COMMAND,
        stagingDir: env.BACKUP_STAGING_DIR,
        retentionCount: Number(env.BACKUP_RETENTION_COUNT) || 30,
        allowSameDevice: env.BACKUP_ALLOW_SAME_DEVICE === '1',
      });
      for (const warning of done.warnings) say(`WARNING: ${warning}`);
      say(`Backup ${done.id} written: ${done.file} (${done.manifest.sizeBytes} bytes, ${done.manifest.facts.accounts} accounts, ${done.manifest.facts.policyRows} policy rows, policy version ${done.manifest.facts.policyVersion})`);
      if (done.removed.length) say(`Retention removed ${done.removed.length} older backup(s)`);
      return 0;
    }
    case 'verify': {
      if (!positional) throw new BackupError('verify needs the backup file');
      const manifest = await verify({ file: positional, verificationKeyFile: env.BACKUP_VERIFICATION_KEY_FILE });
      say(`OK: backup ${manifest.id}, taken ${manifest.createdAt}, signed by ${manifest.signedBy}, ${manifest.sizeBytes} bytes`);
      return 0;
    }
    case 'decrypt': {
      const out = option('--out');
      if (!positional || !out) throw new BackupError('decrypt needs the backup file and --out <where to write the RDB>');
      // A file that decrypts is not thereby ours: check where it came from first.
      const manifest = await verify({ file: positional, verificationKeyFile: env.BACKUP_VERIFICATION_KEY_FILE });
      const done = await decrypt({
        file: positional, out, force: flag('--force'),
        decryptionKeyFile: env.BACKUP_DECRYPTION_KEY_FILE, passphrase: env.BACKUP_KEY_PASSPHRASE,
      });
      say(`Backup ${manifest.id} (taken ${manifest.createdAt}) decrypted to ${done.out} (${done.bytes} bytes). It is in the clear: remove it once Redis has loaded it.`);
      return 0;
    }
    case 'drill': {
      const file = flag('--latest') ? latestIn(env.BACKUP_DIR || '.') : positional;
      if (!file) throw new BackupError('drill needs the backup file, or --latest with BACKUP_DIR set');
      const result = await drill({
        file, verificationKeyFile: env.BACKUP_VERIFICATION_KEY_FILE,
        decryptionKeyFile: env.BACKUP_DECRYPTION_KEY_FILE, passphrase: env.BACKUP_KEY_PASSPHRASE,
      });
      say(`Restore drill — backup ${result.id}, taken ${result.takenAt}\n`);
      say('  ✅ signature and checksum verify');
      say('  ✅ decrypts and authenticates');
      say('  ✅ Redis loads the restored file');
      for (const c of result.checks) say(`  ${c.ok ? '✅' : '❌'} ${c.name} — ${c.detail}`);
      for (const note of result.notes) say(`  ·  ${note}`);
      say(`\n${result.ok ? 'PASSED' : 'FAILED'} in ${result.seconds.toFixed(1)}s`);
      return result.ok ? 0 : 1;
    }
    default:
      say(usage);
      return command ? 2 : 0;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => {
    process.stderr.write(err instanceof BackupError ? `${err.message}\n` : `${err.stack}\n`);
    process.exit(1);
  });
}

module.exports = {
  backup, verify, decrypt, drill, generateKeys, startScratchRedis, connect,
  BackupError, KEY_FILES, FILE_SUFFIX, MANIFEST_SUFFIX, CANARY_KEY, LAST_SUCCESS_KEY,
};
