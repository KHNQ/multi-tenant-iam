const fs = require('fs');
const os = require('os');
const path = require('path');
const { writePrivateFile, PrivateFileError } = require('../../src/private-file');

let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-private-file-')); });
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }); });

const modeOf = (file) => fs.statSync(file).mode & 0o777;

describe('writePrivateFile — the bootstrap password file', () => {
  test('creates the file with mode 0600, and its directory with 0700', () => {
    const file = path.join(dir, 'nested', 'admin-password');
    writePrivateFile(file, 'secret\n');
    expect(fs.readFileSync(file, 'utf8')).toBe('secret\n');
    expect(modeOf(file)).toBe(0o600);
    expect(modeOf(path.dirname(file))).toBe(0o700);
  });

  test('replaces a leftover regular file, and tightens its permissions', () => {
    const file = path.join(dir, 'admin-password');
    fs.writeFileSync(file, 'old', { mode: 0o644 });
    writePrivateFile(file, 'new');
    expect(fs.readFileSync(file, 'utf8')).toBe('new');
    expect(modeOf(file)).toBe(0o600);
  });

  test('refuses a dangling symlink with a clear error (it used to fail with EEXIST)', () => {
    const file = path.join(dir, 'admin-password');
    const target = path.join(dir, 'nowhere');
    fs.symlinkSync(target, file);

    expect(() => writePrivateFile(file, 'secret')).toThrow(PrivateFileError);
    expect(() => writePrivateFile(file, 'secret')).toThrow(/symbolic link/);
    // Nothing was written, and the link was left for the operator to see.
    expect(fs.existsSync(target)).toBe(false);
    expect(fs.lstatSync(file).isSymbolicLink()).toBe(true);
  });

  test('refuses a symlink to an existing file, leaving that file untouched', () => {
    const file = path.join(dir, 'admin-password');
    const target = path.join(dir, 'precious');
    fs.writeFileSync(target, 'do not overwrite');
    fs.symlinkSync(target, file);

    let error;
    try { writePrivateFile(file, 'secret'); } catch (err) { error = err; }
    expect(error).toBeInstanceOf(PrivateFileError);
    expect(error.code).toBe('ESYMLINK');
    expect(fs.readFileSync(target, 'utf8')).toBe('do not overwrite');
  });

  test('refuses a path that is a directory', () => {
    const file = path.join(dir, 'admin-password');
    fs.mkdirSync(file);
    expect(() => writePrivateFile(file, 'secret')).toThrow(/not a regular file/);
  });

  test('fails, without falling back to anything, when the directory cannot be created', () => {
    expect(() => writePrivateFile('/dev/null/iam/admin-password', 'secret')).toThrow(PrivateFileError);
  });
});
