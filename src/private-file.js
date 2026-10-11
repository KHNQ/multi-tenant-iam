/**
 * Writing a secret to a file only its owner can read.
 * ─────────────────────────────────────────────────────────────────────────────
 * Used for the initial administrator's one-time password. The path may sit in
 * a directory other people (or processes) can write to, so what is already at
 * that path is not trusted:
 *
 *   - a symbolic link is REFUSED, with a message saying so. Writing through
 *     it would put the secret wherever it points; replacing it silently would
 *     hide that somebody planted it. (A dangling link is still a link: it is
 *     what made the earlier "remove, then create" approach fail with EEXIST —
 *     rm with `force` treated it as absent and left it in place.)
 *   - anything else that is not a regular file (a directory, a socket) is
 *     refused too;
 *   - a regular file — a leftover from an earlier attempt — is unlinked, and
 *     a file that vanishes between looking and unlinking is fine (ENOENT).
 *
 * The new file is then created with O_CREAT | O_EXCL (and O_NOFOLLOW where
 * the platform has it), so if anything appears at the path in between, the
 * write fails instead of following it. Mode 0600; the directory is created
 * 0700 if it does not exist.
 */

const fs = require('fs');
const path = require('path');

class PrivateFileError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

/**
 * @param {string} file
 * @param {string} content
 * @throws {PrivateFileError}
 */
function writePrivateFile(file, content) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  } catch (err) {
    throw new PrivateFileError(`cannot create the directory for ${file} (${err.code || err.message})`, err.code);
  }

  let existing = null;
  try {
    existing = fs.lstatSync(file);
  } catch (err) {
    if (err.code !== 'ENOENT') throw new PrivateFileError(`cannot inspect ${file} (${err.code || err.message})`, err.code);
  }
  if (existing?.isSymbolicLink()) {
    throw new PrivateFileError(`${file} is a symbolic link; refusing to write a secret through it or over it — remove it and start again`, 'ESYMLINK');
  }
  if (existing && !existing.isFile()) {
    throw new PrivateFileError(`${file} exists and is not a regular file — remove it and start again`, 'ENOTFILE');
  }
  if (existing) {
    try {
      fs.unlinkSync(file);
    } catch (err) {
      if (err.code !== 'ENOENT') throw new PrivateFileError(`cannot replace ${file} (${err.code || err.message})`, err.code);
    }
  }

  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW = 0 } = fs.constants;
  let fd;
  try {
    fd = fs.openSync(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600);
    fs.writeSync(fd, content);
    fs.fsyncSync(fd);
  } catch (err) {
    throw new PrivateFileError(`cannot write ${file} (${err.code || err.message})`, err.code);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

module.exports = { writePrivateFile, PrivateFileError };
