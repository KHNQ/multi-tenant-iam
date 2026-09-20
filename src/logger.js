/**
 * Shared structured logger, used by every process in this system
 * (main.reg.js, registery.js, llm.reg.js, vision.reg.js).
 *
 * Every event is written as one JSON line to:
 *   - logs/{service}-{YYYY-MM-DD}.log   (per-service history)
 *   - logs/combined-{YYYY-MM-DD}.log    (whole-system timeline, for
 *                                         correlating a request across
 *                                         the gateway + registry + a
 *                                         downstream service)
 * and mirrored to the console for local dev visibility.
 *
 * No log4j/winston/pino dependency: at this scale (a handful of
 * processes, JSON lines, daily files) an external logging library
 * buys nothing that a 60-line module doesn't already provide, and it
 * keeps the dependency surface (and its own CVE exposure) smaller.
 */

const fs = require('fs');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '..', 'logs');
fs.mkdirSync(LOG_DIR, { recursive: true });

function dateStamp() {
  return new Date().toISOString().slice(0, 10);
}

function appendLine(fileName, line) {
  fs.appendFile(path.join(LOG_DIR, fileName), line + '\n', (err) => {
    if (err) {
      // Logging must never crash the app it's instrumenting.
      console.error('[Logger] Failed to write log file:', err.message);
    }
  });
}

function consoleMirror(entry) {
  const consoleFn = entry.level === 'error' ? console.error
    : entry.level === 'warn' ? console.warn
      : console.log;
  const metaKeys = Object.keys(entry).filter(
    (k) => !['ts', 'level', 'service', 'category', 'message'].includes(k),
  );
  const metaStr = metaKeys.length
    ? ' ' + JSON.stringify(Object.fromEntries(metaKeys.map((k) => [k, entry[k]])))
    : '';
  consoleFn(`[${entry.service}] ${entry.level.toUpperCase()} ${entry.category}: ${entry.message}${metaStr}`);
}

/**
 * @param {string} serviceName - short tag, e.g. "gateway", "registry", "llm", "vision"
 */
function createLogger(serviceName) {
  function log(level, category, message, meta = {}) {
    const entry = {
      ts: new Date().toISOString(),
      level,
      service: serviceName,
      category,
      message,
      ...meta,
    };

    consoleMirror(entry);
    const line = JSON.stringify(entry);
    appendLine(`${serviceName}-${dateStamp()}.log`, line);
    appendLine(`combined-${dateStamp()}.log`, line);

    return entry;
  }

  return {
    info: (category, message, meta) => log('info', category, message, meta),
    warn: (category, message, meta) => log('warn', category, message, meta),
    error: (category, message, meta) => log('error', category, message, meta),
    // 'audit' = a deliberate security/administrative action (login,
    // role change, policy change, user deletion, ...) as opposed to
    // routine operational info. Same sink, distinct level so log
    // consumers can filter for "what did someone do" vs "what happened".
    audit: (category, message, meta) => log('audit', category, message, meta),

    /** Express middleware: logs every request/response with timing. */
    requestLogger() {
      return (req, res, next) => {
        const startedAt = process.hrtime.bigint();
        res.on('finish', () => {
          const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
          const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
          log(level, 'http', `${req.method} ${req.originalUrl} -> ${res.statusCode}`, {
            method: req.method,
            path: req.originalUrl,
            status: res.statusCode,
            durationMs: Math.round(durationMs * 100) / 100,
            ip: req.ip,
            user: req.user?.username,
          });
        });
        next();
      };
    },
  };
}

module.exports = { createLogger };
