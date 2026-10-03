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
 * and mirrored to the console for local dev visibility. Security-relevant
 * entries are also shipped off the host as they happen, if a collector is
 * configured (log-forwarder.js).
 *
 * Every entry written while a request is being handled carries that
 * request's id, the address it came from and — once it has authenticated —
 * the account making it, without each call site having to pass them along.
 * That is what turns "a role was revoked" into a record of who revoked it,
 * from where, as part of which request.
 *
 * No log4j/winston/pino dependency: at this scale (a handful of
 * processes, JSON lines, daily files) an external logging library
 * buys nothing that a 60-line module doesn't already provide, and it
 * keeps the dependency surface (and its own CVE exposure) smaller.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');
const { createLogForwarderFromEnv } = require('./log-forwarder');

// One per process, shared by every logger in it.
const forwarder = createLogForwarderFromEnv();

// What is known about the request currently being handled. Entered by
// requestLogger(), so it covers everything that runs downstream of it.
const requestContext = new AsyncLocalStorage();

// A caller may supply a request id so one operation can be followed across
// systems — but only something that is plainly an id, never free text that
// would end up in every log line.
const REQUEST_ID = /^[A-Za-z0-9._-]{8,64}$/;

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
    const request = requestContext.getStore();
    const entry = {
      ts: new Date().toISOString(),
      level,
      service: serviceName,
      category,
      message,
      ...(request ? {
        requestId: request.requestId,
        ip: request.ip,
        ...(request.actor ? { actorId: request.actor.id, actor: request.actor.username } : {}),
      } : {}),
      ...meta,
    };

    consoleMirror(entry);
    const line = JSON.stringify(entry);
    appendLine(`${serviceName}-${dateStamp()}.log`, line);
    appendLine(`combined-${dateStamp()}.log`, line);
    if (forwarder) forwarder.push(entry);

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

    /**
     * Records which account the current request has authenticated as, so the
     * entries that follow say who did the thing they describe.
     */
    setActor(actor) {
      const request = requestContext.getStore();
      if (request) request.actor = { id: actor.id, username: actor.username };
    },

    /** Counters for the log forwarder, or null if nothing is being forwarded. */
    forwarderStats: () => (forwarder ? forwarder.stats() : null),

    /**
     * Express middleware: logs every request/response with timing, and opens
     * the request's logging context. Mount it after the body parser — a
     * context entered before the body has been read is lost when the stream's
     * events fire.
     */
    requestLogger() {
      return (req, res, next) => {
        const supplied = req.get('X-Request-Id');
        const requestId = supplied && REQUEST_ID.test(supplied) ? supplied : crypto.randomUUID();
        res.setHeader('X-Request-Id', requestId);

        const context = { requestId, ip: req.ip };
        const startedAt = process.hrtime.bigint();
        res.on('finish', () => {
          const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
          const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
          // 'finish' fires outside the request's async context; re-enter it so
          // this line carries the same id and actor as the rest.
          requestContext.run(context, () => log(level, 'http', `${req.method} ${req.originalUrl} -> ${res.statusCode}`, {
            method: req.method,
            path: req.originalUrl,
            status: res.statusCode,
            durationMs: Math.round(durationMs * 100) / 100,
            user: req.user?.username,
          }));
        });
        requestContext.run(context, next);
      };
    },
  };
}

module.exports = { createLogger };
