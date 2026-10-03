/**
 * Ships security-relevant log entries to a central collector.
 * ─────────────────────────────────────────────────────────────────────────────
 * The log files under logs/ are on the same machine as the thing they
 * describe. That is the wrong place for the record of who did what: whoever
 * takes the host takes its history with it, and with several gateway
 * instances "which host has the log" becomes a question. Entries are
 * therefore also forwarded, as they happen, to wherever the organisation
 * keeps such things (a SIEM, Loki, an Elastic or Splunk HTTP collector).
 *
 *   LOG_FORWARD_URL      http(s) endpoint. Batches are POSTed as NDJSON — one
 *                        JSON object per line. Unset: forwarding is off.
 *   LOG_FORWARD_TOKEN    sent as `Authorization: Bearer …`, if set.
 *   LOG_FORWARD_LEVELS   which levels go (default: audit,warn,error — every
 *                        deliberate security action, every refusal, every
 *                        failure; not the per-request info lines).
 *
 * It is built so that the collector being slow, down or wrong can never slow
 * or stop the service that is logging:
 *   - entries go into a bounded in-memory queue and are sent in the
 *     background, in batches;
 *   - a failed batch stays at the head of the queue and is retried with
 *     backoff, so a collector outage delays entries rather than losing them;
 *   - if the queue fills, the OLDEST entries are dropped and counted — the
 *     local files still have them, and the count is exported as a metric.
 */

const http = require('http');
const https = require('https');
const os = require('os');

const MAX_QUEUE = 10000;
const MAX_BATCH = 200;
const FLUSH_INTERVAL_MS = 1000;
const REQUEST_TIMEOUT_MS = 5000;
const MAX_BACKOFF_MS = 60000;

/**
 * @param {object} config
 * @param {string} config.url
 * @param {string} [config.token]
 * @param {string[]} [config.levels]
 */
function createLogForwarder({ url, token, levels = ['audit', 'warn', 'error'] }) {
  const target = new URL(url);
  const transport = target.protocol === 'https:' ? https : http;
  const host = os.hostname();

  const queue = [];
  const stats = { sent: 0, failed: 0, dropped: 0 };
  let sending = false;
  let backoffMs = 0;
  let retryAt = 0;

  function post(lines) {
    return new Promise((resolve, reject) => {
      const body = `${lines.join('\n')}\n`;
      const req = transport.request(target, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-ndjson',
          'Content-Length': Buffer.byteLength(body),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      }, (res) => {
        res.resume();
        res.on('end', () => (res.statusCode < 300 ? resolve() : reject(new Error(`HTTP ${res.statusCode}`))));
      });
      req.setTimeout(REQUEST_TIMEOUT_MS, () => req.destroy(new Error('timed out')));
      req.on('error', reject);
      req.end(body);
    });
  }

  // Oldest first: the local files still hold what is dropped here.
  function trim() {
    while (queue.length > MAX_QUEUE) {
      queue.shift();
      stats.dropped += 1;
    }
  }

  async function flush() {
    if (sending || queue.length === 0 || Date.now() < retryAt) return;
    sending = true;
    const batch = queue.splice(0, MAX_BATCH);
    try {
      await post(batch);
      stats.sent += batch.length;
      backoffMs = 0;
    } catch {
      // Back to the head of the queue, in order, to be tried again.
      stats.failed += 1;
      queue.unshift(...batch);
      trim();
      backoffMs = Math.min(MAX_BACKOFF_MS, backoffMs ? backoffMs * 2 : 1000);
      retryAt = Date.now() + backoffMs;
    } finally {
      sending = false;
    }
  }

  const timer = setInterval(flush, FLUSH_INTERVAL_MS);
  timer.unref(); // never the reason a process stays alive

  return {
    /** Queues the entry if its level is one that is forwarded. */
    push(entry) {
      if (!levels.includes(entry.level)) return;
      // Which machine and process said it — the first thing a central store
      // needs that a local file never did.
      queue.push(JSON.stringify({ ...entry, host, pid: process.pid }));
      trim();
      if (queue.length >= MAX_BATCH) flush();
    },
    flush,
    stats: () => ({ ...stats, queued: queue.length }),
  };
}

function createLogForwarderFromEnv(env = process.env) {
  if (!env.LOG_FORWARD_URL) return null;
  return createLogForwarder({
    url: env.LOG_FORWARD_URL,
    token: env.LOG_FORWARD_TOKEN,
    levels: env.LOG_FORWARD_LEVELS
      ? env.LOG_FORWARD_LEVELS.split(',').map((level) => level.trim()).filter(Boolean)
      : undefined,
  });
}

module.exports = { createLogForwarder, createLogForwarderFromEnv };
