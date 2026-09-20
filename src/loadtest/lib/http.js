/**
 * Minimal keep-alive HTTP client for the load test.
 *
 * Deliberately does NOT reject on network errors/timeouts — a load test
 * needs to record a failed request as a data point (status 0, an error
 * string) and move on, not throw and abort the whole run.
 */
const http = require('http');
const https = require('https');

function makeAgent(maxSockets) {
  return new http.Agent({ keepAlive: true, maxSockets, maxFreeSockets: maxSockets });
}

function timedRequest(method, url, { body, token, agent, timeoutMs = 10000 } = {}) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : undefined;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      agent,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    };

    const startedAt = process.hrtime.bigint();
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
        let json;
        try {
          json = JSON.parse(data);
        } catch {
          json = data;
        }
        finish({ status: res.statusCode, body: json, durationMs, error: null });
      });
    });

    req.on('error', (err) => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      finish({ status: 0, body: null, durationMs, error: err.message });
    });

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error('timeout'));
    });

    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { makeAgent, timedRequest };
