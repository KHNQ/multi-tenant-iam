/**
 * What the gateway forwards to a service, rebuilt from what it received.
 * ─────────────────────────────────────────────────────────────────────────────
 * A request to `/gateway/{service}/a%2Fb?x=1&x=2` has to reach the service as
 * `/{service}/a%2Fb?x=1&x=2`, with the body it came with. Three parts, each
 * carried across separately and none of them re-interpreted:
 *
 *   path    `/{service}` + the rest of the path, exactly as the client wrote
 *           it. Not decoded and re-encoded: `%2F` inside a segment is one
 *           segment, and decoding it addresses a different resource. This is
 *           also the string authorization is decided on, so what is checked
 *           and what is forwarded are the same bytes.
 *   query   the raw text after the first `?`, or nothing. Never parsed: a
 *           round trip through a query-string parser reorders repeated keys,
 *           drops empty ones and changes `+` and `%20`.
 *   body    the bytes, untouched (see resendConsumedBody).
 */

function splitTarget(url) {
  const mark = url.indexOf('?');
  return mark === -1
    ? { path: url, query: null }
    : { path: url.slice(0, mark), query: url.slice(mark + 1) };
}

/** A `.` or `..` path segment, in plain or percent-encoded spelling. */
function hasDotSegment(path) {
  return path.split('/').some((segment) => {
    const plain = segment.replace(/%2e/gi, '.');
    return plain === '.' || plain === '..';
  });
}

/**
 * @param {string} serviceName the validated :serviceName
 * @param {string} strippedUrl req.url inside the /gateway/:serviceName mount —
 *   everything after the service name, query string included
 * @returns {{ path: string, query: string|null, url: string } | { problem: string }}
 */
function rebuildTarget(serviceName, strippedUrl) {
  const { path: rest, query } = splitTarget(strippedUrl);

  // `/svc/public/../admin` is authorised as one path and resolved, by
  // whatever receives it, as another. No reading of it is safe to forward.
  if (hasDotSegment(rest)) {
    return { problem: "The path contains '.' or '..' segments, which the gateway does not forward" };
  }

  const path = `/${serviceName}${rest.startsWith('/') ? rest : `/${rest}`}`;
  return { path, query, url: query === null ? path : `${path}?${query}` };
}

/**
 * The request-target to put on the wire to the service: any path prefix its
 * base URL carries, then the rebuilt target, verbatim.
 *
 * It is assigned to the outgoing request directly rather than left to
 * http-proxy, which would run it through url.parse() and collapse `//` on the
 * way — re-normalising a path that has already been authorised as written.
 */
function upstreamRequestTarget(baseUrl, target) {
  const prefix = new URL(baseUrl).pathname.replace(/\/+$/, '');
  return `${prefix}${target.url}`;
}

/**
 * The gateway does not read the body of a proxied request: its JSON parser is
 * kept off /gateway, so the incoming stream is piped to the service as it
 * arrives — any content type, any size, byte for byte.
 *
 * This is for the case where that has gone wrong and something in front of
 * the proxy has already consumed the stream (a parser mounted globally, say).
 * The stream is then empty, and piping it would send the service a request
 * whose Content-Length promises a body that never comes: it waits, and the
 * caller times out. If the raw bytes were kept (express.json's `verify` hook
 * stores them as req.rawBody), they are written to the outgoing request here
 * — the original bytes, not a re-serialisation of the parsed object, which
 * would change spacing, key order, large numbers and duplicate keys.
 *
 * @returns {boolean} whether a body was re-sent
 */
function resendConsumedBody(proxyReq, req) {
  if (!Buffer.isBuffer(req.rawBody)) return false;
  proxyReq.removeHeader('Transfer-Encoding');
  proxyReq.setHeader('Content-Length', req.rawBody.length);
  proxyReq.write(req.rawBody);
  return true;
}

module.exports = { rebuildTarget, upstreamRequestTarget, resendConsumedBody };
