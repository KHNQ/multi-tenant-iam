/**
 * The console API's response conventions, in one place.
 *
 * Errors are `{ error: <code>, fields?, correlationId }` with the same id in
 * X-Correlation-Id: the console turns the code into words an operator can act
 * on and shows the id as a reference to quote. Nothing else — no message, no
 * status text, no upstream detail — leaves in an error.
 */

function correlationId(res) {
  return res.getHeader('X-Request-Id') || null;
}

function fail(res, status, code, extra = {}) {
  const id = correlationId(res);
  if (id) res.set('X-Correlation-Id', id);
  return res.status(status).json({ error: code, ...extra, correlationId: id });
}

const denied = (res) => fail(res, 403, 'access_denied');
const notFound = (res) => fail(res, 404, 'not_found');
const invalid = (res, fields) => fail(res, 400, 'validation_failed', { fields });
const refused = (res, fields = null) => fail(res, 400, 'invalid_request', fields ? { fields } : {});
const conflict = (res) => fail(res, 409, 'conflict');
const stale = (res) => fail(res, 409, 'stale_preview');

/** In standby the primary IdP owns the data; the console says so rather than diverge from it. */
const standbyReadOnly = (res) => fail(res, 409, 'standby_read_only', {
  reason: 'standby_read_only',
  message: 'This is the backup system. Make changes in the primary system.',
});

const MAX_PAGE = 100;

/**
 * One page of a list, in the envelope every list route returns:
 *   { count, first, limit, total?, hasMore }  (the caller adds `tenant` and the collection)
 *
 * `first` is a zero-based offset (negative reads as 0); `max` is clamped to
 * 100 and `limit` says what was applied. Where `total` is withheld (clients,
 * roles) `hasMore` is inferred from a full page, so a caller may see one empty
 * final page.
 */
function page(req, items, { defaultMax = 20, total = true } = {}) {
  const first = Math.max(0, Number.parseInt(req.query.first, 10) || 0);
  const asked = Number.parseInt(req.query.max, 10);
  const limit = Math.min(MAX_PAGE, asked > 0 ? asked : defaultMax);
  const slice = items.slice(first, first + limit);
  const envelope = { count: slice.length, first, limit };
  if (total) {
    envelope.total = items.length;
    envelope.hasMore = first + slice.length < items.length;
  } else {
    envelope.hasMore = slice.length === limit;
  }
  return { envelope, slice };
}

/** Wraps an async handler so a thrown error becomes a 500 with a correlation id, never a stack. */
const handle = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (err) {
    next(err);
  }
};

module.exports = { fail, denied, notFound, invalid, refused, conflict, stale, standbyReadOnly, handle, correlationId, page };
