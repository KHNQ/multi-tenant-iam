/* Shared front-end helpers for all three consoles.
   Plain ES modules, no build step — same reasoning as the rest of the UI. */

export const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

export const h = (strings, ...values) => strings.reduce((out, s, i) => out + s + (values[i] ?? ''), '');

/* ── Banners ───────────────────────────────────────────────────────────── */

function bannerHost() {
  let el = document.getElementById('banners');
  if (!el) {
    el = document.createElement('div');
    el.id = 'banners';
    document.body.appendChild(el);
  }
  return el;
}

export function notify(kind, message, ms = kind === 'err' ? 8000 : 4000) {
  const el = document.createElement('div');
  el.className = `banner ${kind}`;
  el.innerHTML = `<span>${esc(message)}</span><button class="x" aria-label="Dismiss">×</button>`;
  el.querySelector('.x').addEventListener('click', () => el.remove());
  bannerHost().appendChild(el);
  if (ms) setTimeout(() => el.remove(), ms);
  return el;
}
export const ok = (m) => notify('ok', m);
export const warn = (m) => notify('warn', m, 10000);
export const err = (m) => notify('err', m);

/* ── Session + API ─────────────────────────────────────────────────────── */

export function session(storageKey) {
  return {
    key: storageKey,
    get token() { return sessionStorage.getItem(storageKey); },
    set token(v) {
      if (v) sessionStorage.setItem(storageKey, v);
      else sessionStorage.removeItem(storageKey);
    },
  };
}

/**
 * One fetch wrapper for every call. Surfaces the server's own error text —
 * these APIs distinguish 400/403/404/409 deliberately, and collapsing that
 * into "request failed" would throw away the most useful thing they say.
 * Any `warnings` array in a response is shown too, since the registry uses it
 * to report what it could not verify rather than failing outright.
 *
 * A SESSION_ENDED answer means the token is no longer good — signed out
 * elsewhere, password changed, account suspended, or access taken away, any
 * of which ends every session the account has. `onSessionEnded` lets the page
 * go back to the sign-in screen instead of failing call after call.
 *
 * @param {object} sess
 * @param {object} [hooks]
 * @param {() => void} [hooks.onSessionEnded]
 */
export function makeApi(sess, { onSessionEnded } = {}) {
  return async function api(path, options = {}) {
    const sentToken = sess.token;
    const res = await fetch(path, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(sess.token ? { Authorization: `Bearer ${sess.token}` } : {}),
        ...(options.headers || {}),
      },
      body: options.body && typeof options.body !== 'string'
        ? JSON.stringify(options.body) : options.body,
    });

    let body = null;
    try { body = await res.json(); } catch { /* no body */ }

    if (!res.ok) {
      const message = body?.error || `${res.status} ${res.statusText}`;
      err(body?.hint ? `${message} — ${body.hint}` : message);
      // Only if the token that was refused is still the current one: a late
      // reply to a call made before signing out must not sign anyone out.
      if (body?.code === 'SESSION_ENDED' && sentToken === sess.token && onSessionEnded) onSessionEnded();
      const e = new Error(message);
      e.status = res.status;
      e.body = body;
      throw e;
    }
    (body?.warnings || []).forEach(warn);
    return body;
  };
}

/* ── Small render helpers ──────────────────────────────────────────────── */

/**
 * A row of chips, optionally each with a remove button.
 *
 * `valueAttr` names the data attribute carrying the chip's own value, and it
 * matters: a remove button usually needs BOTH a subject (whose chip is this)
 * and the value (which chip). Defaulting the value to a generic `data-value`
 * and having handlers fall back `data-subject || data-value` silently picks
 * the wrong one whenever both are present — which is how a "remove role"
 * button came to send the username as the role. Name it, and the handler
 * cannot confuse the two.
 *
 * @param {string[]} items
 * @param {object} [opts]
 * @param {boolean} [opts.removable]
 * @param {object} [opts.data]       extra data-* attributes on the button
 * @param {string} [opts.valueAttr]  attribute name for the chip's own value
 * @param {string} [opts.cls]
 */
export const chips = (items, { removable, data = {}, valueAttr = 'value', cls = '' } = {}) =>
  (items || []).length
    ? items.map((v) => `<span class="chip ${cls}">${esc(v)}${
      removable
        ? `<button ${Object.entries({ ...data, [valueAttr]: v })
          .map(([k, d]) => `data-${k}="${esc(d)}"`).join(' ')} title="Remove">×</button>`
        : ''
    }</span>`).join('')
    : '';

export const badge = (state, label) => `<span class="badge ${esc(state)}">${esc(label ?? state)}</span>`;

export const when = (cond, html) => (cond ? html : '');

export const confirmDanger = (message) => window.confirm(message);

/** Comma/whitespace separated text -> trimmed list. */
export const parseList = (text) => String(text || '')
  .split(/[,\n]/).map((s) => s.trim()).filter(Boolean);

export function relTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const secs = Math.round((Date.now() - d.getTime()) / 1000);
  const units = [[60, 's'], [60, 'm'], [24, 'h'], [365, 'd']];
  let v = secs; let unit = 's';
  for (const [size, u] of units) {
    if (Math.abs(v) < size) { unit = u; break; }
    v = Math.round(v / size); unit = u;
  }
  return v < 1 && unit === 's' ? 'just now' : `${v}${unit} ago`;
}

/* ── Entitlement ───────────────────────────────────────────────────────── */

/**
 * Which consoles this account may see, given the server's own answer about
 * who they are. Pure and exported so it can be exercised directly against
 * live /me + /tenants/mine data (see src/ui-check.js) rather than only by
 * clicking through the page.
 *
 * This decides what is *rendered*; it is not what protects anything. Every
 * view's data comes from an endpoint that authorises the caller server-side,
 * so a tampered client gets an empty, 403-ing shell rather than access.
 *
 * @param {{ isPlatformAdmin?: boolean }} me       response from GET /me
 * @param {Array<{ isAdmin?: boolean }>} myTenants response from GET /tenants/mine
 */
/**
 * Does this account administer any part of the tenant? Administration is four
 * separate grants now (members, roles, policies, destinations), so "is an
 * admin" is no longer the whole question.
 */
export const administers = (tenant) => Boolean(tenant.isAdmin) || (tenant.permissions || []).length > 0;

export function entitledViews(me, myTenants = []) {
  const adminOf = myTenants.filter(administers);
  const views = [{ id: 'access', label: 'My access' }];

  // A platform admin manages every tenant from the platform view, so a second
  // owner-scoped copy of the same panel would be redundant for them.
  if (!me?.isPlatformAdmin && adminOf.length) {
    views.push({ id: 'services', label: 'My services', count: adminOf.length });
  }
  if (me?.isPlatformAdmin) views.push({ id: 'platform', label: 'Platform' });
  return views;
}

/** The view to land on: the most privileged thing this account can do. */
export const defaultView = (views) => views[views.length - 1].id;
