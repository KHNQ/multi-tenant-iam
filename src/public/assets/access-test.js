/**
 * The access-test inspector.
 * ───────────────────────────────────────────────────────────────────────────
 * "Did the role I just granted actually work?" is the question this whole
 * system exists to answer. The server answers it in one of two ways, and says
 * which in `result.mode`:
 *
 *   live-call           testing YOURSELF ("My access"). Your own token is
 *                       replayed through the gateway's /gateway routes, so the
 *                       whole exchange is shown: the claims the gateway read,
 *                       the request as it went out, and the status, headers
 *                       and body that came back.
 *
 *   policy-evaluation   testing SOMEONE ELSE (the tenant panel). The gateway
 *                       asks its own authorization function and reports the
 *                       decision and what granted or stopped it. No token is
 *                       issued for the other account and no service is
 *                       called, so there is no exchange to show — and no
 *                       credential for the tester to end up holding.
 */

import { esc, badge } from './app.js';

export const accessTestModalHtml = `
  <div class="backdrop" id="test-backdrop">
    <div class="modal">
      <div class="spread">
        <div>
          <h2 data-test-title>Access test</h2>
          <div class="muted" data-test-sub></div>
        </div>
        <button class="ghost" data-close-test>Close</button>
      </div>
      <div data-test-body></div>
    </div>
  </div>`;

export function wireAccessTestModal() {
  const backdrop = document.getElementById('test-backdrop');
  const close = () => backdrop.classList.remove('on');
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
  backdrop.querySelector('[data-close-test]').addEventListener('click', close);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });
}

const pretty = (v) => esc(JSON.stringify(v, null, 2));

function renderHeaders(headers) {
  const entries = Object.entries(headers || {});
  if (!entries.length) return '<span class="muted">none</span>';
  return `<dl class="kv wire">${entries.map(([k, v]) => `
    <dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
}

/** The token panel. Only ever the viewer's own token (live-call mode). */
function renderToken(t) {
  if (!t) return '';
  return `
    <details class="panel" style="margin-bottom:12px">
      <summary>
        <span class="caret">▶</span>
        <div style="flex:1;min-width:0">
          <div class="row" style="gap:8px">
            <strong>Bearer token</strong>
            ${badge('info', 'your own')}
            ${t.expiresInSeconds !== null ? `<span class="muted">expires in ${t.expiresInSeconds}s</span>` : ''}
          </div>
          <div class="muted mono" style="margin-top:3px;word-break:break-all">${esc(t.value)}</div>
        </div>
      </summary>
      <div class="body">
        <div class="sub">
          <h3>Header</h3>
          <pre class="wire">${pretty(t.header)}</pre>
        </div>
        <div class="sub">
          <h3>Claims — what the gateway reads to decide</h3>
          <pre class="wire">${pretty(t.claims)}</pre>
        </div>
        <p class="muted" style="margin:10px 0 0">${esc(t.note)}</p>
      </div>
    </details>`;
}

// Three outcomes, three colours. An upstream failure must not look like a
// denial: they point at opposite ends of the system.
const STATE = { allowed: 'allow', denied: 'deny', error: 'warn' };
const VERB = { allowed: 'allowed', denied: 'denied', error: 'not delivered' };

function renderEndpoint(ep) {
  const r = ep.response;
  const state = STATE[ep.decision] || 'warn';
  const label = ep.status === null ? 'no response' : `${ep.status} ${VERB[ep.decision] || ep.decision}`;
  const stoppedBy = ep.stoppedBy || ep.deniedBy;

  const bodyBlock = !r
    ? `<p class="empty">No response — ${esc(ep.error || 'the request never completed')}.</p>`
    : r.json !== null && r.json !== undefined
      ? `<pre class="wire">${pretty(r.json)}</pre>`
      : r.text
        ? `<pre class="wire">${esc(r.text)}${r.truncated ? '\n… truncated' : ''}</pre>`
        : '<span class="muted">empty body</span>';

  return `
    <details class="panel">
      <summary>
        <span class="caret">▶</span>
        <div style="flex:1;min-width:0">
          <div class="row" style="gap:8px">
            <code>${esc(ep.endpoint)}</code>
            ${badge(state, label)}
            <span class="muted mono">${ep.latencyMs}ms</span>
          </div>
          ${stoppedBy ? `<div class="muted" style="margin-top:3px">stopped at <strong>${esc(stoppedBy)}</strong></div>` : ''}
        </div>
      </summary>
      <div class="body">
        ${ep.explanation ? `
          <div class="sub">
            <h3>Why</h3>
            <p class="muted" style="margin:0;font-size:12.5px">${esc(ep.explanation)}</p>
          </div>` : ''}
        <div class="sub">
          <h3>Request</h3>
          <pre class="wire">${esc(ep.request.method)} ${esc(ep.request.url)}</pre>
          ${renderHeaders(ep.request.headers)}
        </div>
        <div class="sub">
          <h3>Response${r ? ` — ${esc(String(r.status))} ${esc(r.statusText || '')}` : ''}</h3>
          ${r ? renderHeaders(r.headers) : ''}
          ${bodyBlock}
        </div>
      </div>
    </details>`;
}

/** Why the gateway would let a call through: the policy row, or the bypass role. */
function renderGrant(g) {
  if (!g) return '';
  return g.bypass
    ? `Allowed because the account holds <strong>${esc(g.bypass)}</strong>, which bypasses policy.`
    : `Allowed by <strong>${esc(g.subject)}</strong> — <code>${esc(g.action)} ${esc(g.resource)}</code>.`;
}

/** One endpoint of a policy evaluation: the decision and its reason, nothing sent. */
function renderDecision(ep) {
  const state = STATE[ep.decision] || 'warn';
  const label = ep.decision === 'allowed' ? 'would be allowed'
    : `${ep.status} ${ep.decision === 'denied' ? 'would be denied' : 'cannot be routed'}`;
  const why = ep.decision === 'allowed' ? renderGrant(ep.grantedBy) : esc(ep.explanation || ep.error || '');

  return `
    <details class="panel">
      <summary>
        <span class="caret">▶</span>
        <div style="flex:1;min-width:0">
          <div class="row" style="gap:8px">
            <code>${esc(ep.endpoint)}</code>
            ${badge(state, label)}
          </div>
          ${ep.stoppedBy ? `<div class="muted" style="margin-top:3px">stopped at <strong>${esc(ep.stoppedBy)}</strong></div>` : ''}
        </div>
      </summary>
      <div class="body">
        <div class="sub">
          <h3>Why</h3>
          <p class="muted" style="margin:0;font-size:12.5px">${why}</p>
        </div>
      </div>
    </details>`;
}

function renderResult(result) {
  const services = result.services || [];
  if (!services.length) return '<p class="empty">No services with endpoints to test against.</p>';

  const evaluated = result.mode === 'policy-evaluation';
  const head = evaluated
    ? `<p class="muted" style="margin:0 0 12px;font-size:12.5px">${esc(result.note || '')}</p>`
    : renderToken(result.token);

  return head + services.map((svc) => `
    <div class="sub">
      <h3>${esc(svc.service)} — ${svc.allowedCount}/${svc.totalCount} ${evaluated ? 'permitted' : 'reachable'}
        ${svc.baseUrl ? `<span class="muted" style="text-transform:none;letter-spacing:0"> · ${esc(svc.baseUrl)}</span>` : ''}</h3>
      ${svc.endpoints.length
        ? svc.endpoints.map(evaluated ? renderDecision : renderEndpoint).join('')
        : '<p class="empty">No endpoints declared.</p>'}
    </div>`).join('');
}

/**
 * Runs an access test and shows it.
 *
 * @param {Function} api      the shared fetch wrapper
 * @param {object} opts
 * @param {string} opts.path  endpoint to POST to
 * @param {string} opts.title modal heading
 * @param {(r:object)=>string} [opts.subtitle] built from the result
 */
export async function runAccessTest(api, { path, title, subtitle }) {
  const modal = document.getElementById('test-backdrop');
  const set = (sel, text) => { modal.querySelector(sel).textContent = text; };

  set('[data-test-title]', title);
  set('[data-test-sub]', 'Checking every endpoint…');
  modal.querySelector('[data-test-body]').innerHTML = '';
  modal.classList.add('on');

  try {
    const result = await api(path, { method: 'POST' });
    set('[data-test-sub]', subtitle ? subtitle(result) : '');
    modal.querySelector('[data-test-body]').innerHTML = renderResult(result);
  } catch (e) {
    modal.querySelector('[data-test-body]').innerHTML =
      `<p class="empty">Test failed: ${esc(e.message)}</p>`;
  }
}
