/**
 * The access-test inspector.
 * ───────────────────────────────────────────────────────────────────────────
 * "Did the role I just granted actually work?" is the question this whole
 * system exists to answer, so the test shows the entire exchange rather than a
 * green tick: the token that was presented and its decoded claims, the request
 * as it went out, and the status, headers and body that came back.
 *
 * The probe runs server-side over loopback through the gateway's own
 * /gateway routes, so what is displayed is the real
 * authenticate -> enforce -> proxy path, not a re-reading of the policy table.
 *
 * Shared by the tenant panel (testing a member) and the console's own
 * "My access" view (testing yourself).
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

/** The token panel — claims in full, the signature deliberately not. */
function renderToken(t) {
  if (!t) return '';
  return `
    <details class="panel" style="margin-bottom:12px">
      <summary>
        <span class="caret">▶</span>
        <div style="flex:1;min-width:0">
          <div class="row" style="gap:8px">
            <strong>Bearer token</strong>
            ${t.masked ? badge('warn', 'masked') : badge('info', 'your own')}
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

function renderResult(result) {
  const services = result.services || [];
  if (!services.length) return '<p class="empty">No services with endpoints to test against.</p>';

  return renderToken(result.token) + services.map((svc) => `
    <div class="sub">
      <h3>${esc(svc.service)} — ${svc.allowedCount}/${svc.totalCount} reachable
        ${svc.baseUrl ? `<span class="muted" style="text-transform:none;letter-spacing:0"> · ${esc(svc.baseUrl)}</span>` : ''}</h3>
      ${svc.endpoints.length
        ? svc.endpoints.map(renderEndpoint).join('')
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
  set('[data-test-sub]', 'Calling every endpoint and recording the whole exchange…');
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
