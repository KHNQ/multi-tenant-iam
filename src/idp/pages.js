/**
 * The pages a person sees during sign-in and sign-out.
 *
 * No script runs on them (CSP `default-src 'none'`), except the one-line
 * auto-submit of a form_post response, which is allowed by a per-response
 * nonce. Each page may submit only back to this origin and — so that the
 * browser follows the redirect that answers it — to the client it is for.
 * English and Persian; Persian is laid out right to left.
 */

const crypto = require('crypto');
const { escapeHtml } = require('./util');

const TEXT = {
  en: {
    signIn: 'Sign in', signInTo: 'to continue to', username: 'Username or email', password: 'Password',
    submit: 'Sign in', cannotSignIn: 'Cannot sign in', newPassword: 'New password', repeatPassword: 'Repeat new password',
    choosePassword: 'Choose a new password', choosePasswordHelp: 'Your password must be replaced before you can continue.',
    setPassword: 'Set password and continue', loggedOut: 'You are signed out', loggedOutHelp: 'You can close this window.',
    confirmLogout: 'Sign out?', confirmLogoutHelp: 'Do you want to sign out of', yes: 'Sign out', redirecting: 'Continuing…',
    continue: 'Continue', invalidLogin: 'Invalid username or password.', locked: 'Too many failed attempts. Try again later.',
    enterBoth: 'Enter your username and password.', mismatch: 'The two passwords do not match.',
    standbyChange: 'Your password must be changed before you can sign in, and that is done in the primary sign-in system. This is the backup system.',
    expired: 'This page has expired. Go back to the application and start again.',
    accountChanged: 'Your account changed while you were signing in. Sign in again.',
    language: 'فارسی',
  },
  fa: {
    signIn: 'ورود', signInTo: 'برای ادامه به', username: 'نام کاربری یا ایمیل', password: 'گذرواژه',
    submit: 'ورود', cannotSignIn: 'ورود ممکن نیست', newPassword: 'گذرواژه جدید', repeatPassword: 'تکرار گذرواژه جدید',
    choosePassword: 'گذرواژه جدید انتخاب کنید', choosePasswordHelp: 'پیش از ادامه باید گذرواژه خود را تغییر دهید.',
    setPassword: 'ثبت گذرواژه و ادامه', loggedOut: 'از حساب خارج شدید', loggedOutHelp: 'می‌توانید این پنجره را ببندید.',
    confirmLogout: 'خروج؟', confirmLogoutHelp: 'آیا می‌خواهید خارج شوید از', yes: 'خروج', redirecting: 'در حال ادامه…',
    continue: 'ادامه', invalidLogin: 'نام کاربری یا گذرواژه نادرست است.', locked: 'تلاش‌های ناموفق زیاد بود. بعداً دوباره تلاش کنید.',
    enterBoth: 'نام کاربری و گذرواژه را وارد کنید.', mismatch: 'دو گذرواژه یکسان نیستند.',
    standbyChange: 'پیش از ورود باید گذرواژه خود را تغییر دهید و این کار در سامانه اصلی ورود انجام می‌شود. این سامانه پشتیبان است.',
    expired: 'این صفحه منقضی شده است. به برنامه برگردید و دوباره شروع کنید.',
    accountChanged: 'حساب شما در حین ورود تغییر کرد. دوباره وارد شوید.',
    language: 'English',
  },
};

/** The locale a request asks for: ui_locales / kc_locale, then Accept-Language. */
function localeOf(req, explicit) {
  const asked = [explicit, req.query?.ui_locales, req.query?.kc_locale, req.body?.ui_locales]
    .filter((value) => typeof value === 'string').join(' ');
  if (/\bfa\b/i.test(asked)) return 'fa';
  if (/\ben\b/i.test(asked)) return 'en';
  return /^fa\b/i.test(req.get?.('Accept-Language') || '') ? 'fa' : 'en';
}

const t = (locale, key) => TEXT[locale]?.[key] ?? TEXT.en[key];

/** A CSP source for the origin (or private-use scheme) a page's form may end up at. */
function formTarget(uri) {
  try {
    const url = new URL(uri);
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : url.protocol;
  } catch {
    return null;
  }
}

function send(res, status, { locale = 'en', title, body, formTargets = [], scriptNonce = null }) {
  const dir = locale === 'fa' ? 'rtl' : 'ltr';
  const targets = [...new Set(formTargets.map(formTarget).filter(Boolean))];
  res.status(status).set({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': [
      "default-src 'none'", "style-src 'self'", "img-src 'self'", "base-uri 'none'", "frame-ancestors 'none'",
      `form-action 'self' ${targets.join(' ')}`.trim(),
      ...(scriptNonce ? [`script-src 'nonce-${scriptNonce}'`] : []),
    ].join('; '),
  }).send(`<!doctype html>
<html lang="${locale}" dir="${dir}">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/assets/theme.css">
</head>
<body>
<div class="topbar"><div class="brand"><div class="mark">IAM</div><h1>${escapeHtml(title)}</h1></div></div>
<div class="card auth">
${body}
</div>
</body>
</html>`);
}

const banner = (message, kind = 'err') => (message ? `<p class="banner ${kind}" role="alert">${escapeHtml(message)}</p>` : '');

function errorPage(res, status, locale, message) {
  send(res, status, { locale, title: t(locale, 'cannotSignIn'), body: `<h2>${escapeHtml(t(locale, 'cannotSignIn'))}</h2><p class="muted">${escapeHtml(message)}</p>` });
}

function loginPage(res, status, { locale, action, blob, clientName, redirectUri, message = '', username = '' }) {
  const other = locale === 'fa' ? 'en' : 'fa';
  send(res, status, {
    locale,
    title: t(locale, 'signIn'),
    formTargets: [redirectUri],
    body: `
  <h2>${escapeHtml(t(locale, 'signIn'))}</h2>
  <p class="muted">${escapeHtml(t(locale, 'signInTo'))} <strong>${escapeHtml(clientName)}</strong></p>
  ${banner(message)}
  <form method="post" action="${escapeHtml(action)}">
    <input type="hidden" name="request" value="${escapeHtml(blob)}">
    <input type="hidden" name="step" value="login">
    <input type="hidden" name="ui_locales" value="${locale}">
    <label class="field">${escapeHtml(t(locale, 'username'))}
      <input name="username" autocomplete="username" value="${escapeHtml(username)}" required ${username ? '' : 'autofocus'} dir="ltr"></label>
    <label class="field">${escapeHtml(t(locale, 'password'))}
      <input name="password" type="password" autocomplete="current-password" required ${username ? 'autofocus' : ''} dir="ltr"></label>
    <button type="submit">${escapeHtml(t(locale, 'submit'))}</button>
  </form>
  <form method="post" action="${escapeHtml(action)}">
    <input type="hidden" name="request" value="${escapeHtml(blob)}">
    <input type="hidden" name="step" value="locale">
    <input type="hidden" name="ui_locales" value="${other}">
    <button type="submit" class="ghost">${escapeHtml(t(locale, 'language'))}</button>
  </form>`,
  });
}

function changePasswordPage(res, status, { locale, action, blob, continuation, redirectUri, message = '' }) {
  send(res, status, {
    locale,
    title: t(locale, 'choosePassword'),
    formTargets: [redirectUri],
    body: `
  <h2>${escapeHtml(t(locale, 'choosePassword'))}</h2>
  <p class="muted">${escapeHtml(t(locale, 'choosePasswordHelp'))}</p>
  ${banner(message)}
  <form method="post" action="${escapeHtml(action)}">
    <input type="hidden" name="request" value="${escapeHtml(blob)}">
    <input type="hidden" name="continuation" value="${escapeHtml(continuation)}">
    <input type="hidden" name="step" value="change">
    <input type="hidden" name="ui_locales" value="${locale}">
    <label class="field">${escapeHtml(t(locale, 'newPassword'))}
      <input name="new_password" type="password" autocomplete="new-password" required autofocus dir="ltr"></label>
    <label class="field">${escapeHtml(t(locale, 'repeatPassword'))}
      <input name="confirm_password" type="password" autocomplete="new-password" required dir="ltr"></label>
    <button type="submit">${escapeHtml(t(locale, 'setPassword'))}</button>
  </form>`,
  });
}

/** response_mode=form_post: the response travels to the client as a POSTed form. */
function formPostPage(res, { locale, redirectUri, params }) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const fields = Object.entries(params).filter(([, value]) => value !== undefined && value !== null)
    .map(([name, value]) => `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`).join('\n    ');
  send(res, 200, {
    locale,
    title: t(locale, 'redirecting'),
    formTargets: [redirectUri],
    scriptNonce: nonce,
    body: `
  <form method="post" action="${escapeHtml(redirectUri)}" id="response">
    ${fields}
    <noscript><button type="submit">${escapeHtml(t(locale, 'continue'))}</button></noscript>
  </form>
  <script nonce="${nonce}">document.getElementById('response').submit();</script>`,
  });
}

function loggedOutPage(res, locale) {
  send(res, 200, { locale, title: t(locale, 'loggedOut'), body: `<h2>${escapeHtml(t(locale, 'loggedOut'))}</h2><p class="muted">${escapeHtml(t(locale, 'loggedOutHelp'))}</p>` });
}

function confirmLogoutPage(res, { locale, action, blob, clientName, redirectUri }) {
  send(res, 200, {
    locale,
    title: t(locale, 'confirmLogout'),
    formTargets: redirectUri ? [redirectUri] : [],
    body: `
  <h2>${escapeHtml(t(locale, 'confirmLogout'))}</h2>
  <p class="muted">${escapeHtml(t(locale, 'confirmLogoutHelp'))} <strong>${escapeHtml(clientName)}</strong>?</p>
  <form method="post" action="${escapeHtml(action)}">
    <input type="hidden" name="confirmation" value="${escapeHtml(blob)}">
    <button type="submit">${escapeHtml(t(locale, 'yes'))}</button>
  </form>`,
  });
}

module.exports = { TEXT, t, localeOf, errorPage, loginPage, changePasswordPage, formPostPage, loggedOutPage, confirmLogoutPage };
