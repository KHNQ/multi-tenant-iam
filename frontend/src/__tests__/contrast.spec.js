import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * IAM-0207 lists contrast as an acceptance criterion, so the palette is measured
 * rather than eyeballed. Values are parsed straight out of style.css: if someone
 * retunes a colour and drops below WCAG AA, this fails.
 */

// vitest runs from the package root; jsdom does not give us a file: import.meta.url
const css = readFileSync(resolve(process.cwd(), 'src/style.css'), 'utf8')

function tokensFor(blockRe) {
  const block = css.match(blockRe)
  if (!block) throw new Error(`token block not found: ${blockRe}`)
  const out = {}
  for (const [, name, value] of block[1].matchAll(/(--iam-[\w-]+):\s*(oklch\([^)]*\))/g)) {
    out[name] = value
  }
  return out
}

/** oklch() -> sRGB, enough of the spec to measure luminance. */
function oklchToRgb(str) {
  const [l, c, h] = str.match(/oklch\(([^)]*)\)/)[1].trim().split(/\s+/).map(Number)
  const hr = (h * Math.PI) / 180
  const a = c * Math.cos(hr)
  const b = c * Math.sin(hr)

  const l_ = l + 0.3963377774 * a + 0.2158037573 * b
  const m_ = l - 0.1055613458 * a - 0.0638541728 * b
  const s_ = l - 0.0894841775 * a - 1.291485548 * b
  const L = l_ ** 3, M = m_ ** 3, S = s_ ** 3

  const lin = [
    +4.0767416621 * L - 3.3077115913 * M + 0.2309699292 * S,
    -1.2684380046 * L + 2.6097574011 * M - 0.3413193965 * S,
    -0.0041960863 * L - 0.7034186147 * M + 1.707614701 * S,
  ]
  return lin.map((v) => Math.min(1, Math.max(0, v)))
}

function luminance(linearRgb) {
  const [r, g, b] = linearRgb
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function ratio(fg, bg) {
  const a = luminance(oklchToRgb(fg))
  const b = luminance(oklchToRgb(bg))
  const [hi, lo] = a > b ? [a, b] : [b, a]
  return (hi + 0.05) / (lo + 0.05)
}

const themes = {
  light: tokensFor(/:root,\s*:host\s*\{([^}]*)\}/),
  dark: tokensFor(/\.dark,\s*:host\(\.dark\)\s*\{([^}]*)\}/),
}

describe.each(Object.entries(themes))('%s theme contrast (WCAG AA)', (name, t) => {
  it('body text on the page surface meets 4.5:1', () => {
    expect(ratio(t['--iam-content'], t['--iam-surface'])).toBeGreaterThanOrEqual(4.5)
  })

  it('body text on raised surfaces meets 4.5:1', () => {
    expect(ratio(t['--iam-content'], t['--iam-surface-raised'])).toBeGreaterThanOrEqual(4.5)
  })

  it('muted text meets 4.5:1 - it is still content, not decoration', () => {
    expect(ratio(t['--iam-content-muted'], t['--iam-surface'])).toBeGreaterThanOrEqual(4.5)
  })

  it('brand buttons meet 4.5:1 between label and fill', () => {
    expect(ratio(t['--iam-brand-content'], t['--iam-brand'])).toBeGreaterThanOrEqual(4.5)
  })

  it('danger text on its surface meets 4.5:1', () => {
    expect(ratio(t['--iam-danger'], t['--iam-danger-surface'])).toBeGreaterThanOrEqual(4.5)
  })
})
