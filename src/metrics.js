/**
 * Metrics, in the Prometheus text exposition format.
 * ─────────────────────────────────────────────────────────────────────────────
 * Three instrument kinds — counter, gauge, histogram — and a render() that
 * prints them. That is the whole of what a scraper needs, and it is small
 * enough to own: no client library, no default metrics nobody asked for, and
 * nothing here that can affect a request (an instrument that is handed a bad
 * value records nothing rather than throwing).
 *
 * Label values are escaped on the way out, so a value that came from a
 * request cannot break the exposition or inject a line into it. Callers still
 * must not label by anything unbounded (a username, a path): every distinct
 * label set is a time series somebody has to store.
 */

const escapeLabel = (value) => String(value).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');

function labelText(names, values) {
  if (names.length === 0) return '';
  return `{${names.map((name, i) => `${name}="${escapeLabel(values[i])}"`).join(',')}}`;
}

// A series is identified by its label values, in the declared order.
const seriesKey = (names, labels) => names.map((name) => String(labels?.[name] ?? '')).join('\u0000');

const DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

function createMetrics() {
  const instruments = [];

  function counter(name, help, labelNames = []) {
    const series = new Map();
    instruments.push({
      name, help, type: 'counter',
      lines: () => [...series.values()].map(({ values, total }) => `${name}${labelText(labelNames, values)} ${total}`),
    });
    return {
      inc(labels = {}, amount = 1) {
        if (!(amount >= 0)) return;
        const key = seriesKey(labelNames, labels);
        const entry = series.get(key) || { values: labelNames.map((n) => labels[n] ?? ''), total: 0 };
        entry.total += amount;
        series.set(key, entry);
      },
    };
  }

  /**
   * @param {() => (number | Array<{ labels: object, value: number }> | Promise<…>)} [collect]
   *   read at scrape time instead of being set — for values that already live
   *   somewhere else (a queue's length, a version number).
   */
  function gauge(name, help, labelNames = [], collect = null) {
    const series = new Map();
    instruments.push({
      name, help, type: 'gauge',
      lines: async () => {
        if (collect) {
          const read = await collect();
          const samples = Array.isArray(read) ? read : [{ labels: {}, value: read }];
          return samples
            .filter((sample) => Number.isFinite(sample.value))
            .map((sample) => `${name}${labelText(labelNames, labelNames.map((n) => sample.labels?.[n] ?? ''))} ${sample.value}`);
        }
        return [...series.values()].map(({ values, value }) => `${name}${labelText(labelNames, values)} ${value}`);
      },
    });
    return {
      set(labels, value) {
        if (typeof labels === 'number') { value = labels; labels = {}; }
        if (!Number.isFinite(value)) return;
        series.set(seriesKey(labelNames, labels), { values: labelNames.map((n) => labels[n] ?? ''), value });
      },
    };
  }

  function histogram(name, help, labelNames = [], buckets = DEFAULT_BUCKETS) {
    const series = new Map();
    instruments.push({
      name, help, type: 'histogram',
      lines: () => [...series.values()].flatMap(({ values, counts, sum, count }) => {
        const withLe = (le) => labelText([...labelNames, 'le'], [...values, le]);
        return [
          ...buckets.map((le, i) => `${name}_bucket${withLe(le)} ${counts[i]}`),
          `${name}_bucket${withLe('+Inf')} ${count}`,
          `${name}_sum${labelText(labelNames, values)} ${sum}`,
          `${name}_count${labelText(labelNames, values)} ${count}`,
        ];
      }),
    });
    return {
      observe(labels, value) {
        if (typeof labels === 'number') { value = labels; labels = {}; }
        if (!(value >= 0)) return;
        const key = seriesKey(labelNames, labels);
        const entry = series.get(key)
          || { values: labelNames.map((n) => labels[n] ?? ''), counts: buckets.map(() => 0), sum: 0, count: 0 };
        // Buckets are cumulative: an observation counts in every bucket it fits under.
        buckets.forEach((le, i) => { if (value <= le) entry.counts[i] += 1; });
        entry.sum += value;
        entry.count += 1;
        series.set(key, entry);
      },
    };
  }

  /** The exposition: every instrument, in the order it was declared. */
  async function render() {
    const blocks = [];
    for (const instrument of instruments) {
      let lines;
      try { lines = await instrument.lines(); } catch { lines = []; } // a gauge that cannot be read is absent, not fatal
      blocks.push(`# HELP ${instrument.name} ${instrument.help}`, `# TYPE ${instrument.name} ${instrument.type}`, ...lines);
    }
    return `${blocks.join('\n')}\n`;
  }

  return { counter, gauge, histogram, render };
}

module.exports = { createMetrics, CONTENT_TYPE: 'text/plain; version=0.0.4; charset=utf-8' };
