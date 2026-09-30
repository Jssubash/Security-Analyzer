/**
 * Self-contained exports of an analysis: an HTML report to share, and the JSON result.
 *
 * Both are built from `SecurityAnalysisResult`, which never holds a credential (passwords are
 * redacted by the host, secret constant values are dropped by the extractor), so an export
 * cannot leak what the analysis found.
 */

import type { SecurityAnalysisResult } from '../analyze.js';
import { escapeHtml as e } from './dom.js';

export function reportFileStem(result: SecurityAnalysisResult): string {
  const stamp = result.analyzedAt.replace(/[:.]/g, '-').replace(/-\d{3}Z$/, 'Z');
  const name = result.app.name.replace(/[^A-Za-z0-9_-]+/g, '_') || 'app';
  return `${name}-security-${stamp}`;
}

export function buildJsonReport(result: SecurityAnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

export function buildHtmlReport(result: SecurityAnalysisResult): string {
  const { score } = result;
  const scoreText = result.securityScore === null ? 'Not assessed' : `${result.securityScore}/100`;
  const counts = (['Critical', 'High', 'Medium', 'Low'] as const)
    .map((s) => `<span class="pill sev-${s.toLowerCase()}">${s}: ${score.severityCounts[s] ?? 0}</span>`)
    .join(' ');

  const findings = result.findings
    .map(
      (f) => `
    <article class="finding sev-${e(f.severity.toLowerCase())}">
      <header>
        <span class="pill sev-${e(f.severity.toLowerCase())}">${e(f.severity)}</span>
        <span class="status">${e(f.status)}</span>
        <strong>${e(f.ruleId)} · ${e(f.ruleTitle)}</strong>
      </header>
      <div class="artifact">${e(f.artifact)}${f.module ? ` <span class="muted">(${e(f.module)})</span>` : ''}</div>
      <p>${e(f.observation)}</p>
      <dl>
        <dt>Why it matters</dt><dd>${e(f.whyItMatters)}</dd>
        <dt>Recommendation</dt><dd>${e(f.recommendation)}</dd>
        <dt>Expected practice</dt><dd>${e(f.expectedPractice)}</dd>
        <dt>Confidence</dt><dd>${e(f.confidence)}</dd>
      </dl>
    </article>`
    )
    .join('');

  const rules = result.rules
    .map(
      (r) => `<tr><td>${e(r.id)}</td><td>${e(r.name)}</td><td>${e(r.severity)}</td><td>${e(r.status)}</td><td>${r.findingCount || ''}</td><td class="muted">${e(r.reason ?? '')}</td></tr>`
    )
    .join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report · ${e(result.app.name)}</title>
<style>
  :root { --fg:#1d2433; --muted:#5f6b7a; --bg:#fff; --line:#e3e7ee; --crit:#b42318; --high:#c4320a; --med:#b54708; --low:#475467; }
  body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); margin: 0 auto; max-width: 960px; padding: 32px 20px; }
  h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 32px 0 12px; }
  .muted { color: var(--muted); }
  .summary { display: flex; gap: 24px; flex-wrap: wrap; align-items: center; padding: 16px; border: 1px solid var(--line); border-radius: 8px; margin-top: 16px; }
  .big { font-size: 28px; font-weight: 700; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; border: 1px solid currentColor; }
  .sev-critical { color: var(--crit); } .sev-high { color: var(--high); } .sev-medium { color: var(--med); } .sev-low, .sev-informational { color: var(--low); }
  .finding { border: 1px solid var(--line); border-left: 4px solid currentColor; border-radius: 6px; padding: 12px 16px; margin: 12px 0; }
  .finding > * { color: var(--fg); } .finding header { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
  .finding .pill { color: inherit; } .status { font-size: 12px; color: var(--muted); }
  .artifact { font-family: ui-monospace, Consolas, monospace; font-size: 12.5px; color: var(--muted); margin-top: 4px; }
  dl { display: grid; grid-template-columns: 150px 1fr; gap: 4px 12px; margin: 8px 0 0; font-size: 13px; } dt { color: var(--muted); } dd { margin: 0; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; } td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
  @media (max-width: 600px) { dl { grid-template-columns: 1fr; } }
</style></head>
<body>
  <h1>Security report — ${e(result.app.name)}</h1>
  <div class="muted">Analysed ${e(new Date(result.analyzedAt).toLocaleString())} · Studio Pro ${e(result.app.studioProVersion ?? 'unknown')} · Mendix Security Analyzer</div>
  <section class="summary">
    <div><div class="muted">Security score</div><div class="big">${e(scoreText)}</div></div>
    <div><div class="muted">Risk rating</div><div class="big">${e(score.riskRating)}</div></div>
    <div><div class="muted">Rule coverage</div><div class="big">${score.coveragePercentage}%</div></div>
    <div>${counts}</div>
  </section>
  <h2>Findings (${result.findings.length})</h2>
  ${findings || '<p class="muted">No findings.</p>'}
  <h2>Rules</h2>
  <table><thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Result</th><th>Findings</th><th>Note</th></tr></thead><tbody>${rules}</tbody></table>
  <h2>What could not be read</h2>
  <ul>${result.coverage.notes.map((n) => `<li class="muted">${e(n)}</li>`).join('') || '<li class="muted">Nothing.</li>'}</ul>
</body></html>`;
}
