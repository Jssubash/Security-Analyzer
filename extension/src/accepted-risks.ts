/**
 * Accepted-risk decisions: a reviewed advisory that the team has decided to live with for now.
 *
 * A decision covers exactly one advisory, in one library version, in one place — a Java library
 * (`library`, by its `folder/fileName`) or a widget package (`widget`, by its file name). It
 * records why, who and when, and a review-by date. It stops applying when:
 *
 * - the review-by date has passed (the advisory counts again, marked "review overdue"), or
 * - the library version changes (the decision was about that version only), or
 * - it is revoked.
 *
 * Decisions live in the app folder, `.security-analyzer/accepted-risks.json`, so they are committed
 * with the app and shared — and reviewed — like any other change. The extension host reads and
 * writes the file and stamps who accepted each risk and when; the pane never edits it directly.
 */

import type { LibraryVulnerability } from './java-libraries.js';

export type RiskScope = 'library' | 'widget';

export interface AcceptedRisk {
  advisoryId: string;
  scope: RiskScope;
  /** `library`: `folder/fileName`; `widget`: the widget package file name. */
  target: string;
  /** The affected library, e.g. `lodash` or `org.apache.commons:commons-text`. */
  package: string;
  /** The library version the decision was made for. */
  version: string;
  reason: string;
  /**
   * Who accepted it, stamped by the host: the person's Git name (`user.name`), or the Windows
   * account when no Git identity is set. Older decisions hold the Windows account only.
   */
  acceptedBy?: string;
  /** Their Git email (`user.email`), when `acceptedBy` came from Git. */
  acceptedByEmail?: string;
  /** The Windows account the decision was recorded from. */
  acceptedByAccount?: string;
  /** Where `acceptedBy` came from; absent on decisions recorded before Git identities were used. */
  acceptedBySource?: 'git' | 'windows';
  /** ISO timestamp, stamped by the host. */
  acceptedAt?: string;
  /** `YYYY-MM-DD`. After this date the advisory counts as open again. */
  reviewBy: string;
}

export interface AcceptedRisksFile {
  /** Where the host read the decisions from, for display. */
  path?: string;
  risks: AcceptedRisk[];
  /** Why the file could not be read, if it could not. */
  error?: string;
}

export const MIN_REASON_LENGTH = 15;
export const DEFAULT_REVIEW_DAYS = 90;
export const MAX_REVIEW_DAYS = 365;

export function riskKey(r: Pick<AcceptedRisk, 'scope' | 'target' | 'advisoryId' | 'package' | 'version'>): string {
  return `${r.scope}|${r.target}|${r.advisoryId}|${r.package}|${r.version}`;
}

/** Today as `YYYY-MM-DD` in local time — review dates are calendar days, not instants. */
export function today(now: Date = new Date()): string {
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

export function addDays(day: string, days: number): string {
  const [y, m, d] = day.split('-').map(Number);
  return today(new Date(y!, m! - 1, d! + days));
}

/** Why a proposed decision cannot be saved, or undefined when it can. */
export function validateRisk(r: Partial<AcceptedRisk>, on: string = today()): string | undefined {
  if (!r.advisoryId || !r.scope || !r.target || !r.package || !r.version) return 'The advisory to accept is not identified.';
  const reason = (r.reason ?? '').trim();
  if (reason.length < MIN_REASON_LENGTH) return `Explain why the risk is acceptable (at least ${MIN_REASON_LENGTH} characters), so a reviewer can judge it.`;
  if (!r.reviewBy || !/^\d{4}-\d{2}-\d{2}$/.test(r.reviewBy)) return 'Choose a review-by date.';
  if (r.reviewBy <= on) return 'The review-by date must be in the future.';
  if (r.reviewBy > addDays(on, MAX_REVIEW_DAYS)) return `Choose a review-by date within ${MAX_REVIEW_DAYS} days: accepted risks have to be looked at again.`;
  return undefined;
}

export interface AcceptedVulnerability {
  vulnerability: LibraryVulnerability;
  risk: AcceptedRisk;
}

export interface SplitVulnerabilities {
  /** Still counting: never accepted, or accepted with the review date passed (see `overdue`). */
  open: LibraryVulnerability[];
  /** Accepted and within the review date: shown, not counted. */
  accepted: AcceptedVulnerability[];
  /** The subset of `open` whose acceptance has lapsed, with the lapsed decision. */
  overdue: AcceptedVulnerability[];
}

export function splitByAcceptance(
  list: LibraryVulnerability[],
  risks: AcceptedRisk[],
  scope: RiskScope,
  target: string,
  on: string = today()
): SplitVulnerabilities {
  const byKey = new Map(risks.map((r) => [riskKey(r), r]));
  const out: SplitVulnerabilities = { open: [], accepted: [], overdue: [] };
  for (const v of list) {
    const risk = byKey.get(riskKey({ scope, target, advisoryId: v.id, package: v.package, version: v.version }));
    if (!risk) {
      out.open.push(v);
    } else if (risk.reviewBy < on) {
      out.open.push(v);
      out.overdue.push({ vulnerability: v, risk });
    } else {
      out.accepted.push({ vulnerability: v, risk });
    }
  }
  return out;
}

/**
 * Who accepted a decision, for display: the Git name with the email in brackets, and the Windows account
 * as a detail. A decision recorded without a Git identity — or before identities were recorded —
 * names the Windows account and says so, rather than passing an account name off as a person.
 */
export function acceptedByText(r: Pick<AcceptedRisk, 'acceptedBy' | 'acceptedByEmail' | 'acceptedByAccount' | 'acceptedBySource'>): {
  who: string;
  detail?: string;
} {
  if (!r.acceptedBy) return { who: 'unknown' };
  if (r.acceptedBySource === 'git') {
    return {
      who: r.acceptedByEmail ? `${r.acceptedBy} (${r.acceptedByEmail})` : r.acceptedBy,
      detail: r.acceptedByAccount ? `Windows account ${r.acceptedByAccount}` : undefined,
    };
  }
  return {
    who: `${r.acceptedBy} (Windows account)`,
    detail: r.acceptedBySource === 'windows' ? 'no Git identity was set on that computer' : undefined,
  };
}

/** Decisions that no longer match anything found — the library was upgraded or removed. */
export function staleRisks(risks: AcceptedRisk[], live: Set<string>): AcceptedRisk[] {
  return risks.filter((r) => !live.has(riskKey(r)));
}
