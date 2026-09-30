/**
 * The contract every extractor follows.
 *
 * An extractor reports not just what it read but how completely it read it. That second
 * half is the point: `docs/security.md` §4 requires an unreadable fact to reach the rules
 * as NOT_ANALYZABLE, and the only place that can be known is where the reading happened.
 */

import type { Analyzability } from '@mendix-analyzer/application-ir';

export interface Extraction<T> {
  value: T;
  analyzability: Analyzability;
  /** Why the result is PARTIAL or NOT_ANALYZABLE. Empty when fully ANALYZED. */
  notes: string[];
}

export function analyzed<T>(value: T, notes: string[] = []): Extraction<T> {
  return { value, analyzability: notes.length > 0 ? 'PARTIAL' : 'ANALYZED', notes };
}

export function notAnalyzable<T>(value: T, reason: string): Extraction<T> {
  return { value, analyzability: 'NOT_ANALYZABLE', notes: [reason] };
}
