/**
 * A small factory for declaring rules.
 *
 * Every field a `Finding` needs that is already on the `Rule` — category, severity, the
 * "why it matters" and "expected practice" text, the source skill — is copied from the rule
 * rather than restated at each call site. The old catalogue repeated all of it inline, and
 * the copies had already drifted: SEC-001's rule text said "must define explicit module role
 * access rules" while its finding text said entities "may be completely inaccessible", which
 * is a different claim. One declaration means the report cannot contradict the catalogue.
 *
 * The factory also keeps finding IDs unique. A duplicate ID silently collapses two findings
 * into one in any UI that keys on it, which is how a rule that fires on three attributes
 * ends up displaying one.
 */

import type { Finding, Rule, RuleCategory, RuleSeverity, RuleStatus } from '@mendix-analyzer/rule-engine';
import type { ApplicationIR, FactKey } from '@mendix-analyzer/application-ir';

export type Confidence = 'High' | 'Medium' | 'Low';

/** What a rule supplies per violation; everything else is inherited from the rule. */
export interface FindingSeed {
  /** Unique within the rule. Combined with the rule id to form the finding id. */
  key: string;
  artifact: string;
  observation: string;
  /** Overrides the rule's default recommendation when the fix is instance-specific. */
  recommendation?: string;
  module?: string;
  status?: RuleStatus;
  severity?: RuleSeverity;
  confidence?: Confidence;
  objectName: string;
  objectType: string;
  artifactPath: string;
  details?: Record<string, unknown>;
  snippet?: string;
}

export type Emit = (seed: FindingSeed) => void;

export interface RuleSpec {
  id: string;
  name: string;
  description: string;
  category: RuleCategory;
  subcategory: string;
  severity: RuleSeverity;
  sourceSkill: string;
  sourceSection?: string;
  expectedPractice: string;
  recommendation: string;
  whyItMatters: string;
  confidence: Confidence;
  /** Defaults to `true`. Set `false` for advisory rules that must not score a project down. */
  enabled?: boolean;
  requires: readonly FactKey[];
  check: (ir: ApplicationIR, emit: Emit) => void;
}

export function defineRule(spec: RuleSpec): Rule {
  const { check, enabled, ...metadata } = spec;

  return {
    ...metadata,
    enabled: enabled ?? true,
    evaluate: (ir) => {
      const findings: Finding[] = [];
      const usedKeys = new Set<string>();

      const emit: Emit = (seed) => {
        let key = seed.key;
        if (usedKeys.has(key)) {
          let suffix = 2;
          while (usedKeys.has(`${key}-${suffix}`)) suffix++;
          key = `${key}-${suffix}`;
        }
        usedKeys.add(key);

        findings.push({
          id: `${spec.id}-${key}`,
          ruleId: spec.id,
          ruleTitle: spec.name,
          category: spec.category,
          severity: seed.severity ?? spec.severity,
          status: seed.status ?? 'FAIL',
          module: seed.module,
          artifact: seed.artifact,
          observation: seed.observation,
          whyItMatters: spec.whyItMatters,
          expectedPractice: spec.expectedPractice,
          recommendation: seed.recommendation ?? spec.recommendation,
          confidence: seed.confidence ?? spec.confidence,
          evidence: {
            artifactPath: seed.artifactPath,
            objectName: seed.objectName,
            objectType: seed.objectType,
            details: seed.details ?? {},
            snippet: seed.snippet,
          },
          sourceSkill: spec.sourceSkill,
          sourceSection: spec.sourceSection,
        });
      };

      check(ir, emit);
      return findings;
    },
  };
}
