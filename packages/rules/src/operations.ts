import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const operationsRules: Rule[] = [
  {
    id: 'OPS-001',
    name: 'Sensitive Constant Exposed to Client',
    description: 'Constants marked "Expose to client" are visible in the web/mobile client package.',
    category: 'Operations',
    subcategory: 'Configuration Security',
    severity: 'Critical',
    sourceSkill: 'project-settings.md',
    sourceSection: 'Constants and Client Exposure',
    expectedPractice: 'Never expose API secrets, private keys, or passwords to the client.',
    recommendation: 'Uncheck "Expose to client" on sensitive constants.',
    whyItMatters: 'Anyone inspecting mobile package bundles or network requests can extract the secret key.',
    confidence: 'High',
    // Superseded by SEC-027, which reports the same defect in the Security category and only
    // fires when the constant actually carries a value. Leaving both enabled scored one
    // exposed constant twice, in two categories, at Critical each.
    enabled: false,
    /** reads constant names and their client exposure. */
    requires: ['constants'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const c of ir.operations.constants) {
        if (c.isExposedToClient && /(api_?key|private_?key|secret|token|password|passwd|auth_?header|credential)/i.test(c.name)) {
          findings.push({
            id: `OPS-001-${c.name}`,
            ruleId: 'OPS-001',
            ruleTitle: 'Sensitive Constant Exposed to Client',
            category: 'Operations',
            severity: 'Critical',
            status: 'FAIL',
            module: c.module,
            artifact: `Constant: ${c.name}`,
            observation: `Sensitive constant "${c.name}" is configured with "Expose to client = true".`,
            whyItMatters: 'Exposing credentials to the client allows unauthenticated reverse-engineering of secrets.',
            expectedPractice: 'Keep confidential keys server-side only.',
            recommendation: `Disable client exposure on constant "${c.name}".`,
            confidence: 'High',
            evidence: {
              artifactPath: `${c.module}.${c.name}`,
              objectName: c.name,
              objectType: 'Constant',
              details: { isExposedToClient: c.isExposedToClient },
            },
            sourceSkill: 'project-settings.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'OPS-002',
    name: 'Scheduled Event Running Frequently Without Error Logging',
    description: 'Scheduled events should be monitored and run within defined maintenance windows.',
    category: 'Operations',
    subcategory: 'Scheduled Jobs',
    severity: 'Low',
    sourceSkill: 'project-settings.md',
    sourceSection: 'Scheduled Events',
    expectedPractice: 'Ensure scheduled event microflows log start/completion telemetry.',
    recommendation: 'Add Log Message activities in the scheduled event target microflow.',
    whyItMatters: 'Silent background failures can run unnoticed for days.',
    confidence: 'Medium',
    enabled: true,
    /** Phase 1 extracts no scheduled events, so this is skipped rather than passed. */
    requires: ['scheduledEvents'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const ev of ir.operations.scheduledEvents) {
        if (ev.enabled && !ev.microflow.includes('Log')) {
          findings.push({
            id: `OPS-002-${ev.name}`,
            ruleId: 'OPS-002',
            ruleTitle: 'Scheduled Event Running Frequently Without Error Logging',
            category: 'Operations',
            severity: 'Low',
            status: 'WARNING',
            module: ev.module,
            artifact: `Scheduled Event: ${ev.name}`,
            observation: `Scheduled event "${ev.name}" triggers microflow "${ev.microflow}". Verify it logs execution telemetry.`,
            whyItMatters: 'Unlogged background jobs make troubleshooting operational anomalies difficult.',
            expectedPractice: 'Log event execution telemetry in background jobs.',
            recommendation: `Add structured logging to "${ev.microflow}".`,
            confidence: 'Medium',
            evidence: {
              artifactPath: `${ev.module}.${ev.name}`,
              objectName: ev.name,
              objectType: 'ScheduledEvent',
              details: { interval: ev.interval, microflow: ev.microflow },
            },
            sourceSkill: 'project-settings.md',
          });
        }
      }
      return findings;
    },
  },
];
