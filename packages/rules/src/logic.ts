import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const logicRules: Rule[] = [
  {
    id: 'MF-001',
    name: 'Missing Error Handler on Critical Microflow',
    description: 'Microflows performing batch updates or external integration calls must implement error handling.',
    category: 'Logic',
    subcategory: 'Robustness',
    severity: 'Medium',
    sourceSkill: 'write-microflows.md',
    sourceSection: 'Error Handling Patterns',
    expectedPractice: 'Configure custom error handling with rollback and logging on critical activities.',
    recommendation: 'Right-click the call activity -> Set Error Handling -> Custom with rollback or compensating action.',
    whyItMatters: 'Unhandled errors crash the user session and can leave the database in an inconsistent state.',
    confidence: 'High',
    enabled: true,
    /** cyclomatic complexity is computed from the activity graph. */
    requires: ['microflowActivities'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, mf] of Object.entries(ir.microflows)) {
        if (
          (mf.name.startsWith('SUB_') || mf.name.toLowerCase().includes('batch') || mf.callsMicroflows.length > 3) &&
          !mf.hasErrorHandling
        ) {
          findings.push({
            id: `MF-001-${mf.name}`,
            ruleId: 'MF-001',
            ruleTitle: 'Missing Error Handler on Critical Microflow',
            category: 'Logic',
            severity: 'Medium',
            status: 'WARNING',
            module: mf.module,
            artifact: `Microflow: ${mf.name}`,
            observation: `Microflow "${mf.name}" performs critical or batch logic without error handling.`,
            whyItMatters: 'Unexpected exceptions will terminate execution abruptly without graceful recovery or user feedback.',
            expectedPractice: 'Implement error handling handlers on all batch and integration flows.',
            recommendation: `Add error handling handlers in "${mf.name}".`,
            confidence: 'High',
            evidence: {
              artifactPath: `${mf.module}.${mf.name}`,
              objectName: mf.name,
              objectType: 'Microflow',
              details: { hasErrorHandling: mf.hasErrorHandling, complexity: mf.cyclomaticComplexity },
            },
            sourceSkill: 'write-microflows.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'MF-002',
    name: 'Oversized Microflow Without Modularization',
    description: 'Microflows with more than 20 activities should be decomposed into cohesive sub-microflows.',
    category: 'Logic',
    subcategory: 'Maintainability',
    severity: 'Low',
    sourceSkill: 'write-microflows.md',
    sourceSection: 'Microflow Modularization',
    expectedPractice: 'Keep microflows concise (under 15–20 activities) for readability and testability.',
    recommendation: 'Extract sequential logical blocks into sub-microflows.',
    whyItMatters: 'Long microflows are difficult to comprehend, navigate, and unit test.',
    confidence: 'High',
    enabled: true,
    /** error handling is an activity-level fact. */
    requires: ['microflowActivities'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, mf] of Object.entries(ir.microflows)) {
        if (mf.activities.length > 20) {
          findings.push({
            id: `MF-002-${mf.name}`,
            ruleId: 'MF-002',
            ruleTitle: 'Oversized Microflow Without Modularization',
            category: 'Logic',
            severity: 'Low',
            status: 'WARNING',
            module: mf.module,
            artifact: `Microflow: ${mf.name}`,
            observation: `Microflow "${mf.name}" contains ${mf.activities.length} activities (threshold: 20).`,
            whyItMatters: 'Excessively long flows create maintenance friction and are difficult to unit-test effectively.',
            expectedPractice: 'Extract logic into sub-microflows prefixed with SUB_.',
            recommendation: `Split "${mf.name}" into smaller, reusable sub-microflows.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${mf.module}.${mf.name}`,
              objectName: mf.name,
              objectType: 'Microflow',
              details: { activityCount: mf.activities.length },
            },
            sourceSkill: 'write-microflows.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'NF-001',
    name: 'High Cyclomatic Complexity Nanoflow',
    description: 'Nanoflows should remain simple UI helpers; complex business logic belongs in microflows.',
    category: 'Logic',
    subcategory: 'Client Logic',
    severity: 'Medium',
    sourceSkill: 'write-nanoflows.md',
    sourceSection: 'Nanoflow Responsibilities',
    expectedPractice: 'Keep nanoflow complexity low (<= 5). Move heavy processing to the server via microflow call.',
    recommendation: 'Move complex branching and data transformation to a server-side microflow.',
    whyItMatters: 'Heavy client-side logic slows mobile device rendering and exposes business rules to the client.',
    confidence: 'High',
    enabled: true,
    /** nanoflow complexity is computed from the activity graph. */
    requires: ['microflowActivities'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, nf] of Object.entries(ir.nanoflows)) {
        if (nf.cyclomaticComplexity > 8) {
          findings.push({
            id: `NF-001-${nf.name}`,
            ruleId: 'NF-001',
            ruleTitle: 'High Cyclomatic Complexity Nanoflow',
            category: 'Logic',
            severity: 'Medium',
            status: 'WARNING',
            module: nf.module,
            artifact: `Nanoflow: ${nf.name}`,
            observation: `Nanoflow "${nf.name}" has cyclomatic complexity of ${nf.cyclomaticComplexity} (threshold: 8).`,
            whyItMatters: 'High client-side complexity can degrade mobile performance.',
            expectedPractice: 'Offload non-trivial calculations to server microflows.',
            recommendation: `Refactor "${nf.name}" and delegate business calculations to a server microflow.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${nf.module}.${nf.name}`,
              objectName: nf.name,
              objectType: 'Nanoflow',
              details: { complexity: nf.cyclomaticComplexity },
            },
            sourceSkill: 'write-nanoflows.md',
          });
        }
      }
      return findings;
    },
  },
];
