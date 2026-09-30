import { Rule } from '@mendix-analyzer/rule-engine';
import { securityRules } from './security.js';
import { dataRules } from './data.js';
import { performanceRules } from './performance.js';
import { architectureRules } from './architecture.js';
import { logicRules } from './logic.js';
import { uiRules } from './ui.js';
import { integrationRules } from './integration.js';
import { operationsRules } from './operations.js';
import { maintainabilityRules } from './maintainability.js';

export * from './define-rule.js';
export * from './security-facts.js';
export * from './security.js';
export * from './microflow-security.js';
export * from './data.js';
export * from './performance.js';
export * from './architecture.js';
export * from './logic.js';
export * from './ui.js';
export * from './integration.js';
export * from './operations.js';
export * from './maintainability.js';

/**
 * Returns the complete initial default catalog of Mendix Governance & Compliance Rules.
 */
export function getDefaultRules(): Rule[] {
  return [
    ...securityRules,
    ...dataRules,
    ...performanceRules,
    ...architectureRules,
    ...logicRules,
    ...uiRules,
    ...integrationRules,
    ...operationsRules,
    ...maintainabilityRules,
  ];
}
