import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const integrationRules: Rule[] = [
  {
    id: 'INT-001',
    name: 'Published REST Service Missing Versioning',
    description: 'Published REST APIs must explicitly define a version in their endpoint path (e.g. /v1/).',
    category: 'Integration',
    subcategory: 'API Governance',
    severity: 'Medium',
    sourceSkill: 'rest-client.md',
    sourceSection: 'Published REST Versioning',
    expectedPractice: 'Include an explicit version prefix in published service routes.',
    recommendation: 'Prefix published service path with /v1/ or configure service version attribute.',
    whyItMatters: 'Unversioned endpoints make backwards compatibility and contract changes breaking for API consumers.',
    confidence: 'High',
    enabled: true,
    /** Phase 1 extracts no services, so this is skipped rather than passed. */
    requires: ['publishedServices'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const svc of ir.integrations.publishedRestServices) {
        if (!svc.version || !/v\d+/i.test(svc.version)) {
          findings.push({
            id: `INT-001-${svc.name}`,
            ruleId: 'INT-001',
            ruleTitle: 'Published REST Service Missing Versioning',
            category: 'Integration',
            severity: 'Medium',
            status: 'WARNING',
            module: svc.module,
            artifact: `REST Service: ${svc.name}`,
            observation: `Published REST service "${svc.name}" does not specify an API version.`,
            whyItMatters: 'API contract changes will immediately break external clients without versioning.',
            expectedPractice: 'Specify API versioning on all published services.',
            recommendation: `Set a version (e.g. "v1") on REST service "${svc.name}".`,
            confidence: 'High',
            evidence: {
              artifactPath: `${svc.module}.${svc.name}`,
              objectName: svc.name,
              objectType: 'PublishedRestService',
              details: { version: svc.version },
            },
            sourceSkill: 'rest-client.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'INT-002',
    name: 'Hardcoded Integration URL',
    description: 'External API base URLs should be managed via Mendix Constants, not hardcoded strings.',
    category: 'Integration',
    subcategory: 'Configuration Management',
    severity: 'Medium',
    sourceSkill: 'project-settings.md',
    sourceSection: 'Constants and Environment Configurations',
    expectedPractice: 'Use project Constants for external URLs to enable environment-specific configuration.',
    recommendation: 'Create a Constant in the module and reference it in the REST call activity.',
    whyItMatters: 'Hardcoded URLs point test/staging environments to production endpoints or require code changes to update.',
    confidence: 'Medium',
    enabled: true,
    /** consumed services are part of the same unread integration model. */
    requires: ['publishedServices'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const consumed of ir.integrations.consumedRestServices) {
        if (consumed.baseUrl && (consumed.baseUrl.startsWith('http://') || consumed.baseUrl.startsWith('https://'))) {
          findings.push({
            id: `INT-002-${consumed.name}`,
            ruleId: 'INT-002',
            ruleTitle: 'Hardcoded Integration URL',
            category: 'Integration',
            severity: 'Medium',
            status: 'WARNING',
            module: consumed.module,
            artifact: `Consumed REST: ${consumed.name}`,
            observation: `Consumed REST service "${consumed.name}" has hardcoded URL "${consumed.baseUrl}".`,
            whyItMatters: 'Environment switching between Dev, Test, Acceptance, and Production becomes error-prone.',
            expectedPractice: 'Store endpoint URLs in Project Constants.',
            recommendation: `Replace hardcoded URL in "${consumed.name}" with a module Constant.`,
            confidence: 'Medium',
            evidence: {
              artifactPath: `${consumed.module}.${consumed.name}`,
              objectName: consumed.name,
              objectType: 'ConsumedRestService',
              details: { url: consumed.baseUrl },
            },
            sourceSkill: 'project-settings.md',
          });
        }
      }
      return findings;
    },
  },
];
