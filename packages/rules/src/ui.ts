import { Rule, Finding } from '@mendix-analyzer/rule-engine';

export const uiRules: Rule[] = [
  {
    id: 'UI-001',
    name: 'Page Widget Count Exceeds Recommended Limit',
    description: 'Pages with more than 40 widgets degrade client DOM performance and should use snippets.',
    category: 'UI',
    subcategory: 'Page Performance',
    severity: 'Low',
    sourceSkill: 'create-page.md',
    sourceSection: 'Page Structure and Snippets',
    expectedPractice: 'Break heavy pages into reusable snippets and lazy-loaded tabs.',
    recommendation: 'Extract groups of widgets into Mendix Snippets.',
    whyItMatters: 'Large DOM trees increase initial page render time and memory consumption on mobile browsers.',
    confidence: 'High',
    enabled: true,
    /** widget counts are read from the page documents. */
    requires: ['pageAccess'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, page] of Object.entries(ir.pages)) {
        if (page.totalWidgets > 40) {
          findings.push({
            id: `UI-001-${page.name}`,
            ruleId: 'UI-001',
            ruleTitle: 'Page Widget Count Exceeds Recommended Limit',
            category: 'UI',
            severity: 'Low',
            status: 'WARNING',
            module: page.module,
            artifact: `Page: ${page.name}`,
            observation: `Page "${page.name}" contains ${page.totalWidgets} widgets (threshold: 40).`,
            whyItMatters: 'Excessive widgets increase browser DOM tree depth and delay page load.',
            expectedPractice: 'Modularize dense pages using Snippets.',
            recommendation: `Extract reusable sections of "${page.name}" into Snippets.`,
            confidence: 'High',
            evidence: {
              artifactPath: `${page.module}.${page.name}`,
              objectName: page.name,
              objectType: 'Page',
              details: { widgetCount: page.totalWidgets },
            },
            sourceSkill: 'create-page.md',
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'UI-002',
    name: 'Unprotected Page Access',
    description: 'Pages without assigned user roles can either be inaccessible or accidentally exposed.',
    category: 'UI',
    subcategory: 'Page Access Security',
    severity: 'High',
    sourceSkill: 'manage-security.md',
    sourceSection: 'Page Access',
    expectedPractice: 'Explicitly configure allowed user/module roles for every page.',
    recommendation: 'Open Page Properties in Studio Pro -> Visible for -> Select authorized roles.',
    whyItMatters: 'Missing page permissions lead to navigation errors or unauthorized page views.',
    confidence: 'High',
    // Superseded by SEC-019, which reports the same pages. A page with no allowed roles cannot
    // be opened by anyone, so it is a configuration gap rather than an exposure: SEC-019 rates
    // it Low/WARNING deliberately, and this rule's High/FAIL contradicted that in a second
    // category for the same finding.
    enabled: false,
    /** reads AllowedModuleRoles from the page documents. */
    requires: ['pageAccess'],
    evaluate: (ir) => {
      const findings: Finding[] = [];
      for (const [key, page] of Object.entries(ir.pages)) {
        const mod = ir.modules[page.module];
        const isExcluded = page.module.toLowerCase() === 'system' || (mod && (mod.isSystem || mod.isMarketplace));
        if (page.allowedRoles.length === 0 && !isExcluded) {
          findings.push({
            id: `UI-002-${page.name}`,
            ruleId: 'UI-002',
            ruleTitle: 'Unprotected Page Access',
            category: 'UI',
            severity: 'High',
            status: 'FAIL',
            module: page.module,
            artifact: `Page: ${page.name}`,
            observation: `Page "${page.name}" has no roles assigned to its visibility list.`,
            whyItMatters: 'Without role assignments, runtime access is either denied unexpectedly or fails security auditing.',
            expectedPractice: 'Assign explicit roles to all navigable pages.',
            recommendation: `Configure role permissions on page "${page.name}".`,
            confidence: 'High',
            evidence: {
              artifactPath: `${page.module}.${page.name}`,
              objectName: page.name,
              objectType: 'Page',
              details: { rolesCount: page.allowedRoles.length },
            },
            sourceSkill: 'manage-security.md',
          });
        }
      }
      return findings;
    },
  },
];
