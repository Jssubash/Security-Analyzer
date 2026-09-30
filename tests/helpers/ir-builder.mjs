/**
 * Minimal synthetic IRs for per-rule tests.
 *
 * `docs/security.md` §8 test 3 asks for one IR per rule that must fire and one that must not.
 * The point of building those by hand rather than reusing the reference project is that a rule
 * which fires on TestApp might be firing for the wrong reason; a two-entity IR where exactly
 * one fact differs between the firing and quiet cases pins down *which* fact the rule reads.
 *
 * The baseline is a clean, locked-down app: production security level, no guest access, no demo
 * users, a policy at baseline. Every test starts from that and introduces exactly one defect.
 */

const MODULES = {
  App: {
    name: 'App',
    type: 'user',
    isSystem: false,
    isMarketplace: false,
    entities: [],
    microflows: [],
    nanoflows: [],
    pages: [],
    dependencies: [],
  },
  Market: {
    name: 'Market',
    type: 'marketplace',
    isSystem: false,
    isMarketplace: true,
    entities: [],
    microflows: [],
    nanoflows: [],
    pages: [],
    dependencies: [],
  },
};

const FULL_COVERAGE = {
  projectSecurity: 'ANALYZED',
  moduleRoles: 'ANALYZED',
  entityAccessRules: 'ANALYZED',
  attributeTypes: 'ANALYZED',
  pageAccess: 'ANALYZED',
  publishedServices: 'ANALYZED',
  microflows: 'ANALYZED',
  microflowActivities: 'ANALYZED',
  modelReferences: 'ANALYZED',
  constants: 'ANALYZED',
  scheduledEvents: 'ANALYZED',
  notes: [],
};

/** A clean baseline IR, with `overrides` merged one level deep. */
export function makeIr(overrides = {}) {
  const base = {
    metadata: {
      name: 'Synthetic',
      mendixVersion: '11.12.4',
      applicationType: 'web',
      primaryMprPath: 'Synthetic.mpr',
      totalModules: 2,
      totalEntities: 0,
      totalMicroflows: 0,
      totalNanoflows: 0,
      totalPages: 0,
    },
    coverage: { ...FULL_COVERAGE },
    modules: structuredClone(MODULES),
    entities: {},
    associations: [],
    microflows: {},
    nanoflows: {},
    pages: {},
    security: {
      projectSecurityLevel: 'CheckEverything',
      isProductionReady: true,
      userRoles: [],
      moduleRoles: [],
      anonymousUserEnabled: false,
      securityEnabled: true,
      strictMode: true,
      strictPageUrlCheck: true,
      demoUsersEnabled: false,
      demoUsers: [],
      passwordPolicy: {
        minimumLength: 12,
        requireDigit: true,
        requireMixedCase: true,
        requireSymbol: true,
      },
    },
    integrations: {
      publishedRestServices: [],
      consumedRestServices: [],
      publishedODataServices: [],
    },
    customCode: { javaActions: [], javaScriptActions: [], vendorJars: [], widgetPackages: [] },
    operations: { constants: [], scheduledEvents: [] },
    dependencyGraph: { nodes: [], edges: [], cycles: [], godModules: [] },
    generatedAt: '2026-01-01T00:00:00.000Z',
  };

  const ir = { ...base, ...overrides };
  if (overrides.security) ir.security = { ...base.security, ...overrides.security };
  if (overrides.coverage) ir.coverage = { ...base.coverage, ...overrides.coverage };
  if (overrides.operations) ir.operations = { ...base.operations, ...overrides.operations };
  if (overrides.customCode) ir.customCode = { ...base.customCode, ...overrides.customCode };
  if (overrides.integrations) ir.integrations = { ...base.integrations, ...overrides.integrations };
  return ir;
}

export function userRole(name, moduleRoles = [], extra = {}) {
  return {
    name,
    moduleRoles: moduleRoles.map((q) => {
      const dot = q.indexOf('.');
      return { module: q.slice(0, dot), role: q.slice(dot + 1) };
    }),
    manageableRoles: [],
    isAnonymous: false,
    isAdministrator: false,
    checkSecurity: true,
    ...extra,
  };
}

export function moduleRole(qualifiedName) {
  const dot = qualifiedName.indexOf('.');
  return {
    name: qualifiedName.slice(dot + 1),
    module: qualifiedName.slice(0, dot),
    qualifiedName,
  };
}

export function attribute(name, type = 'String', extra = {}) {
  return { name, type, isCalculated: false, isSensitive: false, isPii: false, ...extra };
}

export function accessRule(moduleRoles, extra = {}) {
  return {
    id: 'rule-1',
    moduleRoles,
    allowCreate: false,
    allowDelete: false,
    defaultMemberAccess: 'None',
    memberAccess: [],
    ...extra,
  };
}

export function entity(qualifiedName, extra = {}) {
  const dot = qualifiedName.indexOf('.');
  return {
    name: qualifiedName.slice(dot + 1),
    module: qualifiedName.slice(0, dot),
    qualifiedName,
    persistenceType: 'persistable',
    specializations: [],
    attributes: [],
    indexes: [],
    accessRules: [],
    isSecurityConfigured: true,
    ...extra,
  };
}

export function page(qualifiedName, extra = {}) {
  const dot = qualifiedName.indexOf('.');
  return {
    name: qualifiedName.slice(dot + 1),
    module: qualifiedName.slice(0, dot),
    qualifiedName,
    totalWidgets: 1,
    widgets: [],
    allowedRoles: [],
    isAccessibleAnonymously: false,
    ...extra,
  };
}

export function microflow(qualifiedName, extra = {}) {
  const dot = qualifiedName.indexOf('.');
  return {
    name: qualifiedName.slice(dot + 1),
    module: qualifiedName.slice(0, dot),
    qualifiedName,
    returnType: 'Void',
    parameters: [],
    activities: [],
    cyclomaticComplexity: 1,
    hasErrorHandling: true,
    callsMicroflows: [],
    callsJavaActions: [],
    retrievesInsideLoops: [],
    commitsInsideLoops: [],
    deletesInsideLoops: [],
    isExposedAsService: false,
    allowedRoles: [],
    appliesEntityAccess: true,
    ...extra,
  };
}

export function constant(qualifiedName, extra = {}) {
  const dot = qualifiedName.indexOf('.');
  return {
    name: qualifiedName.slice(dot + 1),
    module: qualifiedName.slice(0, dot),
    dataType: 'String',
    hasDefaultValue: false,
    isExposedToClient: false,
    ...extra,
  };
}

/** Index entities/pages/microflows by qualified name, the shape the IR uses. */
export function byQualifiedName(items) {
  return Object.fromEntries(items.map((i) => [i.qualifiedName, i]));
}

/**
 * A guest user role plus the module roles it holds, wired into an IR's security model.
 *
 * Anonymous reachability in the IR is *derived*, not declared, so a test that grants a guest
 * role must also set `isAccessibleAnonymously` on any page it expects to be reachable — the
 * same computation `extract/pages.ts` performs.
 */
export function withGuest(security, heldModuleRoles) {
  return {
    ...security,
    anonymousUserEnabled: true,
    anonymousRole: 'Anonymous',
    userRoles: [
      ...(security.userRoles ?? []),
      userRole('Anonymous', heldModuleRoles, { isAnonymous: true }),
    ],
    moduleRoles: [...(security.moduleRoles ?? []), ...heldModuleRoles.map(moduleRole)],
  };
}
