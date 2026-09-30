/**
 * `SEC-MF-*`: microflow security rules, read from microflow bodies and the model-wide reference index.
 *
 * These need facts the archive parser does not yet extract — microflow activities in execution
 * order (`microflowActivities`) and where each microflow is referenced (`modelReferences`). Where
 * those are NOT_ANALYZABLE the engine records the rule NOT_APPLICABLE, so an analyzer that cannot
 * see inside a microflow never reports it as safe.
 *
 * Interpretations of the governance specification, stated once here and in each rule:
 *
 *   - "CreateAction / ChangeAction / DeleteAction" are Mendix's create-object, change-object and
 *     delete-object activities, under whatever name the source uses for them (normalised by the
 *     extractor: storage writes `CreateChangeAction`, the metamodel `CreateObjectAction`).
 *   - "Execution steps" are activities in the order the sequence flows run them from the start
 *     event; start/end events, annotations and merges are not steps.
 *   - "The Anonymous user module role" is any module role held by the user role selected on App
 *     Security's Anonymous users tab.
 *   - A microflow in a Marketplace module is reported for review one severity lower: the team
 *     cannot edit it, and the fix is usually the role mapping rather than the flow.
 */

import type { Activity, ApplicationIR, Microflow } from '@mendix-analyzer/application-ir';
import type { RuleSeverity } from '@mendix-analyzer/rule-engine';

import { defineRule } from './define-rule.js';
import {
  guestModuleRoles,
  isAdministratorRole,
  isPersistableEntity,
  isPlatformModule,
  isUserModule,
} from './security-facts.js';

const SKILL = 'manage-security.md';

/** Referrers that put a microflow behind a client UI trigger. */
const UI_REFERRERS = new Set(['Page', 'Snippet', 'Layout', 'NavigationDocument', 'BuildingBlock', 'PageTemplate']);

const MUTATIONS = new Set(['CreateAction', 'ChangeAction', 'DeleteAction']);

/** Text that shows a step reading the incoming request's headers or credentials. */
const HEADER_INSPECTION = /httprequest|httpheader|authorization|bearer|api[-_ ]?key|x-api|jwt|token/i;

/** One step lower for a Marketplace microflow, which the team cannot change in place. */
function lower(severity: RuleSeverity): RuleSeverity {
  return severity === 'Critical' ? 'High' : severity === 'High' ? 'Medium' : 'Low';
}

function ownership(ir: ApplicationIR, mf: Microflow, severity: RuleSeverity) {
  const own = isUserModule(ir, mf.module);
  return {
    own,
    status: own ? ('FAIL' as const) : ('WARNING' as const),
    severity: own ? severity : lower(severity),
    suffix: own ? '' : ` The microflow belongs to Marketplace module "${mf.module}" and cannot be changed in place.`,
  };
}

function flows(ir: ApplicationIR): Microflow[] {
  return Object.values(ir.microflows).filter((mf) => !isPlatformModule(ir, mf.module));
}

/** A role counts as administrative when its name says so, or it is a System role. */
function nonAdministrativeRoles(roles: readonly string[]): string[] {
  return roles.filter((qualified) => {
    const dot = qualified.indexOf('.');
    const module = qualified.slice(0, dot);
    const role = qualified.slice(dot + 1);
    return module !== 'System' && !isAdministratorRole(role);
  });
}

function describeStep(a: Activity): string {
  const on = a.targetEntity ?? (a.properties.variable ? `$${a.properties.variable}` : undefined);
  return on ? `${a.type} on ${on}` : a.type;
}

function stepText(a: Activity): string {
  return [a.properties.text, a.properties.expression, a.properties.callee, a.xPathConstraint, a.targetEntity]
    .filter((s) => typeof s === 'string')
    .join(' ');
}

export const microflowSecurityRules = [
  // -------------------------------------------------------------------------------------- 1
  defineRule({
    id: 'SEC-MF-001',
    name: 'Missing entity access on client interactions',
    description:
      'Bypassing entity security checks on microflows interacting directly with the user interface.',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'Critical',
    sourceSkill: SKILL,
    sourceSection: 'Microflow Security',
    expectedPractice:
      'A microflow started from a page, layout or navigation item applies entity access, so it reads and writes only what the calling user is allowed to.',
    recommendation: 'Toggle Apply Entity Access to True in the microflow property panel.',
    whyItMatters:
      'With entity access off, a microflow runs with full data rights no matter who pressed the button. Any non-administrative user who can reach the page can make it read or change records their own access rules would refuse.',
    confidence: 'High',
    requires: ['microflows', 'modelReferences', 'projectSecurity'],
    check: (ir, emit) => {
      for (const mf of flows(ir)) {
        // Condition 1: Apply entity access is off.
        if (mf.appliesEntityAccess !== false) continue;
        // Condition 2: allowed for a non-administrative role.
        const roles = nonAdministrativeRoles(mf.allowedRoles);
        if (roles.length === 0) continue;
        // Condition 3: referenced from a client UI trigger.
        const triggers = (mf.referencedBy ?? []).filter((r) => UI_REFERRERS.has(r.kind));
        if (triggers.length === 0) continue;

        const o = ownership(ir, mf, 'Critical');
        emit({
          key: mf.qualifiedName,
          module: mf.module,
          status: o.status,
          severity: o.severity,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation: `Microflow "${mf.qualifiedName}" does not apply entity access, is allowed for non-administrative role(s) ${roles.join(', ')}, and is triggered from the UI by ${triggers.map((t) => `${t.kind.toLowerCase()} ${t.qualifiedName}`).join(', ')}.${o.suffix}`,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: {
            appliesEntityAccess: false,
            nonAdministrativeRoles: roles,
            uiTriggers: triggers.map((t) => `${t.kind}: ${t.qualifiedName}`),
            unitPath: mf.provenance?.unitPath,
          },
        });
      }
    },
  }),

  // -------------------------------------------------------------------------------------- 2
  defineRule({
    id: 'SEC-MF-002',
    name: 'Anonymous user write permissions',
    description:
      'Allowing unauthenticated internet users to execute microflows that perform database modifications.',
    category: 'Security',
    subcategory: 'Anonymous Access',
    severity: 'Critical',
    sourceSkill: SKILL,
    sourceSection: 'Anonymous Users',
    expectedPractice:
      'Microflows the anonymous user role can call do not create, change or delete stored objects.',
    recommendation:
      'Remove database mutation activities from anonymous microflows. Process input data using non-persistable temporary entities first, then run validation checks before committing records via a secure session.',
    whyItMatters:
      'Anyone on the internet can call a microflow the anonymous role is allowed to run. If it creates, changes or deletes stored objects, unauthenticated visitors can write to the database directly.',
    confidence: 'High',
    requires: ['microflows', 'microflowActivities', 'projectSecurity', 'entityAccessRules'],
    check: (ir, emit) => {
      const anonymous = guestModuleRoles(ir);
      if (anonymous.size === 0) return;

      for (const mf of flows(ir)) {
        // Condition 1: allowed for an anonymous-held module role.
        const via = mf.allowedRoles.filter((r) => anonymous.has(r));
        if (via.length === 0) continue;
        // Conditions 2 and 3: a create/change/delete on a persistable entity. A step whose entity
        // cannot be resolved does not count: condition 3 requires persistable to be established.
        const writes = mf.activities.filter(
          (a) => MUTATIONS.has(a.type) && a.targetEntity !== undefined && isPersistableEntity(ir, a.targetEntity)
        );
        if (writes.length === 0) continue;

        const o = ownership(ir, mf, 'Critical');
        emit({
          key: mf.qualifiedName,
          module: mf.module,
          status: o.status,
          severity: o.severity,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation: `Microflow "${mf.qualifiedName}" is allowed for anonymous-held module role(s) ${via.join(', ')} and modifies stored data: ${writes.map(describeStep).join('; ')}.${o.suffix}`,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: {
            anonymousHeldRoles: via,
            mutations: writes.map(describeStep),
            appliesEntityAccess: mf.appliesEntityAccess ?? null,
            unitPath: mf.provenance?.unitPath,
          },
        });
      }
    },
  }),

  // -------------------------------------------------------------------------------------- 3
  defineRule({
    id: 'SEC-MF-003',
    name: 'Parameter ID tampering vulnerability',
    description:
      'Microflows accepting an entity object directly from the client interface while running in "Sudo Mode".',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'High',
    sourceSkill: 'xpath-constraints.md',
    sourceSection: 'Row-Level Security',
    expectedPractice:
      'A client-callable microflow that changes or deletes an object it received either applies entity access or first checks that the current user may act on that object.',
    recommendation:
      'Turn on Apply Entity Access to let the database filter invalid object manipulation, or add a validation gate checking $Parameter/Owner = $CurrentUser.',
    whyItMatters:
      "The client chooses which object it passes. A microflow running without entity access will change or delete whatever object id it is given, so a user can tamper with the request to act on someone else's record.",
    confidence: 'Medium',
    requires: ['microflows', 'microflowActivities'],
    check: (ir, emit) => {
      for (const mf of flows(ir)) {
        // Condition 1: running without entity access.
        if (mf.appliesEntityAccess !== false) continue;
        // "Directly from the client interface": only a microflow with allowed roles can be
        // called by the client; a sub-microflow receives its parameters from its caller.
        if (mf.allowedRoles.length === 0) continue;

        for (const param of mf.parameters) {
          // Condition 2: an Object or List parameter.
          if (param.type !== 'Object' && param.type !== 'List') continue;
          // Condition 3: a change or delete on that parameter variable.
          const index = mf.activities.findIndex(
            (a) => (a.type === 'ChangeAction' || a.type === 'DeleteAction') && a.properties.variable === param.name
          );
          if (index < 0) continue;
          // Condition 4: no earlier step validating the current user's authority over it — a
          // database retrieve constrained on [%CurrentUser%], or a decision on $currentUser.
          const guarded = mf.activities.slice(0, index).some((a) => {
            if (a.type === 'RetrieveAction' && a.properties.retrieveSource === 'database') {
              return /currentuser/i.test(a.xPathConstraint ?? '');
            }
            return a.type === 'Decision' && /\$currentuser/i.test(String(a.properties.expression ?? ''));
          });
          if (guarded) continue;

          const step = mf.activities[index];
          const o = ownership(ir, mf, 'High');
          emit({
            key: `${mf.qualifiedName}.${param.name}`,
            module: mf.module,
            status: o.status,
            severity: o.severity,
            artifact: `Microflow: ${mf.qualifiedName}`,
            observation: `Microflow "${mf.qualifiedName}" does not apply entity access, receives $${param.name} (${param.type}${param.entity ? ` of ${param.entity}` : ''}) from the client, and runs ${step.type} on it without first checking that the current user owns or may act on that object.${o.suffix}`,
            objectName: mf.name,
            objectType: 'Microflow',
            artifactPath: mf.qualifiedName,
            details: {
              parameter: param.name,
              parameterType: param.type,
              entity: param.entity ?? null,
              mutation: step.type,
              allowedRoles: mf.allowedRoles,
              unitPath: mf.provenance?.unitPath,
            },
          });
        }
      }
    },
  }),

  // -------------------------------------------------------------------------------------- 4
  defineRule({
    id: 'SEC-MF-004',
    name: 'Public endpoint missing auth logic',
    description:
      'Published microflow REST/OData endpoints exposed publicly without any programmatic authorization validation.',
    category: 'Security',
    subcategory: 'Integration Security',
    severity: 'High',
    sourceSkill: 'rest-client.md',
    sourceSection: 'Published REST Services',
    expectedPractice:
      'A published endpoint either requires authentication or verifies the caller (API key, token, JWT) in its first steps.',
    recommendation:
      'Enable system authentication for the published microflow endpoint, or implement custom token verification logic as the very first step in the execution sequence.',
    whyItMatters:
      'An endpoint without authentication runs its microflow for any caller on the internet. If the microflow does not check a credential before it does anything else, every step after it is public.',
    // Header inspection is recognised by pattern (HttpRequest/HttpHeader use, or a Java action
    // named for auth/token/JWT verification), so a custom check under another name can be missed.
    confidence: 'Medium',
    requires: ['publishedServices', 'microflowActivities'],
    check: (ir, emit) => {
      for (const service of ir.integrations.publishedRestServices) {
        for (const endpoint of service.endpoints) {
          // Condition 2: authentication not required.
          if (endpoint.requiresAuthentication) continue;
          // Condition 1: bound to a microflow we can read.
          const mf = ir.microflows[endpoint.microflow];
          if (!mf) continue;
          // Condition 3: neither of the first two steps inspects the request's headers.
          const firstSteps = mf.activities.slice(0, 2);
          if (firstSteps.some((a) => HEADER_INSPECTION.test(stepText(a)))) continue;

          emit({
            key: `${service.name}-${endpoint.name}`,
            module: service.module,
            artifact: `REST endpoint: ${service.name} ${endpoint.httpMethod} ${endpoint.path}`,
            observation: `Published endpoint "${endpoint.httpMethod} ${endpoint.path}" on service "${service.name}" does not require authentication, and the first steps of its microflow "${mf.qualifiedName}" (${firstSteps.map(describeStep).join(', ') || 'none'}) do not inspect the request headers for an API key, token or JWT.`,
            objectName: endpoint.name,
            objectType: 'RestEndpoint',
            artifactPath: mf.qualifiedName,
            details: {
              service: service.name,
              path: endpoint.path,
              microflow: mf.qualifiedName,
              firstSteps: firstSteps.map(describeStep),
            },
          });
        }
      }
    },
  }),

  // -------------------------------------------------------------------------------------- 5
  defineRule({
    id: 'SEC-MF-005',
    name: 'Dead/exposed privilege code',
    description:
      'Microflows with defined user security rights that are no longer actively used or wired up in the model.',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'Medium',
    sourceSkill: SKILL,
    sourceSection: 'Microflow Security',
    expectedPractice: 'Only microflows that something in the model starts carry allowed roles.',
    recommendation:
      'Remove the allowed roles from the microflow properties to render it strictly internal, or delete the dead code entirely from the module.',
    whyItMatters:
      'An unused microflow with allowed roles is still callable from the client by anyone holding those roles. It is attack surface nobody is maintaining, and it is easy to forget when access rules change.',
    confidence: 'Medium',
    requires: ['microflows', 'modelReferences'],
    check: (ir, emit) => {
      for (const mf of flows(ir)) {
        // Condition 1: allowed roles are set.
        if (mf.allowedRoles.length === 0) continue;
        // Marketplace modules ship microflows for optional use; an unused one is their design.
        if (!isUserModule(ir, mf.module)) continue;
        // Condition 2: nothing in the model refers to it.
        if (mf.referencedBy === undefined || mf.referencedBy.length > 0) continue;

        emit({
          key: mf.qualifiedName,
          module: mf.module,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation: `Microflow "${mf.qualifiedName}" is allowed for ${mf.allowedRoles.join(', ')} but nothing in the model refers to it — no page, layout, navigation item, microflow or nanoflow call, entity event, scheduled event, workflow, published service, project setting or Java action.`,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: { allowedRoles: mf.allowedRoles, references: 0, unitPath: mf.provenance?.unitPath },
        });
      }
    },
  }),
];
