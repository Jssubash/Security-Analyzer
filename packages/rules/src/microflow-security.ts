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

import type { AccessRights, AccessRule, Activity, ApplicationIR, Microflow } from '@mendix-analyzer/application-ir';
import type { RuleSeverity } from '@mendix-analyzer/rule-engine';

import { defineRule } from './define-rule.js';
import {
  dataAccess,
  guestModuleRoles,
  isPersistableEntity,
  isPlatformModule,
  isUserFacingWithoutEntityAccess,
  isUserModule,
  nonAdministrativeRoles,
  stepList,
  uiTriggers,
} from './security-facts.js';
import type { DataAccess } from './security-facts.js';

const SKILL = 'manage-security.md';

const MUTATIONS = new Set(['CreateAction', 'ChangeAction', 'DeleteAction']);

/** Text that shows a step reading the incoming request's headers or credentials. */
const HEADER_INSPECTION = /httprequest|httpheader|authorization|bearer|api[-_ ]?key|x-api|jwt|token/i;

/** One step higher, when the anonymous role can reach the microflow. */
function raise(severity: RuleSeverity): RuleSeverity {
  return severity === 'Low' ? 'Medium' : severity === 'Medium' ? 'High' : 'Critical';
}

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
    name: 'Microflow started from a page runs without entity access',
    description:
      'A microflow that a page, snippet, layout or navigation item starts for a non-administrator role runs with "Apply entity access" off.',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'Critical',
    sourceSkill: SKILL,
    sourceSection: 'Microflow Security',
    expectedPractice:
      'A microflow behind a button, data source or menu item applies entity access, so it reads and changes only what the user who clicked may see and change.',
    recommendation: 'Turn on "Apply entity access" in the microflow properties.',
    whyItMatters:
      'With "Apply entity access" off, the microflow ignores the entity access rules and XPath constraints. Whoever can open the page can make it show or change records their own access rules would hide or refuse — for example every user\'s requests instead of only their own.',
    confidence: 'High',
    requires: ['microflows', 'modelReferences', 'projectSecurity'],
    check: (ir, emit) => {
      const anonymous = guestModuleRoles(ir);
      for (const mf of flows(ir)) {
        // Entity access off, a non-administrative role, and a page or navigation item that starts it.
        if (!isUserFacingWithoutEntityAccess(ir, mf)) continue;
        const roles = nonAdministrativeRoles(mf.allowedRoles);
        const triggers = uiTriggers(mf) ?? [];
        const guestHeld = mf.allowedRoles.filter((r) => anonymous.has(r));

        // Graded by what the microflow itself does with stored data; unread contents keep Critical.
        const data = dataAccess(ir, mf);
        const graded: Record<DataAccess, RuleSeverity> = { writes: 'Critical', reads: 'High', calls: 'Medium', none: 'Low' };
        // One level higher when the anonymous role can run it too, as in SEC-028.
        const severity = data ? (guestHeld.length > 0 ? raise(graded[data.level]) : graded[data.level]) : 'Critical';
        const o = ownership(ir, mf, severity);
        // Reads and writes are the defect; a flow with no data step of its own is a review item.
        const certain = !data || data.level === 'writes' || data.level === 'reads';

        const what = !data
          ? ''
          : data.level === 'writes'
            ? ` It writes stored data (${stepList(data.steps)}) with full rights, so a user can change records their own access rules would refuse.`
            : data.level === 'reads'
              ? ` It reads stored data (${stepList(data.steps)}) with full rights, so a user can see records their own access rules would hide.`
              : data.level === 'calls'
                ? ` It does no data work itself but calls other microflows (${stepList(data.steps)}); check whether those read or write stored data.`
                : ' It touches no stored data, so the setting has no effect today — but any data step added later will run with full rights.';
        const usedBy = triggers.slice(0, 3).map((t) => `${t.kind === 'NavigationDocument' ? 'navigation' : t.kind.toLowerCase()} ${t.qualifiedName}`);

        emit({
          key: mf.qualifiedName,
          module: mf.module,
          status: o.own && certain ? 'FAIL' : 'WARNING',
          severity: o.severity,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation:
            `Microflow "${mf.qualifiedName}" is started from ${usedBy.join(', ')}${triggers.length > 3 ? ` and ${triggers.length - 3} more` : ''} for role(s) ${roles.join(', ')}, and runs with "Apply entity access" off.${what}` +
            (guestHeld.length > 0 ? ` The anonymous role can run it too (through ${guestHeld.join(', ')}), without logging in.` : '') +
            o.suffix,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: {
            appliesEntityAccess: false,
            nonAdministrativeRoles: roles,
            uiTriggers: triggers.map((t) => `${t.kind}: ${t.qualifiedName}`),
            dataAccess: data?.level ?? 'not read',
            dataSteps: data?.steps.slice(0, 10) ?? [],
            guestHeldRoles: guestHeld,
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
    name: 'Microflow trusts the object the browser sends (ID tampering)',
    description:
      'A microflow the browser can call, running with "Apply entity access" off, changes or deletes the object it receives — or copies a helper object\'s values into stored data — without first checking that the user may do so.',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'High',
    sourceSkill: 'xpath-constraints.md',
    sourceSection: 'Row-Level Security',
    expectedPractice:
      'A microflow that changes or deletes an object the browser sent either applies entity access, or first checks that the current user may act on that object (for example a retrieve with [%CurrentUser%] in its XPath).',
    recommendation:
      'Turn on "Apply entity access" so the access rules decide which objects the user may change, or start the microflow with a check that the object belongs to the current user and stop if it does not.',
    whyItMatters:
      "The browser decides which object it sends — and a user can change that object's id in the browser's developer tools. A microflow with entity access off then changes or deletes whatever record it is given, including someone else's. A non-persistable helper object (a form or wizard entity) is only a risk when its values are written into stored data; changing the helper itself touches nothing in the database.",
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
          // Condition 3, by what the parameter holds:
          // - a persistable entity (or one that cannot be established): a change or delete on the
          //   parameter itself, which acts on the stored record the client picked;
          // - a non-persistable entity: only when its values are written into persistable data — a
          //   Change or Create on a persistable entity whose values read from $Parameter. Changing or
          //   deleting the helper object itself touches nothing in the database.
          const persistableParam = !param.entity || isPersistableEntity(ir, param.entity);
          const readsParam = new RegExp(`\\$${param.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_])`);
          const index = persistableParam
            ? mf.activities.findIndex(
                (a) => (a.type === 'ChangeAction' || a.type === 'DeleteAction') && a.properties.variable === param.name
              )
            : mf.activities.findIndex(
                (a) =>
                  (a.type === 'ChangeAction' || a.type === 'CreateAction') &&
                  a.properties.variable !== param.name &&
                  a.targetEntity !== undefined &&
                  isPersistableEntity(ir, a.targetEntity) &&
                  readsParam.test(String(a.properties.text ?? ''))
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

          const step = mf.activities[index]!;
          const o = ownership(ir, mf, 'High');
          const received = `$${param.name} (${param.type}${param.entity ? ` of ${param.entity}` : ''}${persistableParam ? '' : ', non-persistable'})`;
          emit({
            key: `${mf.qualifiedName}.${param.name}`,
            module: mf.module,
            status: o.status,
            severity: o.severity,
            artifact: `Microflow: ${mf.qualifiedName}`,
            observation: persistableParam
              ? `Microflow "${mf.qualifiedName}" does not apply entity access, receives ${received} from the client, and runs ${step.type} on it without first checking that the current user owns or may act on that object.${o.suffix}`
              : `Microflow "${mf.qualifiedName}" does not apply entity access, receives ${received} from the client, and writes its values into persistable ${step.targetEntity} (${step.type}) without first checking that the current user may change that data.${o.suffix}`,
            objectName: mf.name,
            objectType: 'Microflow',
            artifactPath: mf.qualifiedName,
            details: {
              parameter: param.name,
              parameterType: param.type,
              entity: param.entity ?? null,
              mutation: step.type,
              ...(persistableParam ? {} : { writesTo: step.targetEntity ?? null }),
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

  // -------------------------------------------------------------------------------------- 6
  defineRule({
    id: 'SEC-MF-006',
    name: 'Integration call without error handling and logging',
    description:
      'A microflow activity that calls another system or converts external data (REST, web service, OData, import or export mapping, document generation, ML model, workflow, Java action) has no custom error handling, or its error flow does not log the error.',
    category: 'Security',
    subcategory: 'Integration Security',
    severity: 'High',
    sourceSkill: 'error-handling-in-microflows.md',
    sourceSection: 'Error Handling in Microflows',
    expectedPractice:
      'Set the activity\'s error handling to "Custom with rollback" or "Custom without rollback", and place a Log message activity (or a call to a microflow that logs) on the error flow that records $latestError, before any end or error event.',
    recommendation:
      'Right-click the activity ▸ Set error handling… ▸ "Custom with rollback" or "Custom without rollback". Draw the error flow to a Log message activity that writes $latestError/Message and $latestError/Stacktrace (for REST and web services also $latestHttpResponse or $latestSoapFault), then end with an error event, an end event, or a message to the user.',
    whyItMatters:
      'With the default "Rollback", a failing call stops the microflow, undoes its database changes and leaves the user with a general error, while the other system may already have acted — a rollback does not undo an outside call. A custom handler without a log hides the failure completely: nobody can see that a payment, message or import did not go through, or why. Mendix\'s documentation says to always add an error handler to a Call REST service activity and to always log the error message and stack trace in it.',
    confidence: 'High',
    requires: ['microflows', 'microflowActivities'],
    check: (ir, emit) => {
      const background = backgroundMicroflows(ir);
      const logging = new Map<string, boolean>();
      for (const mf of flows(ir)) {
        const own = isUserModule(ir, mf.module);
        const runsInBackground = background.get(mf.qualifiedName);
        const unhandled: string[] = [];
        const unlogged: string[] = [];
        for (const a of mf.activities) {
          const kind = INTEGRATION_CALLS[a.type];
          if (!kind || a.properties.disabled === true) continue;
          // Java actions: every call in your own modules; in Marketplace modules only the calls
          // that run in the background, where no user is present to see an error.
          if (a.type === 'JavaActionCall' && !own && !runsInBackground) continue;
          const handling = a.properties.errorHandlingType;
          // "Continue" is a deliberate choice to carry on past a failure (offered on Java action and
          // microflow calls), so it is not reported.
          if (typeof handling !== 'string' || /^Continue$/i.test(handling)) continue;
          const label = describeCall(a, kind);
          if (!/^Custom/i.test(handling)) {
            unhandled.push(label);
            continue;
          }
          const path = a.properties.errorPath as { logs: boolean; calls: string[] } | undefined;
          const logged = !!path && (path.logs || path.calls.some((c) => logsError(ir, c, logging, 0)));
          if (!logged) unlogged.push(label);
        }
        if (unhandled.length === 0 && unlogged.length === 0) continue;

        const o = ownership(ir, mf, unhandled.length > 0 ? 'High' : 'Medium');
        const parts: string[] = [];
        if (unhandled.length > 0) {
          parts.push(
            `${unhandled.length} ${unhandled.length === 1 ? 'call has' : 'calls have'} no custom error handling (the default "Rollback"): ${callList(unhandled)}.`
          );
        }
        if (unlogged.length > 0) {
          parts.push(
            `${unlogged.length} ${unlogged.length === 1 ? 'call has' : 'calls have'} custom error handling but no Log message on the error flow: ${callList(unlogged)}.`
          );
        }
        const where = runsInBackground ? ` It runs in the background (${runsInBackground}), where no user sees an error.` : '';

        emit({
          key: mf.qualifiedName,
          module: mf.module,
          status: o.status,
          severity: o.severity,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation: `Microflow "${mf.qualifiedName}": ${parts.join(' ')}${where}${o.suffix}`,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: {
            withoutErrorHandling: unhandled,
            withoutLogging: unlogged,
            background: runsInBackground ?? null,
            unitPath: mf.provenance?.unitPath,
          },
        });
      }
    },
  }),

  // -------------------------------------------------------------------------------------- 7
  defineRule({
    id: 'SEC-MF-007',
    name: 'Value converted without an empty check',
    description:
      'A Create object or Change object activity sets a member from an object variable\'s value through a conversion, function or calculation (parseInteger, parseDecimal, parseDateTime, formatDateTime, formatDecimal, toString, getCaption, round, addDays, arithmetic …) without first checking that the value is not empty.',
    category: 'Security',
    subcategory: 'Data Integrity',
    severity: 'Medium',
    sourceSkill: 'expressions.md',
    sourceSection: 'Expressions',
    expectedPractice:
      'Every value that is converted or calculated is checked for empty first — `if $Object/Member != empty then … else …` in the expression, or a Decision before the activity — or, for parse functions, given a default value such as `parseInteger($Object/Member, 0)`.',
    recommendation:
      'Wrap the conversion in an empty check, e.g. `if $Object/Member != empty then parseInteger($Object/Member) else 0`, add a default value to parse functions (`parseInteger($Object/Member, 0)`, `parseDecimal($Object/Member, 0)`, `parseDateTime($Object/Member, \'dd-MM-yyyy\', dateTime(1900))`), or check the value with a Decision before the activity.',
    whyItMatters:
      'A conversion or calculation on an empty value stops the microflow with an error: the user sees a general error, the microflow\'s changes are rolled back and, in the background, the job stops halfway. Mendix\'s documentation says parseInteger, parseDecimal and parseDateTime raise an error when the text cannot be parsed and no default value is given, and that reading or calculating with an empty value makes the expression invalid. Copying a value of the same type (String to String) is not affected and not reported.',
    confidence: 'Medium',
    requires: ['microflows', 'microflowActivities'],
    check: (ir, emit) => {
      const background = backgroundMicroflows(ir);
      for (const mf of flows(ir)) {
        const issues: { activityId: string; activity: string; member: string; expression: string; problem: string; short: string }[] = [];
        const checked = new Set<string>();
        for (const a of mf.activities) {
          // A Decision that tests a value for empty protects it for the activities after it.
          if (a.type === 'Decision') for (const p of emptyChecks(String(a.properties.expression ?? ''))) checked.add(p);
          if ((a.type !== 'CreateAction' && a.type !== 'ChangeAction') || a.properties.disabled === true) continue;
          const members = a.properties.members as Member[] | undefined;
          const variables = (a.properties.variables ?? {}) as Record<string, string>;
          for (const m of members ?? []) {
            // An association is set to an object, which needs no conversion.
            if (!m.attribute) continue;
            const risks = unsafeConversions(ir, m.value, variables, checked);
            if (risks.length === 0) continue;
            issues.push({
              activityId: a.id,
              activity: a.type === 'CreateAction' ? 'Create object' : 'Change object',
              member: m.attribute,
              expression: oneLine(m.value),
              problem: risks.join('; '),
              // "toString", "parseInteger", "calculation" — for the one-line summary.
              short: [...new Set(risks.map((r) => (r.startsWith('calculation') ? 'calculation' : r.slice(0, r.indexOf('(')))))].join(', '),
            });
          }
        }
        if (issues.length === 0) continue;

        const runsInBackground = background.get(mf.qualifiedName);
        const o = ownership(ir, mf, runsInBackground ? 'High' : 'Medium');
        const where = runsInBackground ? ` It runs in the background (${runsInBackground}), where an error stops the job without anyone seeing it.` : '';
        emit({
          key: mf.qualifiedName,
          module: mf.module,
          status: o.status,
          severity: o.severity,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation: `Microflow "${mf.qualifiedName}": ${issues.length} ${issues.length === 1 ? 'value is' : 'values are'} converted or calculated without an empty check, so an empty value stops the microflow with an error: ${issues.map((i) => `${i.activity} → ${i.member} (${i.short})`).join('; ')}. The evidence shows each expression.${where}${o.suffix}`,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: {
            // activityId lets the pane open the microflow with this activity selected.
            conversions: issues.map(({ activityId, activity, member, expression, problem }) => ({ activity, member, expression, problem, activityId })),
            background: runsInBackground ?? null,
            unitPath: mf.provenance?.unitPath,
          },
        });
      }
    },
  }),

  // -------------------------------------------------------------------------------------- 8
  defineRule({
    id: 'SEC-MF-008',
    name: 'Role can run the microflow but lacks the entity access its activities need',
    description:
      'A microflow with "Apply entity access" on is allowed for a module role whose entity access rules do not give the rights its activities need: create, change (write on each member it sets), delete, or read for a retrieve. Sub-microflows it calls are checked with the same module roles.',
    category: 'Security',
    subcategory: 'Microflow Security',
    severity: 'Critical',
    sourceSkill: SKILL,
    sourceSection: 'Microflow Security',
    expectedPractice:
      'Every module role allowed to run a microflow that applies entity access has, in the entity access rules, the create, write, delete and read rights the microflow\'s activities use — or is not allowed to run it.',
    recommendation:
      'Either remove the module role from the microflow\'s allowed roles (and hide the buttons that start it for that role), or give the module role the missing rights in the entity\'s access rules (Domain model ▸ entity ▸ Access rules ▸ Access rights: "Create objects", "Delete objects", Read/Write on the member).',
    whyItMatters:
      'With "Apply entity access" on, Mendix checks the user\'s access rules at every step. When the role may start the microflow but may not create, change or delete what it touches, the user clicks Save and gets "An error occurred, please contact your system administrator", and the work is rolled back. A retrieve without read access returns nothing for that role, so the microflow silently works on empty data.',
    confidence: 'High',
    requires: ['microflows', 'microflowActivities', 'entityAccessRules', 'projectSecurity', 'moduleRoles'],
    check: (ir, emit) => {
      // Who runs each microflow: the module roles allowed on it, and the module roles of every
      // microflow that calls it (a sub-microflow runs with the caller's user).
      const runners = new Map<string, Map<string, string>>();
      const addRunner = (name: string, moduleRole: string, via: string) => {
        const byRole = runners.get(name) ?? new Map<string, string>();
        if (!byRole.has(moduleRole)) byRole.set(moduleRole, via);
        runners.set(name, byRole);
      };
      for (const mf of flows(ir)) {
        if (mf.allowedRoles.length === 0) continue;
        const seen = new Set<string>();
        const visit = (name: string, depth: number, via: string) => {
          if (seen.has(name) || depth > 10) return;
          seen.add(name);
          const flow = ir.microflows[name];
          if (!flow) return;
          for (const role of mf.allowedRoles) addRunner(name, role, via);
          for (const a of flow.activities) {
            // A task-queue call does not run in the user's own session, so it is not followed.
            if (a.type !== 'MicroflowCall' || a.properties.queued === true || typeof a.properties.callee !== 'string') continue;
            visit(a.properties.callee, depth + 1, depth === 0 ? `called from ${name}` : via);
          }
        };
        visit(mf.qualifiedName, 0, '');
      }

      for (const mf of flows(ir)) {
        if (mf.appliesEntityAccess !== true) continue;
        const byRole = runners.get(mf.qualifiedName);
        if (!byRole || byRole.size === 0) continue;

        const problems: string[] = [];
        let blocking = false;
        const vias = new Set<string>();
        for (const [moduleRole, via] of byRole) {
          const holders = userRolesHolding(ir, [moduleRole]);
          // Every holder has security checks off: entity access is never applied for them.
          if (holders.length > 0 && holders.every((u) => u.checkSecurity === false)) continue;
          const held = rightsOf(moduleRole, holders);
          const missing: string[] = [];
          for (const a of mf.activities) {
            if (a.properties.disabled === true) continue;
            const result = missingRights(ir, a, held);
            if (!result) continue;
            missing.push(result.text);
            if (result.blocking) blocking = true;
          }
          if (missing.length === 0) continue;
          const users = holders.length > 0 ? ` (user role${holders.length === 1 ? '' : 's'} ${holders.map((u) => u.name).join(', ')})` : '';
          problems.push(`module role ${moduleRole}${users} cannot ${[...new Set(missing)].join('; ')}`);
          if (via) vias.add(via);
        }
        if (problems.length === 0) continue;

        const o = ownership(ir, mf, blocking ? 'Critical' : 'Medium');
        const caller = vias.size > 0 ? ` It runs with the roles of its caller (${[...vias].slice(0, 3).join(', ')}).` : '';
        emit({
          key: mf.qualifiedName,
          module: mf.module,
          status: o.status,
          severity: o.severity,
          artifact: `Microflow: ${mf.qualifiedName}`,
          observation:
            `Microflow "${mf.qualifiedName}" applies entity access, but a module role allowed to run it lacks the access its activities need: ${problems.join('. ')}.${caller}` +
            (blocking ? ' Users with that role get an error when the microflow runs, and the work is rolled back.' : ' The retrieve returns nothing for users with that role.') +
            o.suffix,
          objectName: mf.name,
          objectType: 'Microflow',
          artifactPath: mf.qualifiedName,
          details: { moduleRoles: [...byRole.keys()], problems, unitPath: mf.provenance?.unitPath },
        });
      }
    },
  }),
];

/** Activities that call another system or convert external data, with the name a finding uses. */
const INTEGRATION_CALLS: Record<string, string> = {
  RestCall: 'Call REST service',
  RestRequest: 'Send REST request',
  WebServiceCall: 'Call web service',
  AppServiceCall: 'Call app service',
  ExternalAction: 'Call external action',
  SendExternalObject: 'Send external object',
  DeleteExternalObject: 'Delete external object',
  ImportMapping: 'Import with mapping',
  ExportMapping: 'Export with mapping',
  GenerateDocument: 'Generate document',
  MLModelCall: 'Call ML model',
  WorkflowCall: 'Call workflow',
  JavaActionCall: 'Java action',
};

/**
 * How a finding names an activity: its type, the caption the developer gave it (if any), and what it
 * calls — e.g. `Call REST service "Get orders" (GET $Config/Url, mapping Module.ImportOrders)`.
 * The type comes from the activity itself, so renaming an activity never changes whether it is checked.
 */
function describeCall(a: Activity, kind: string): string {
  const text = (v: unknown) => (typeof v === 'string' && v ? v : undefined);
  const { caption, callee, endpoint, mapping } = a.properties;
  const isMapping = a.type === 'ImportMapping' || a.type === 'ExportMapping';
  const target = text(callee) ?? (isMapping ? text(mapping) : undefined);
  const extra = [text(endpoint), !isMapping && text(mapping) ? `mapping ${mapping}` : undefined].filter(Boolean).join(', ');
  return [kind, text(caption) ? `"${caption}"` : undefined, target, extra ? `(${extra})` : undefined].filter(Boolean).join(' ');
}

/** Every activity, in order, with a count for repeats: "Java action A (2 times), Call REST service". */
function callList(labels: string[]): string {
  const counts = new Map<string, number>();
  for (const l of labels) counts.set(l, (counts.get(l) ?? 0) + 1);
  return [...counts].map(([l, n]) => (n > 1 ? `${l} (${n} times)` : l)).join('; ');
}

/** Whether a microflow, or one it calls, has a Log message activity. */
function logsError(ir: ApplicationIR, name: string, cache: Map<string, boolean>, depth: number): boolean {
  const cached = cache.get(name);
  if (cached !== undefined) return cached;
  const mf = ir.microflows[name];
  if (!mf || depth > 5) return false;
  cache.set(name, false);
  const result = mf.activities.some(
    (a) =>
      a.type === 'LogMessage' ||
      (a.type === 'MicroflowCall' && typeof a.properties.callee === 'string' && logsError(ir, a.properties.callee, cache, depth + 1))
  );
  cache.set(name, result);
  return result;
}

/** Referrers whose microflows run without a user waiting for them. */
const BACKGROUND_REFERRERS: Record<string, string> = {
  ScheduledEvent: 'scheduled event',
  Workflow: 'workflow',
};

/**
 * Microflows that run in the background, with how: started by a scheduled event or a workflow,
 * called with "Execute this microflow in a task queue", or called (at any depth) from one of those.
 */
function backgroundMicroflows(ir: ApplicationIR): Map<string, string> {
  const result = new Map<string, string>();
  /** Each microflow's entry point: the microflow the background run starts in, and how it starts. */
  const entry = new Map<string, string>();
  const queue: string[] = [];
  const mark = (name: string, how: string, from?: string) => {
    if (result.has(name) || !ir.microflows[name]) return;
    const root = from ? entry.get(from)! : name;
    entry.set(name, root);
    result.set(name, from ? `called from ${root}, ${result.get(root)}` : how);
    queue.push(name);
  };
  for (const mf of Object.values(ir.microflows)) {
    for (const r of mf.referencedBy ?? []) {
      const kind = BACKGROUND_REFERRERS[r.kind];
      if (kind) mark(mf.qualifiedName, `started by ${kind} ${r.qualifiedName}`);
    }
    for (const a of mf.activities) {
      if (a.type === 'MicroflowCall' && a.properties.queued === true && typeof a.properties.callee === 'string') {
        mark(a.properties.callee, `called in a task queue from ${mf.qualifiedName}`);
      }
    }
  }
  while (queue.length > 0) {
    const name = queue.shift()!;
    for (const a of ir.microflows[name].activities) {
      if (a.type === 'MicroflowCall' && typeof a.properties.callee === 'string') mark(a.properties.callee, '', name);
    }
  }
  return result;
}

// ------------------------------------------------------------------ SEC-MF-007: expression checks

/** Parse functions: they fail on empty or unparsable text unless given a default value. */
const PARSE_FUNCTIONS = new Set(['parseinteger', 'parselong', 'parsedecimal', 'parsedatetime', 'parsedatetimeutc']);

/** Functions that fail, or convert, when given an empty value (Mendix expression functions). */
const VALUE_FUNCTIONS = new Set([
  ...PARSE_FUNCTIONS,
  'tostring',
  'formatdatetime', 'formatdatetimeutc', 'formatdate', 'formatdateutc', 'formattime', 'formattimeutc', 'formatdecimal',
  'datetimetoepoch', 'epochtodatetime', 'getcaption', 'getkey',
  'round', 'floor', 'ceil', 'abs', 'pow', 'sqrt', 'max', 'min',
]);

/** Date functions (addDays, betweenHours, beginOfMonth, trimToDays …): an empty date makes them fail. */
const DATE_FUNCTION = /^(add|subtract|between|beginof|endof|trimto)[a-z]+$/;

/** An attribute path read from an object variable: `$Order/Total`, `$Order/Module.Order_Customer/Module.Customer/Name`. */
const VALUE_PATH = /\$[A-Za-z_]\w*(?:\/[A-Za-z_][\w.]*)+/g;

/** Numeric attribute types, where `+` is a calculation rather than joining text. */
const NUMERIC = /^(Integer|Long|Decimal|AutoNumber|Float|Currency)/i;

/** String literals blanked out, so a format such as 'dd-MM-yyyy' is not read as an operator. */
function withoutLiterals(expression: string): string {
  return expression.replace(/'(?:[^']|'')*'/g, "''");
}

/** The paths an expression tests for empty: `$X/A != empty`, `$X/A = empty`, `empty != $X/A`. */
function emptyChecks(expression: string): string[] {
  const text = withoutLiterals(expression);
  const found: string[] = [];
  for (const m of text.matchAll(/(\$[A-Za-z_]\w*(?:\/[A-Za-z_][\w.]*)*)\s*!?=\s*empty\b/g)) found.push(m[1]);
  for (const m of text.matchAll(/\bempty\s*!?=\s*(\$[A-Za-z_]\w*(?:\/[A-Za-z_][\w.]*)*)/g)) found.push(m[1]);
  return found;
}

/** The arguments of the call whose opening parenthesis is at `open`, split at top-level commas. */
function callArguments(text: string, open: number): string[] {
  const args: string[] = [];
  let depth = 0;
  let start = open + 1;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) {
        args.push(text.slice(start, i));
        const trimmed = args.map((a) => a.trim());
        return trimmed.length === 1 && trimmed[0] === '' ? [] : trimmed;
      }
    } else if (c === ',' && depth === 1) {
      args.push(text.slice(start, i));
      start = i + 1;
    }
  }
  return [];
}

/** Whether a parse call carries a default value, which it returns instead of failing. */
function hasDefault(fn: string, args: string[]): boolean {
  if (fn === 'parseinteger' || fn === 'parselong') return args.length >= 2;
  if (fn === 'parsedatetime' || fn === 'parsedatetimeutc') return args.length >= 3;
  // parseDecimal(value, default) or parseDecimal(value, 'format', default).
  if (fn === 'parsedecimal') return args.length >= 3 || (args.length === 2 && args[1] !== "''");
  return false;
}

/** The type of the attribute a path ends on, following generalizations; `undefined` when unknown. */
function pathType(ir: ApplicationIR, path: string, variables: Record<string, string>): string | undefined {
  const parts = path.slice(1).split('/');
  const entityName = parts.length === 2 ? variables[parts[0]] : parts[parts.length - 2];
  const attribute = parts[parts.length - 1];
  let entity = entityName ? ir.entities[entityName] : undefined;
  for (let depth = 0; entity && depth < 10; depth++) {
    const found = entity.attributes.find((a) => a.name === attribute);
    if (found) return found.type;
    entity = entity.generalization ? ir.entities[entity.generalization] : undefined;
  }
  return undefined;
}

/**
 * Each conversion or calculation in a member's expression that reads a value nobody checked for
 * empty, described for the finding, e.g. "parseInteger($Object/Member) without a default value".
 */
function unsafeConversions(ir: ApplicationIR, expression: string, variables: Record<string, string>, checkedBefore: Set<string>): string[] {
  const text = withoutLiterals(expression);
  const checked = new Set([...checkedBefore, ...emptyChecks(expression)]);
  const risks: string[] = [];
  const reported = new Set<string>();

  // Innermost calls first, so a value is blamed on the function that reads it directly:
  // in parseDateTime(formatDateTime($X/Date)) the formatDateTime is what fails on an empty date.
  const calls = [...text.matchAll(/\b([A-Za-z]\w*)\s*\(/g)].reverse();
  for (const call of calls) {
    const fn = call[1].toLowerCase();
    if (!VALUE_FUNCTIONS.has(fn) && !DATE_FUNCTION.test(fn)) continue;
    const args = callArguments(text, call.index! + call[0].length - 1);
    // A parse function's default value covers its input, also for the functions around it.
    if (PARSE_FUNCTIONS.has(fn) && hasDefault(fn, args)) {
      for (const p of args[0]?.match(VALUE_PATH) ?? []) reported.add(p);
      continue;
    }
    const inputs = PARSE_FUNCTIONS.has(fn) ? args.slice(0, 1) : args;
    for (const input of inputs) {
      for (const p of input.match(VALUE_PATH) ?? []) {
        if (checked.has(p) || reported.has(p)) continue;
        reported.add(p);
        risks.push(PARSE_FUNCTIONS.has(fn) ? `${call[1]}(${p}) without a default value or empty check` : `${call[1]}(${p}) without an empty check`);
      }
    }
  }

  // Calculations: a value next to * : div mod or -, or next to + when the value is a number.
  for (const m of text.matchAll(VALUE_PATH)) {
    const p = m[0];
    if (checked.has(p) || reported.has(p)) continue;
    const before = text.slice(0, m.index).trimEnd();
    const after = text.slice(m.index! + p.length).trimStart();
    const op = /(\*|:|-|\+|\bdiv|\bmod)$/.exec(before)?.[1] ?? /^(\*|:|-|\+|div\b|mod\b)/.exec(after)?.[1];
    if (!op) continue;
    if (op === '+' && !NUMERIC.test(pathType(ir, p, variables) ?? '')) continue;
    reported.add(p);
    risks.push(`calculation with ${p} without an empty check`);
  }
  return risks;
}

function oneLine(expression: string): string {
  const flat = expression.replace(/\s+/g, ' ').trim();
  return flat.length > 160 ? `${flat.slice(0, 157)}…` : flat;
}

// ------------------------------------------------------------------ SEC-MF-008: entity access per role

/** A member a Create or Change object activity sets. */
interface Member {
  attribute?: string;
  association?: string;
  value: string;
}

/** User roles holding at least one of the given `Module.Role` names. */
function userRolesHolding(ir: ApplicationIR, moduleRoles: string[]) {
  const wanted = new Set(moduleRoles);
  return ir.security.userRoles.filter((u) => u.moduleRoles.some((r) => wanted.has(`${r.module}.${r.role}`)));
}

/**
 * The module roles whose access rules count for a module role allowed on a microflow.
 *
 * In its own module only the role itself counts: the access rules given to that module role are
 * what the developer designed for it, and another role of the same module that a user role
 * happens to combine with it must not hide a gap. A module role cannot have access rules on
 * another module's entities, so there the roles of other modules count that every user role
 * holding it also holds — what each of those users is guaranteed to have.
 */
function rightsOf(moduleRole: string, holders: ApplicationIR['security']['userRoles']): Set<string> {
  const ownModule = moduleRole.slice(0, moduleRole.indexOf('.'));
  const held = new Set([moduleRole]);
  if (holders.length === 0) return held;
  const sets = holders.map((u) => new Set(u.moduleRoles.filter((r) => r.module !== ownModule).map((r) => `${r.module}.${r.role}`)));
  for (const role of sets[0]) if (sets.every((s) => s.has(role))) held.add(role);
  return held;
}

/** The access rules on an entity and its generalizations that apply to any of the held module roles. */
function applicableRules(ir: ApplicationIR, entityName: string, held: Set<string>): AccessRule[] | undefined {
  let entity: ApplicationIR['entities'][string] | undefined = ir.entities[entityName];
  if (!entity) return undefined;
  const rules: AccessRule[] = [];
  for (let depth = 0; entity && depth < 10; depth++) {
    rules.push(...entity.accessRules.filter((r) => r.moduleRoles.some((m) => held.has(m))));
    entity = entity.generalization ? ir.entities[entity.generalization] : undefined;
  }
  return rules;
}

const shortName = (qualified: string) => qualified.slice(qualified.lastIndexOf('.') + 1);

/**
 * The best access the rules give on one member, from each rule's access rights (an XPath
 * constraint on the rule does not change them). `undefined` when no rule mentions an
 * association, whose access may be set on the entity at its other end.
 */
function memberAccess(rules: AccessRule[], member: string, isAssociation: boolean): AccessRights | undefined {
  let best: AccessRights | undefined;
  const rank = { None: 0, ReadOnly: 1, ReadWrite: 2 } as const;
  for (const rule of rules) {
    const entry = rule.memberAccess.find((m) => m.attributeOrAssociation === member || shortName(m.attributeOrAssociation) === shortName(member));
    const access = entry?.access ?? (isAssociation ? undefined : rule.defaultMemberAccess);
    if (access && (!best || rank[access] > rank[best])) best = access;
  }
  // An attribute no rule grants has no access; an association may be granted elsewhere.
  return best ?? (isAssociation ? undefined : 'None');
}

/**
 * What a module role holding `held` cannot do in one activity, or `undefined` when its access
 * rights cover everything the activity needs. Only the access rights count — "Create objects",
 * "Delete objects" and Read/Write per member — whether or not the rule has an XPath constraint.
 * `blocking` is true when the activity fails with an error (create, change, delete).
 */
function missingRights(ir: ApplicationIR, a: Activity, held: Set<string>): { text: string; blocking: boolean } | undefined {
  const entityName = a.targetEntity;
  // Non-persistable objects: the runtime does not hold a microflow to their create, delete and
  // write rights (Mendix's own Administration module creates them without those rights).
  if (!entityName || !isPersistableEntity(ir, entityName)) return undefined;

  if (a.type === 'RetrieveAction') {
    if (a.properties.retrieveSource !== 'database') return undefined;
    const rules = applicableRules(ir, entityName, held);
    if (!rules || rules.length > 0) return undefined;
    return { text: `retrieve ${entityName} (no access rule, so the retrieve returns nothing)`, blocking: false };
  }

  if (a.type !== 'CreateAction' && a.type !== 'ChangeAction' && a.type !== 'DeleteAction') return undefined;
  const rules = applicableRules(ir, entityName, held);
  if (!rules) return undefined;
  if (rules.length === 0) {
    const verb = a.type === 'CreateAction' ? 'create' : a.type === 'ChangeAction' ? 'change' : 'delete';
    return { text: `${verb} ${entityName} (no access rule for this role)`, blocking: true };
  }

  const gaps: string[] = [];
  if (a.type === 'CreateAction' && !rules.some((r) => r.allowCreate)) {
    gaps.push(`create ${entityName} ("Create objects" is off)`);
  }
  if (a.type === 'DeleteAction' && !rules.some((r) => r.allowDelete)) {
    gaps.push(`delete ${entityName} ("Delete objects" is off)`);
  }
  if (a.type === 'CreateAction' || a.type === 'ChangeAction') {
    for (const m of (a.properties.members as Member[] | undefined) ?? []) {
      const member = m.attribute ?? m.association;
      if (!member) continue;
      const access = memberAccess(rules, member, !m.attribute);
      if (access === undefined || access === 'ReadWrite') continue;
      gaps.push(`write ${member} (${access === 'ReadOnly' ? 'read only' : 'no access'})`);
    }
  }
  return gaps.length > 0 ? { text: gaps.join('; '), blocking: true } : undefined;
}
