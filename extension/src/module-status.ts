/**
 * Module-level security status: Studio Pro's Module status grid, with the reasons behind it.
 *
 * Studio Pro reports each module's entity, page, microflow and nanoflow access as "Complete" or
 * "Incomplete". This builds the same per-module view from the IR and says *which* entity has no
 * access rule, *which* page no role can open, *which* callable microflow skips entity access, and
 * what the anonymous user role can reach — so "Incomplete" becomes a list of things to fix.
 *
 * The completeness tests are this analyzer's, stated in `explain` below, not a reimplementation of
 * Studio Pro's consistency checker; where they differ the Studio Pro dialog is authoritative.
 */

import type { AccessRule, ApplicationIR, Entity, ModuleType } from '@mendix-analyzer/application-ir';
import type { Finding, RuleSeverity } from '@mendix-analyzer/rule-engine';
import { guestModuleRoles, isPersistableEntity } from '@mendix-analyzer/rules';

import type { NanoflowAccess } from './snapshot/build-ir.js';

/** `complete`: nothing missing. `incomplete`: something has no access set. `review`: set, but risky. */
export type AccessState = 'complete' | 'incomplete' | 'review' | 'empty';

export interface RoleGrant {
  /** Qualified module role, e.g. `MyFirstModule.User`. */
  role: string;
  /** Human-readable rights, e.g. `create · delete · read 5 · write 2 · XPath`. */
  rights: string;
  anonymous: boolean;
}

export interface EntityRow {
  name: string;
  qualifiedName: string;
  persistable: boolean;
  grants: RoleGrant[];
  anonymous: boolean;
  state: 'ok' | 'no-rules' | 'anonymous';
  /** Why the row has its state, in a sentence. */
  note: string;
}

export interface PageRow {
  name: string;
  qualifiedName: string;
  roles: string[];
  anonymous: boolean;
  dataEntities?: string[];
  state: 'ok' | 'no-roles' | 'anonymous';
  note: string;
}

/** A microflow or nanoflow that calls another one. */
export interface FlowCaller {
  qualifiedName: string;
  kind: 'microflow' | 'nanoflow';
}

export interface FlowRow {
  name: string;
  qualifiedName: string;
  roles: string[];
  anonymous: boolean;
  /**
   * Flows that call this one, i.e. where it is used as a sub-microflow or sub-nanoflow. Empty
   * when nothing calls it; `undefined` when call information was not read.
   */
  calledBy?: FlowCaller[];
  /** Microflows only; `undefined` for nanoflows, which always run with the caller's access. */
  appliesEntityAccess?: boolean;
  state: 'ok' | 'internal' | 'no-entity-access' | 'anonymous';
  note: string;
}

export interface AccessSection<Row> {
  state: AccessState;
  /** One line under the tile, e.g. "7 of 8 entities have access rules". */
  summary: string;
  rows: Row[];
}

export interface ModuleRoleRow {
  qualifiedName: string;
  name: string;
  /** User roles that hold this module role. */
  grantedTo: string[];
  anonymous: boolean;
}

export interface ModuleStatus {
  name: string;
  type: ModuleType;
  findings: Record<RuleSeverity, number> & { total: number };
  roles: ModuleRoleRow[];
  entities: AccessSection<EntityRow>;
  pages: AccessSection<PageRow>;
  microflows: AccessSection<FlowRow>;
  nanoflows: AccessSection<FlowRow>;
  anonymous: { entities: number; pages: number; microflows: number; nanoflows: number; total: number };
  /** The worst state across the sections, for sorting and the card's accent. */
  overall: AccessState;
}

const STATE_RANK: Record<AccessState, number> = { incomplete: 3, review: 2, complete: 1, empty: 0 };

export function buildModuleStatus(
  ir: ApplicationIR,
  nanoflows: readonly NanoflowAccess[],
  findings: readonly Finding[],
  flowReferences?: Readonly<Record<string, readonly string[]>>
): ModuleStatus[] {
  const callers = flowReferences ? callerIndex(ir, nanoflows, flowReferences) : undefined;
  const guestRoles = guestModuleRoles(ir);
  const holders = new Map<string, string[]>();
  for (const userRole of ir.security.userRoles) {
    for (const m of userRole.moduleRoles) {
      const key = `${m.module}.${m.role}`;
      holders.set(key, [...(holders.get(key) ?? []), userRole.name]);
    }
  }

  return Object.values(ir.modules)
    .filter((m) => !m.isSystem)
    .map((module) => {
      const name = module.name;
      const roles = ir.security.moduleRoles
        .filter((r) => r.module === name)
        .map((r) => ({
          qualifiedName: r.qualifiedName,
          name: r.name,
          grantedTo: holders.get(r.qualifiedName) ?? [],
          anonymous: guestRoles.has(r.qualifiedName),
        }));

      const entities = entitySection(ir, Object.values(ir.entities).filter((e) => e.module === name), guestRoles);
      const pages = pageSection(ir, Object.values(ir.pages).filter((p) => p.module === name), guestRoles);
      const microflows = flowSection(
        Object.values(ir.microflows)
          .filter((f) => f.module === name)
          .map((f) => ({ name: f.name, qualifiedName: f.qualifiedName, roles: f.allowedRoles, appliesEntityAccess: f.appliesEntityAccess })),
        guestRoles,
        'microflow',
        callers
      );
      const nanoflowSection = flowSection(
        nanoflows.filter((f) => f.module === name).map((f) => ({ name: f.name, qualifiedName: f.qualifiedName, roles: f.allowedRoles })),
        guestRoles,
        'nanoflow',
        callers
      );

      const own = findings.filter((f) => f.module === name);
      const count = (s: RuleSeverity) => own.filter((f) => f.severity === s).length;

      const anonymous = {
        entities: entities.rows.filter((r) => r.state === 'anonymous').length,
        pages: pages.rows.filter((r) => r.state === 'anonymous').length,
        microflows: microflows.rows.filter((r) => r.anonymous).length,
        nanoflows: nanoflowSection.rows.filter((r) => r.anonymous).length,
        total: 0,
      };
      anonymous.total = anonymous.entities + anonymous.pages + anonymous.microflows + anonymous.nanoflows;

      const sections = [entities, pages, microflows, nanoflowSection];
      const overall = sections.reduce<AccessState>(
        (worst, s) => (STATE_RANK[s.state] > STATE_RANK[worst] ? s.state : worst),
        'empty'
      );

      return {
        name,
        type: module.type,
        findings: {
          Critical: count('Critical'),
          High: count('High'),
          Medium: count('Medium'),
          Low: count('Low'),
          Informational: count('Informational'),
          total: own.length,
        },
        roles,
        entities,
        pages,
        microflows,
        nanoflows: nanoflowSection,
        anonymous,
        overall,
      };
    })
    .sort(
      (a, b) =>
        Number(a.type !== 'user') - Number(b.type !== 'user') ||
        STATE_RANK[b.overall] - STATE_RANK[a.overall] ||
        a.name.localeCompare(b.name)
    );
}

// ------------------------------------------------------------------ entities

function entitySection(ir: ApplicationIR, entities: Entity[], guestRoles: ReadonlySet<string>): AccessSection<EntityRow> {
  const rows: EntityRow[] = entities
    .map((entity) => {
      const persistable = isPersistableEntity(ir, entity.qualifiedName);
      const grants = entity.accessRules.flatMap((rule) =>
        rule.moduleRoles.map((role) => ({ role, rights: describeRights(rule), anonymous: guestRoles.has(role) }))
      );
      const anonymous = grants.some((g) => g.anonymous);
      let state: EntityRow['state'] = 'ok';
      let note = `${grants.length} role grant${grants.length === 1 ? '' : 's'}`;
      if (entity.accessRules.length === 0) {
        state = persistable ? 'no-rules' : 'ok';
        note = persistable
          ? 'No access rules: no role can read or change this data once security is on.'
          : 'Non-persistable with no access rules; fine unless it is used on a page.';
      } else if (anonymous && persistable) {
        state = 'anonymous';
        note = 'The anonymous user role has an access rule on this stored entity.';
      }
      return { name: entity.name, qualifiedName: entity.qualifiedName, persistable, grants, anonymous, state, note };
    })
    .sort((a, b) => rowRank(b.state) - rowRank(a.state) || a.name.localeCompare(b.name));

  const persistable = rows.filter((r) => r.persistable);
  const covered = persistable.filter((r) => r.state !== 'no-rules').length;
  const state: AccessState =
    rows.length === 0
      ? 'empty'
      : rows.some((r) => r.state === 'no-rules')
        ? 'incomplete'
        : rows.some((r) => r.state === 'anonymous')
          ? 'review'
          : 'complete';
  const summary =
    rows.length === 0
      ? 'No entities'
      : `${covered} of ${persistable.length} persistable ${plural(persistable.length, 'entity has', 'entities have')} access rules`;
  return { state, summary, rows };
}

function describeRights(rule: AccessRule): string {
  const parts: string[] = [];
  if (rule.allowCreate) parts.push('create');
  if (rule.allowDelete) parts.push('delete');
  const read = rule.memberAccess.filter((m) => m.access !== 'None').length;
  const write = rule.memberAccess.filter((m) => m.access === 'ReadWrite').length;
  if (rule.defaultMemberAccess !== 'None') parts.push(`${rule.defaultMemberAccess === 'ReadWrite' ? 'write' : 'read'} by default`);
  if (read > 0) parts.push(`read ${read}`);
  if (write > 0) parts.push(`write ${write}`);
  if (rule.xPathConstraint) parts.push('XPath');
  return parts.length > 0 ? parts.join(' · ') : 'no member rights';
}

// ------------------------------------------------------------------ pages

function pageSection(
  ir: ApplicationIR,
  pages: ApplicationIR['pages'][string][],
  guestRoles: ReadonlySet<string>
): AccessSection<PageRow> {
  const rows: PageRow[] = pages
    .map((page) => {
      const anonymous = page.allowedRoles.some((r) => guestRoles.has(r));
      let state: PageRow['state'] = 'ok';
      let note = `${page.allowedRoles.length} allowed role${page.allowedRoles.length === 1 ? '' : 's'}`;
      if (page.allowedRoles.length === 0) {
        state = 'no-roles';
        note = 'No allowed roles: nobody can open this page once security is on.';
      } else if (anonymous) {
        // Judged the way SEC-018 judges it: an anonymous page that works only with
        // non-persistable data (a login page on LoginContext) exposes nothing stored.
        const stored = page.dataEntities?.filter((e) => isPersistableEntity(ir, e));
        if (stored === undefined) {
          state = 'anonymous';
          note = 'Open to the anonymous user role; its contents were not read.';
        } else if (stored.length > 0) {
          state = 'anonymous';
          note = `Open to the anonymous user role and uses stored data: ${stored.join(', ')}.`;
        } else {
          note = page.dataEntities!.length === 0
            ? 'Open to the anonymous user role; uses no entity data, so nothing stored is exposed.'
            : `Open to the anonymous user role; uses only non-persistable ${page.dataEntities!.join(', ')}, so nothing stored is exposed.`;
        }
      }
      return { name: page.name, qualifiedName: page.qualifiedName, roles: page.allowedRoles, anonymous, dataEntities: page.dataEntities, state, note };
    })
    .sort((a, b) => rowRank(b.state) - rowRank(a.state) || a.name.localeCompare(b.name));

  const covered = rows.filter((r) => r.state !== 'no-roles').length;
  const state: AccessState =
    rows.length === 0 ? 'empty' : rows.some((r) => r.state === 'no-roles') ? 'incomplete' : rows.some((r) => r.state === 'anonymous') ? 'review' : 'complete';
  const summary = rows.length === 0 ? 'No pages' : `${covered} of ${rows.length} ${plural(rows.length, 'page has', 'pages have')} allowed roles`;
  return { state, summary, rows };
}

// ------------------------------------------------------------------ flows

interface FlowInput {
  name: string;
  qualifiedName: string;
  roles: string[];
  appliesEntityAccess?: boolean;
}

/**
 * Who calls whom. A flow's references name the flows it calls; a reference to a flow from another
 * flow is counted as a call. That also counts a flow passed as an argument (e.g. to a Java action
 * that runs it), which is still a use of it from logic.
 */
function callerIndex(
  ir: ApplicationIR,
  nanoflows: readonly NanoflowAccess[],
  flowReferences: Readonly<Record<string, readonly string[]>>
): Map<string, FlowCaller[]> {
  const kinds = new Map<string, 'microflow' | 'nanoflow'>();
  for (const name of Object.keys(ir.microflows)) kinds.set(name, 'microflow');
  for (const f of nanoflows) kinds.set(f.qualifiedName, 'nanoflow');

  const index = new Map<string, FlowCaller[]>();
  for (const [caller, references] of Object.entries(flowReferences)) {
    const callerKind = kinds.get(caller);
    if (!callerKind) continue;
    for (const callee of new Set(references)) {
      if (callee === caller || !kinds.has(callee)) continue;
      const list = index.get(callee) ?? [];
      list.push({ qualifiedName: caller, kind: callerKind });
      index.set(callee, list);
    }
  }
  for (const list of index.values()) list.sort((a, b) => a.qualifiedName.localeCompare(b.qualifiedName));
  return index;
}

function describeCallers(callers: readonly FlowCaller[], kind: 'microflow' | 'nanoflow'): string {
  const names = callers.map((c) => `${c.qualifiedName}${c.kind === kind ? '' : ` (${c.kind})`}`);
  return `Used as a sub-${kind} by ${names.join(', ')}.`;
}

function flowSection(
  flows: FlowInput[],
  guestRoles: ReadonlySet<string>,
  kind: 'microflow' | 'nanoflow',
  callers?: ReadonlyMap<string, FlowCaller[]>
): AccessSection<FlowRow> {
  const rows: FlowRow[] = flows
    .map((flow) => {
      const anonymous = flow.roles.some((r) => guestRoles.has(r));
      const calledBy = callers ? callers.get(flow.qualifiedName) ?? [] : undefined;
      let state: FlowRow['state'];
      let note: string;
      if (flow.roles.length === 0) {
        state = 'internal';
        note =
          calledBy === undefined
            ? `No allowed roles: only callable from other ${kind}s, not directly from a page.`
            : calledBy.length > 0
              ? `No allowed roles, so it runs only inside the flows that call it. ${describeCallers(calledBy, kind)}`
              : `No allowed roles and not called by any microflow or nanoflow in the model. It may be unused, or started from outside a flow (scheduled event, after-startup, published service).`;
      } else if (kind === 'microflow' && flow.appliesEntityAccess === false) {
        state = 'no-entity-access';
        note = 'Callable by a role but does not apply entity access, so it reads and writes with full rights.';
      } else if (anonymous) {
        state = 'anonymous';
        note = 'Callable by the anonymous user role.';
      } else {
        state = 'ok';
        note = kind === 'microflow' ? 'Callable by a role and applies entity access.' : 'Callable by a role.';
      }
      if (state !== 'internal' && calledBy && calledBy.length > 0) note += ` ${describeCallers(calledBy, kind)}`;
      return { ...flow, anonymous, calledBy, state, note };
    })
    .sort((a, b) => rowRank(b.state) - rowRank(a.state) || a.name.localeCompare(b.name));

  const callable = rows.filter((r) => r.state !== 'internal').length;
  const state: AccessState =
    rows.length === 0 ? 'empty' : rows.some((r) => r.state === 'no-entity-access' || r.state === 'anonymous') ? 'review' : 'complete';
  const summary =
    rows.length === 0
      ? `No ${kind}s`
      : `${callable} callable by a role · ${rows.length - callable} internal`;
  return { state, summary, rows };
}

// ------------------------------------------------------------------ helpers

function rowRank(state: string): number {
  switch (state) {
    case 'no-rules':
    case 'no-roles':
      return 3;
    case 'anonymous':
    case 'no-entity-access':
      return 2;
    case 'ok':
      return 1;
    default:
      return 0;
  }
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}
