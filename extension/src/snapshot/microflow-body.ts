/**
 * A microflow's parameters and activities, in execution order.
 *
 * Mendix stores a microflow as a bag of objects (`ObjectCollection.Objects`) wired together by
 * sequence flows (`Flows`, each with an origin and destination id). Execution order is not stored;
 * it is recovered here by walking the flows from the start event. Objects the walk cannot reach —
 * the bodies of loops, which have their own collection — follow in the order they are found.
 *
 * Activity types are normalised because Studio Pro's untyped API and `.mxunit` storage name some
 * of them differently (a create-object activity is `CreateChangeAction` on disk; the metamodel
 * calls it `CreateObjectAction`). Anything not listed keeps the model's own name, so a rule never
 * mistakes an unfamiliar activity for a familiar one.
 */

import type { Activity, Microflow } from '@mendix-analyzer/application-ir';

import { bool, child, children, isNode, raw, ref, str, typeOf, walk } from './accessors.js';
import type { SnapshotNode } from './types.js';

export interface MicroflowBody {
  parameters: Microflow['parameters'];
  activities: Activity[];
  /** Activity type names the extractor did not recognise, for coverage notes. */
  unknownActions: string[];
  /** The return value expression of each end event that has one. */
  returnValues: string[];
}

const ACTION_KINDS: Record<string, string> = {
  CreateChangeAction: 'CreateAction',
  CreateObjectAction: 'CreateAction',
  ChangeAction: 'ChangeAction',
  ChangeObjectAction: 'ChangeAction',
  DeleteAction: 'DeleteAction',
  CommitAction: 'CommitAction',
  RollbackAction: 'RollbackAction',
  RetrieveAction: 'RetrieveAction',
  MicroflowCallAction: 'MicroflowCall',
  JavaActionCallAction: 'JavaActionCall',
  RestCallAction: 'RestCall',
  CallRestServiceAction: 'RestCall',
  AggregateListAction: 'AggregateList',
  CreateVariableAction: 'CreateVariable',
  ChangeVariableAction: 'ChangeVariable',
  ShowFormAction: 'ShowPage',
  ShowPageAction: 'ShowPage',
  CloseFormAction: 'ClosePage',
  ClosePageAction: 'ClosePage',
  ShowMessageAction: 'ShowMessage',
  ValidationFeedbackAction: 'ValidationFeedback',
  LogMessageAction: 'LogMessage',
  CastAction: 'Cast',
  // Calls to other systems, files and documents (SEC-MF-006).
  RestOperationCallAction: 'RestRequest',
  WebServiceCallAction: 'WebServiceCall',
  AppServiceCallAction: 'AppServiceCall',
  ImportXmlAction: 'ImportMapping',
  ExportXmlAction: 'ExportMapping',
  GenerateDocumentAction: 'GenerateDocument',
  CallExternalAction: 'ExternalAction',
  SendExternalObject: 'SendExternalObject',
  DeleteExternalObject: 'DeleteExternalObject',
  MLModelCallAction: 'MLModelCall',
  WorkflowCallAction: 'WorkflowCall',
};

/** Activities that are not data or logic steps and never count as "an execution step". */
const PASSIVE = new Set(['StartEvent', 'EndEvent', 'ErrorEvent', 'Annotation', 'ContinueEvent', 'BreakEvent', 'ExclusiveMerge']);

const local = (type: string | undefined): string => (type ? type.slice(type.indexOf('$') + 1) : '');

/** Returns `undefined` when the microflow's contents were not read (a shallow copy). */
export function extractMicroflowBody(node: SnapshotNode): MicroflowBody | undefined {
  const collection = child(node, 'ObjectCollection');
  if (!collection) return undefined;

  // ---------------------------------------------------------------- objects, including loop bodies
  const objects: { node: SnapshotNode; loopId?: string }[] = [];
  const visitCollection = (c: SnapshotNode, loopId?: string) => {
    for (const obj of children(c, 'Objects')) {
      objects.push({ node: obj, loopId });
      const inner = child(obj, 'ObjectCollection');
      if (inner) visitCollection(inner, obj.$ID ?? loopId);
    }
  };
  visitCollection(collection);

  // ---------------------------------------------------------------- execution order
  const byId = new Map(objects.filter((o) => o.node.$ID).map((o) => [o.node.$ID!, o]));
  const next = new Map<string, string[]>();
  const errorNext = new Map<string, string[]>();
  const incoming = new Set<string>();
  const flowNodes = [...children(node, 'Flows'), ...objects.flatMap((o) => children(o.node, 'Flows'))];
  for (const flow of flowNodes) {
    const from = pointer(flow, 'OriginPointer', 'Origin');
    const to = pointer(flow, 'DestinationPointer', 'Destination');
    if (!from || !to) continue;
    next.set(from, [...(next.get(from) ?? []), to]);
    if (bool(flow, 'IsErrorHandler') === true) errorNext.set(from, [...(errorNext.get(from) ?? []), to]);
    incoming.add(to);
  }
  const ordered: typeof objects = [];
  const seen = new Set<string>();
  const bfs = (startId: string) => {
    const queue = [startId];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (seen.has(id)) continue;
      seen.add(id);
      const o = byId.get(id);
      if (o) ordered.push(o);
      queue.push(...(next.get(id) ?? []));
    }
  };
  for (const o of objects) if (local(typeOf(o.node)) === 'StartEvent' && o.node.$ID) bfs(o.node.$ID);
  // Loop bodies and anything else unreachable: start from objects nothing flows into.
  for (const o of objects) if (o.node.$ID && !seen.has(o.node.$ID) && !incoming.has(o.node.$ID)) bfs(o.node.$ID);
  for (const o of objects) if (!o.node.$ID || !seen.has(o.node.$ID)) ordered.push(o);

  // ---------------------------------------------------------------- parameters and activities
  const parameters: Microflow['parameters'] = [];
  const variableEntity = new Map<string, string | undefined>();
  const activities: Activity[] = [];
  const unknownActions = new Set<string>();

  const isParameter = (kind: string) => kind === 'MicroflowParameter' || kind === 'MicroflowParameterObject';

  // Parameters are not on any flow, so they are read first: their variables must be known before
  // the activities that change or delete them.
  for (const { node: obj } of objects) {
    if (!isParameter(local(typeOf(obj)))) continue;
    const name = str(obj, 'Name') ?? obj.$Name ?? '';
    const typeNode = child(obj, 'VariableType', 'ParameterType', 'Type');
    const typeKind = local(typeOf(typeNode)).replace(/Type$/, '');
    const entity = ref(typeNode, 'Entity');
    parameters.push({ name, type: typeKind || 'Unknown', entity });
    if (entity) variableEntity.set(name, entity);
  }

  const returnValues: string[] = [];
  for (const { node: obj, loopId } of ordered) {
    const kind = local(typeOf(obj));
    if (kind === 'EndEvent') {
      const value = str(obj, 'ReturnValue')?.trim();
      if (value) returnValues.push(value);
    }
    if (isParameter(kind) || PASSIVE.has(kind)) continue;

    if (kind === 'ActionActivity') {
      const action = child(obj, 'Action');
      const actionKind = local(typeOf(action));
      const type = ACTION_KINDS[actionKind] ?? actionKind;
      if (!ACTION_KINDS[actionKind] && actionKind) unknownActions.add(actionKind);
      const activity = toActivity(obj, action, type, loopId, variableEntity);
      const handling = str(action, 'ErrorHandlingType');
      if (handling) {
        activity.properties.errorHandlingType = handling;
        if (obj.$ID && errorNext.has(obj.$ID)) activity.properties.errorPath = errorPath(obj.$ID, errorNext, next, byId);
      }
      if (bool(obj, 'Disabled') === true) activity.properties.disabled = true;
      // A caption the developer typed, so a finding can name the activity as it reads on the canvas.
      // Generated captions arrive as a placeholder and are left out.
      const caption = str(obj, 'Caption');
      if (bool(obj, 'AutoGenerateCaption') === false && caption) activity.properties.caption = caption;
      activities.push(activity);
      continue;
    }
    if (kind === 'ExclusiveSplit' || kind === 'InheritanceSplit') {
      const condition = child(obj, 'SplitCondition');
      activities.push({
        id: obj.$ID ?? '',
        type: 'Decision',
        name: str(obj, 'Caption') ?? 'Decision',
        isWithinLoop: loopId !== undefined,
        parentLoopId: loopId,
        properties: { expression: str(condition, 'Expression') ?? '', text: textOf(obj) },
      });
      continue;
    }
    if (kind === 'LoopedActivity') {
      // The iterator holds objects of the list's entity.
      const source = child(obj, 'LoopSource');
      const iterator = str(source, 'VariableName', 'LoopVariableName');
      const list = str(source, 'ListVariableName', 'IteratedListVariableName');
      if (iterator && list) variableEntity.set(iterator, variableEntity.get(list));
      activities.push({ id: obj.$ID ?? '', type: 'Loop', name: 'Loop', isWithinLoop: loopId !== undefined, parentLoopId: loopId, properties: {} });
      continue;
    }
    activities.push({ id: obj.$ID ?? '', type: kind, name: kind, isWithinLoop: loopId !== undefined, parentLoopId: loopId, properties: { text: textOf(obj) } });
  }

  return { parameters, activities, unknownActions: [...unknownActions], returnValues };
}

function toActivity(
  obj: SnapshotNode,
  action: SnapshotNode | undefined,
  type: string,
  loopId: string | undefined,
  variableEntity: Map<string, string | undefined>
): Activity {
  const properties: Record<string, unknown> = { text: textOf(action) };
  let targetEntity: string | undefined;
  let xPathConstraint: string | undefined;

  if (type === 'CreateAction' || type === 'ChangeAction') {
    // "Commit": No, Yes or YesWithoutEvents — whether the activity itself stores the object (SEC-005).
    const commit = str(action, 'Commit');
    if (commit) properties.commit = commit;
    // The members the activity sets (SEC-MF-007, SEC-MF-008), and the object variables in scope.
    const members = children(action, 'Items')
      .map((item) => ({ attribute: ref(item, 'Attribute'), association: ref(item, 'Association'), value: str(item, 'Value') }))
      .filter((m) => (m.attribute || m.association) && m.value);
    if (members.length > 0) {
      properties.members = members;
      properties.variables = Object.fromEntries([...variableEntity].filter(([, e]) => e !== undefined));
    }
  }

  switch (type) {
    case 'CreateAction': {
      targetEntity = ref(action, 'Entity');
      const output = str(action, 'VariableName', 'OutputVariableName');
      properties.outputVariable = output;
      if (output) variableEntity.set(output, targetEntity);
      break;
    }
    case 'ChangeAction':
    case 'DeleteAction':
    case 'CommitAction':
    case 'RollbackAction': {
      const variable = str(action, 'ChangeVariableName', 'DeleteVariableName', 'CommitVariableName', 'RollbackVariableName');
      properties.variable = variable;
      targetEntity = variable ? variableEntity.get(variable) : undefined;
      break;
    }
    case 'RetrieveAction': {
      const output = str(action, 'ResultVariableName', 'OutputVariableName');
      const source = child(action, 'RetrieveSource');
      properties.outputVariable = output;
      if (local(typeOf(source)) === 'DatabaseRetrieveSource') {
        properties.retrieveSource = 'database';
        targetEntity = ref(source, 'Entity');
        xPathConstraint = str(source, 'XpathConstraint', 'XPathConstraint') || undefined;
      } else if (source) {
        properties.retrieveSource = 'association';
        properties.startVariable = str(source, 'StartVariableName');
        properties.association = ref(source, 'AssociationId', 'Association');
      }
      if (output) variableEntity.set(output, targetEntity);
      break;
    }
    case 'MicroflowCall': {
      const call = child(action, 'MicroflowCall');
      properties.callee = ref(call, 'Microflow');
      // "Execute this microflow in a task queue": the callee runs in the background.
      if (child(call, 'QueueSettings')) properties.queued = true;
      // The variable the called microflow's result is stored in (SEC-005).
      if (bool(action, 'UseReturnVariable') !== false) properties.outputVariable = str(action, 'OutputVariableName') || undefined;
      break;
    }
    case 'CreateVariable':
      properties.outputVariable = str(action, 'VariableName') || undefined;
      properties.value = str(action, 'InitialValue');
      break;
    case 'ChangeVariable':
      properties.variable = str(action, 'ChangeVariableName') || undefined;
      properties.value = str(action, 'Value');
      break;
    case 'JavaActionCall':
      properties.callee = ref(action, 'JavaAction');
      if (child(action, 'QueueSettings')) properties.queued = true;
      // The variable the action's result is stored in, when "Use return value" is on (SEC-005).
      if (bool(action, 'UseReturnVariable') !== false) properties.outputVariable = str(action, 'OutputVariableName') || undefined;
      break;
    case 'RestCall':
      properties.endpoint = restEndpoint(action);
    // falls through: a REST call can also apply a mapping
    case 'ImportMapping':
    case 'ExportMapping':
      // The mapping the call applies, if any, to name the activity in findings.
      properties.mapping =
        ref(child(child(action, 'ResultHandling'), 'ImportMappingCall'), 'Mapping') ??
        ref(child(action, 'ResultHandling', 'RequestHandling'), 'Mapping');
      break;
    case 'RestRequest':
      properties.callee = ref(action, 'Operation');
      break;
    case 'WebServiceCall': {
      const service = ref(action, 'ImportedWebService') ?? ref(action, 'ServiceName');
      const operation = ref(action, 'OperationName');
      properties.callee = service && operation ? `${service} ▸ ${operation}` : (service ?? operation);
      break;
    }
    case 'ExternalAction': {
      const service = ref(action, 'ConsumedODataService');
      const name = ref(action, 'Name');
      properties.callee = service && name ? `${service} ▸ ${name}` : (service ?? name);
      break;
    }
    case 'GenerateDocument':
      properties.callee = ref(action, 'DocumentTemplate');
      break;
    case 'MLModelCall':
      properties.callee = ref(action, 'MlMappingDocument');
      break;
    case 'WorkflowCall':
      properties.callee = ref(action, 'Workflow');
      break;
  }

  return {
    id: obj.$ID ?? '',
    type,
    name: type,
    isWithinLoop: loopId !== undefined,
    parentLoopId: loopId,
    targetEntity,
    xPathConstraint,
    properties,
  };
}

/** Every string in the element, for pattern checks such as "does this step read HTTP headers?". */
function textOf(node: SnapshotNode | undefined): string {
  if (!node) return '';
  const parts: string[] = [];
  for (const n of walk(node)) {
    for (const v of Object.values(n)) {
      if (typeof v === 'string' && v.length > 0) parts.push(v);
      else if (Array.isArray(v)) for (const item of v) if (typeof item === 'string') parts.push(item);
    }
  }
  return parts.join(' ').slice(0, 4000);
}

/** "GET https://host/path" or "POST $Config/Endpoint" — the method and location a REST call uses. */
function restEndpoint(action: SnapshotNode | undefined): string | undefined {
  const http = child(action, 'HttpConfiguration');
  if (!http) return undefined;
  const method = str(http, 'NewHttpMethod', 'HttpMethod')?.toUpperCase();
  const template = child(http, 'CustomLocationTemplate');
  let location = str(template, 'Text') || str(http, 'CustomLocation') || undefined;
  if (location && template) {
    const args = children(template, 'Arguments').map((a) => str(a, 'Expression') ?? '');
    location = location.replace(/\{(\d+)\}/g, (m, i) => args[Number(i) - 1] || m);
  }
  if (!location) return undefined;
  return method ? `${method} ${location}` : location;
}

/**
 * What the error flow of an activity leads to: whether a Log message activity is on it, and which
 * microflows it calls (one of them may do the logging). The walk follows every flow after the
 * first error flow, so a handler that joins the normal flow again is followed into it.
 */
function errorPath(
  from: string,
  errorNext: Map<string, string[]>,
  next: Map<string, string[]>,
  byId: Map<string, { node: SnapshotNode }>
): { logs: boolean; calls: string[] } {
  const calls: string[] = [];
  let logs = false;
  const seen = new Set<string>();
  const queue = [...(errorNext.get(from) ?? [])];
  while (queue.length > 0) {
    const id = queue.shift()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const obj = byId.get(id)?.node;
    if (!obj) continue;
    const action = child(obj, 'Action');
    const kind = local(typeOf(action));
    if (kind === 'LogMessageAction') logs = true;
    if (kind === 'MicroflowCallAction') {
      const callee = ref(child(action, 'MicroflowCall'), 'Microflow');
      if (callee) calls.push(callee);
    }
    queue.push(...(next.get(id) ?? []));
  }
  return { logs, calls };
}

function pointer(flow: SnapshotNode, ...names: string[]): string | undefined {
  const v = raw(flow, names);
  if (typeof v === 'string' && v.length > 0) return v;
  if (isNode(v)) return v.$ID;
  return undefined;
}
