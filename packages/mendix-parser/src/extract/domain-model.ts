/**
 * Extract entities, attributes, access rules and associations from
 * `DomainModels$DomainModel` units.
 *
 * This replaces the old parser's reconstruction of the domain model from generated Java
 * proxy classes (`mpr-parser.ts:218-267`), which produced 72 "entities" for a project that
 * actually defines 8, invented an attribute type for each one, and hardcoded
 * `hasAccessRules: true` so that every entity appeared to be protected.
 *
 * Access rules are the part that matters most for Phase 1, and they are only recoverable
 * from a tree: a rule's `AllowedModuleRoles`, its `XPathConstraint` and its per-member
 * `AccessRights` are meaningful solely in relation to the rule that contains them and the
 * entity that contains that. A flat scan for tag bytes cannot reassemble them.
 */

import type {
  AccessRights,
  AccessRule,
  Association,
  AssociationType,
  Attribute,
  DeleteBehavior,
  Entity,
  IndexItem,
  MemberAccessRule,
  PersistenceType,
} from '@mendix-analyzer/application-ir';
import { classifySensitivity } from '@mendix-analyzer/application-ir';

import {
  bool,
  docArray,
  elementId,
  elementType,
  formatGuid,
  num,
  str,
  strArray,
  subDoc,
} from '../bson/accessors.js';
import type { BsonDocument } from '../bson/reader.js';
import type { ModelGraph } from '../model/model-graph.js';
import { analyzed, notAnalyzable } from './types.js';
import type { Extraction } from './types.js';

const DOMAIN_MODEL_TYPE = 'DomainModels$DomainModel';

const ACCESS_RIGHTS: readonly AccessRights[] = ['None', 'ReadOnly', 'ReadWrite'];
const ASSOCIATION_TYPES: readonly AssociationType[] = ['Reference', 'ReferenceSet'];
const DELETE_BEHAVIORS: readonly DeleteBehavior[] = [
  'DeleteBoth',
  'DeleteParentOnly',
  'DeleteChildOnly',
  'DeleteNever',
];

export interface DomainModelExtraction {
  entities: Extraction<Record<string, Entity>>;
  associations: Extraction<Association[]>;
  /** Whether real attribute types were readable; sensitivity rules depend on this. */
  attributeTypes: Extraction<null>;
  /** Whether access rules were readable at all. */
  accessRules: Extraction<null>;
}

export function extractDomainModel(graph: ModelGraph): DomainModelExtraction {
  const refs = graph.units.refsOfType(DOMAIN_MODEL_TYPE);
  if (refs.length === 0) {
    const reason = `no ${DOMAIN_MODEL_TYPE} unit was found, so no entity could be read`;
    return {
      entities: notAnalyzable({}, reason),
      associations: notAnalyzable([], reason),
      attributeTypes: notAnalyzable(null, reason),
      accessRules: notAnalyzable(null, reason),
    };
  }

  const entities: Record<string, Entity> = {};
  const associations: Association[] = [];
  const notes: string[] = [];
  const typeNotes: string[] = [];
  const ruleNotes: string[] = [];
  /** Entity `$ID` → qualified name, so association endpoints can be resolved. */
  const entityNameById = new Map<string, string>();
  /**
   * Associations are resolved only after every module has been read. A cross-module
   * association names an entity that may live in a module not yet visited, so resolving
   * eagerly would make an endpoint's readability depend on unit iteration order.
   */
  const pendingAssociations: { raw: BsonDocument; moduleName: string }[] = [];

  for (const { tree, ref } of graph.units.unitsOfType(DOMAIN_MODEL_TYPE)) {
    const owner = graph.moduleOf(ref);
    if (!owner) {
      notes.push(`the module owning ${ref.unitPath} could not be resolved; its entities were skipped`);
      continue;
    }

    for (const raw of docArray(tree, 'Entities')) {
      const name = str(raw, 'Name');
      if (!name) {
        notes.push(`an unnamed entity in ${owner.name} was skipped`);
        continue;
      }
      const qualifiedName = `${owner.name}.${name}`;
      const id = elementId(raw);
      if (id) entityNameById.set(id, qualifiedName);

      const generalization = subDoc(raw, 'MaybeGeneralization');
      const entity: Entity = {
        name,
        module: owner.name,
        qualifiedName,
        persistenceType: persistenceOf(generalization),
        generalization: str(generalization, 'Generalization') || undefined,
        specializations: [], // filled in after every entity is known
        attributes: docArray(raw, 'Attributes').map((a) =>
          toAttribute(a, qualifiedName, typeNotes)
        ),
        indexes: docArray(raw, 'Indexes').map(toIndex),
        accessRules: docArray(raw, 'AccessRules').map((r, i) =>
          toAccessRule(r, qualifiedName, i, ref.unitPath, ruleNotes)
        ),
        isSecurityConfigured: docArray(raw, 'AccessRules').length > 0,
        hasOwnerAttribute: bool(generalization, 'HasOwnerAttr'),
        hasChangedByAttribute: bool(generalization, 'HasChangedByAttr'),
        documentation: str(raw, 'Documentation') || undefined,
        provenance: { unitPath: ref.unitPath, elementId: id },
      };
      entities[qualifiedName] = entity;
    }

    // `Associations` holds associations whose two ends live in this module;
    // `CrossAssociations` holds those pointing at an entity in another module. Reading only
    // the first would report a project whose modules are wired together as having no
    // dependencies at all.
    for (const key of ['Associations', 'CrossAssociations'] as const) {
      for (const raw of docArray(tree, key)) {
        pendingAssociations.push({ raw, moduleName: owner.name });
      }
    }
  }

  for (const { raw, moduleName } of pendingAssociations) {
    const association = toAssociation(raw, moduleName, entityNameById, notes);
    if (association) associations.push(association);
  }

  // Specializations are the inverse of `Generalization`; derive them rather than reading
  // them, because only the child records the relationship.
  for (const entity of Object.values(entities)) {
    if (!entity.generalization) continue;
    const parent = entities[entity.generalization];
    if (parent) parent.specializations.push(entity.qualifiedName);
  }

  const total = Object.values(entities).length;
  const withRules = Object.values(entities).filter((e) => e.isSecurityConfigured).length;
  if (total > 0 && withRules === 0) {
    ruleNotes.push(
      `none of the ${total} entities read defines an access rule; if the project is known to ` +
        'configure entity access, treat this as an extraction failure rather than a finding'
    );
  }

  return {
    entities: analyzed(entities, notes),
    associations: analyzed(associations, notes),
    attributeTypes: analyzed(null, typeNotes),
    accessRules: analyzed(null, ruleNotes),
  };
}

/**
 * `MaybeGeneralization` is either a `Generalization` (naming a qualified parent) or a
 * `NoGeneralization` (carrying the entity's own `Persistable` flag and system members).
 * A specialization inherits persistence from its parent, so it is resolved later by the
 * caller if needed; reporting `persistable` here is the Mendix default for a child of a
 * persistable parent.
 */
function persistenceOf(generalization: BsonDocument | undefined): PersistenceType {
  const persistable = bool(generalization, 'Persistable');
  if (persistable === undefined) return 'persistable';
  return persistable ? 'persistable' : 'non-persistable';
}

/**
 * Read an attribute's real type from `NewType`.
 *
 * The `$Type` discriminator is `DomainModels$<Name>AttributeType`, e.g.
 * `DomainModels$StringAttributeType` → `String`. Deriving the name from the discriminator
 * rather than matching a fixed list means a type introduced by a future Studio Pro version
 * is reported accurately instead of being silently mapped to `String`, which is what made
 * the old parser's `HashedString` check in `rules/security.ts:211` unable to ever pass.
 */
function toAttribute(raw: BsonDocument, entityName: string, notes: string[]): Attribute {
  const name = str(raw, 'Name') ?? '';
  const typeDoc = subDoc(raw, 'NewType');
  const discriminator = elementType(typeDoc);
  const type = discriminator ? attributeTypeName(discriminator) : undefined;
  if (!type) {
    notes.push(`the type of ${entityName}.${name || '(unnamed)'} could not be read`);
  }

  const valueDoc = subDoc(raw, 'Value');
  const sensitivity = classifySensitivity(name);

  return {
    name,
    type,
    length: num(typeDoc, 'Length'),
    defaultValue: str(valueDoc, 'DefaultValue') || undefined,
    isCalculated: elementType(valueDoc) === 'DomainModels$CalculatedValue',
    isSensitive: sensitivity.kind === 'secret',
    isPii: sensitivity.kind === 'pii',
    sensitivityKind: sensitivity.kind,
    sensitivityTerm: sensitivity.matchedTerm,
    documentation: str(raw, 'Documentation') || undefined,
  };
}

function attributeTypeName(discriminator: string): string | undefined {
  const match = /^DomainModels\$(.+)AttributeType$/.exec(discriminator);
  return match ? match[1] : undefined;
}

function toIndex(raw: BsonDocument): IndexItem {
  return {
    name: str(raw, 'Name') ?? '',
    attributes: docArray(raw, 'Attributes')
      .map((a) => str(a, 'Attribute') ?? '')
      .filter((a) => a.length > 0),
  };
}

/**
 * Read one access rule.
 *
 * `AllowedModuleRoles` holds qualified `Module.Role` strings, which is what makes it
 * possible to ask whether a rule grants access to a role the guest user role also holds —
 * the question SEC-020 and SEC-021 exist to answer.
 */
function toAccessRule(
  raw: BsonDocument,
  entityName: string,
  ordinal: number,
  unitPath: string,
  notes: string[]
): AccessRule {
  const roles = strArray(raw, 'AllowedModuleRoles');
  if (roles.length === 0) {
    notes.push(
      `access rule ${ordinal + 1} on ${entityName} lists no module roles, so it grants nothing`
    );
  }

  const xPath = str(raw, 'XPathConstraint');

  return {
    id: elementId(raw) ?? `${entityName}#AccessRule${ordinal + 1}`,
    moduleRoles: roles,
    allowCreate: bool(raw, 'AllowCreate') ?? false,
    allowDelete: bool(raw, 'AllowDelete') ?? false,
    defaultMemberAccess: accessRights(str(raw, 'DefaultMemberAccessRights')) ?? 'None',
    memberAccess: docArray(raw, 'MemberAccesses').map(toMemberAccess),
    // An empty string means "no constraint", which is materially different from "the
    // constraint could not be read"; both arrive here as `undefined`, so the distinction
    // is carried by `entityAccessRules` coverage rather than by this field.
    xPathConstraint: xPath && xPath.length > 0 ? xPath : undefined,
    documentation: str(raw, 'Documentation') || undefined,
    provenance: { unitPath, elementId: elementId(raw) },
  };
}

function toMemberAccess(raw: BsonDocument): MemberAccessRule {
  const attribute = str(raw, 'Attribute');
  const association = str(raw, 'Association');
  const isAssociation = !attribute && !!association;
  return {
    attributeOrAssociation: (isAssociation ? association : attribute) ?? '',
    isAssociation,
    access: accessRights(str(raw, 'AccessRights')) ?? 'None',
  };
}

function accessRights(value: string | undefined): AccessRights | undefined {
  return ACCESS_RIGHTS.find((r) => r === value);
}

function toAssociation(
  raw: BsonDocument,
  moduleName: string,
  entityNameById: Map<string, string>,
  notes: string[]
): Association | undefined {
  const name = str(raw, 'Name');
  if (!name) {
    notes.push(`an unnamed association in ${moduleName} was skipped`);
    return undefined;
  }

  // Endpoints are recorded as pointers to entity `$ID`s. A pointer that does not resolve
  // usually means the other end lives in a module whose domain model was unreadable.
  const parentEntity = resolvePointer(raw, 'ParentPointer', entityNameById);
  const childEntity = resolvePointer(raw, 'ChildPointer', entityNameById);
  if (!parentEntity || !childEntity) {
    notes.push(`association ${moduleName}.${name} has an endpoint that could not be resolved`);
  }

  const rawType = str(raw, 'Type');
  return {
    name,
    module: moduleName,
    parentEntity: parentEntity ?? '',
    childEntity: childEntity ?? '',
    type: ASSOCIATION_TYPES.find((t) => t === rawType) ?? 'Reference',
    owner: str(raw, 'Owner') === 'Both' ? 'Both' : 'Default',
    deleteBehavior: deleteBehaviorOf(raw),
    documentation: str(raw, 'Documentation') || undefined,
  };
}

function resolvePointer(
  raw: BsonDocument,
  key: string,
  entityNameById: Map<string, string>
): string | undefined {
  const value = raw[key];
  if (value instanceof Uint8Array) {
    const id = formatGuid(value);
    return id ? entityNameById.get(id) : undefined;
  }
  if (typeof value === 'string' && value.length > 0) {
    // Some versions record the qualified name directly.
    return entityNameById.get(value) ?? value;
  }
  return undefined;
}

function deleteBehaviorOf(raw: BsonDocument): DeleteBehavior {
  const direct = str(raw, 'DeleteBehavior');
  const found = DELETE_BEHAVIORS.find((b) => b === direct);
  if (found) return found;

  // Newer models nest the behaviour, recording each end separately.
  const nested = subDoc(raw, 'DeleteBehavior');
  const parent = str(nested, 'ParentDeleteBehavior') ?? str(nested, 'DeleteParent');
  const child = str(nested, 'ChildDeleteBehavior') ?? str(nested, 'DeleteChild');
  if (parent === 'DeleteMeAndReferences' && child === 'DeleteMeAndReferences') return 'DeleteBoth';
  if (parent === 'DeleteMeAndReferences') return 'DeleteParentOnly';
  if (child === 'DeleteMeAndReferences') return 'DeleteChildOnly';
  return 'DeleteNever';
}
