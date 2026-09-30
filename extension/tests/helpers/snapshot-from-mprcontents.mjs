/**
 * Build a ModelSnapshot from an unpacked project's `mprcontents`, the way the Studio Pro host
 * builds one from the live model.
 *
 * This is what lets the extension's analysis be tested without Studio Pro: the reference
 * project is read with the parser's BSON reader and containment graph, and each unit is copied
 * into the snapshot shape with storage property names. The host sends metamodel names instead
 * (see `naming.test.mjs`, which checks both spellings produce the same IR).
 *
 * Passwords are redacted here exactly as `SecretRedactor.cs` does in the host, so no test can
 * pass by reading a plaintext value the production path never sees.
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';

import { looksQualified } from '@mendix-analyzer/application-ir';
import { formatGuid } from '@mendix-analyzer/mendix-parser';
import { ModelGraph } from '@mendix-analyzer/mendix-parser';

/** Unit types the host collects, by module and at project level. */
export const MODULE_UNIT_TYPES = [
  'Security$ModuleSecurity',
  'DomainModels$DomainModel',
  'Forms$Page',
  'Microflows$Microflow',
  'Constants$Constant',
  'Rest$PublishedRestService',
  'Forms$Snippet',
  'Microflows$Nanoflow',
];
export const PROJECT_UNIT_TYPES = ['Security$ProjectSecurity', 'Navigation$NavigationDocument'];

/** Units the host copies shallowly: nested elements (widgets, activities) are skipped. */
// Microflows are copied in full: the SEC-MF rules read their parameters and activities.
const SHALLOW_TYPES = new Set(['Forms$Page', 'Forms$Snippet', 'Microflows$Nanoflow']);

/** Units given `$References`; mirrors `ModelSnapshotReader.ReferenceKinds`. */
const REFERENCE_TYPES = new Set(['Forms$Page', 'Forms$Snippet', 'Microflows$Microflow', 'Microflows$Nanoflow']);

/**
 * Qualified-name strings anywhere in the tree. The host collects by-name references from the
 * API's type information; storage has none, so shape is used instead. Extra strings are harmless:
 * the resolver ignores names that are not entities, flows or snippets.
 */
function references(doc) {
  const found = new Set();
  const visit = (v) => {
    if (typeof v === 'string') {
      if (looksQualified(v)) found.add(v);
    } else if (Array.isArray(v)) v.forEach(visit);
    else if (isDoc(v)) Object.values(v).forEach(visit);
  };
  visit(doc);
  return [...found].sort();
}

/** Properties whose values are credentials; mirrors `SecretRedactor.SecretPropertyNames`. */
const SECRET_PROPERTIES = new Set(['adminpassword', 'password']);

export function redact(value) {
  return {
    $redacted: true,
    length: value.length,
    hasDigit: /[0-9]/.test(value),
    hasLower: /[a-z]/.test(value),
    hasUpper: /[A-Z]/.test(value),
    hasSymbol: /[^A-Za-z0-9]/.test(value),
  };
}

function isDoc(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array);
}

function convertValue(key, value, shallow) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'bigint') return Number(value);
  if (value instanceof Uint8Array) return value.length === 16 ? formatGuid(value) : null;
  if (Array.isArray(value)) {
    const out = [];
    for (const item of value) {
      if (isDoc(item)) {
        if (!shallow) out.push(convertNode(item, false));
      } else {
        const v = convertValue(key, item, shallow);
        if (v !== undefined) out.push(v);
      }
    }
    return out;
  }
  // A flow's return type survives a shallow copy, as in the host: data sources resolve through it.
  if (isDoc(value)) return shallow && !/ReturnType$/i.test(key) ? undefined : convertNode(value, false);
  if (typeof value === 'string' && SECRET_PROPERTIES.has(key.toLowerCase())) return redact(value);
  return value;
}

export function convertNode(doc, shallow) {
  const node = { $Type: doc.$Type };
  if (doc.$ID instanceof Uint8Array) node.$ID = formatGuid(doc.$ID);
  for (const key of Object.keys(doc)) {
    if (key === '$Type' || key === '$ID') continue;
    const v = convertValue(key, doc[key], shallow);
    if (v !== undefined) node[key] = v;
  }
  return node;
}

function javaSources(projectRoot) {
  const out = [];
  const root = join(projectRoot, 'javasource');
  if (!existsSync(root)) return out;
  for (const dir of readdirSync(root, { withFileTypes: true })) {
    if (!dir.isDirectory()) continue;
    const actions = join(root, dir.name, 'actions');
    if (!existsSync(actions)) continue;
    for (const file of readdirSync(actions)) {
      if (!file.toLowerCase().endsWith('.java')) continue;
      out.push({
        moduleDirectory: dir.name,
        fileName: file,
        relativePath: `javasource/${dir.name}/actions/${file}`,
        content: readFileSync(join(actions, file), 'utf8'),
      });
    }
  }
  return out;
}

/**
 * @param {string} projectRoot directory holding the `.mpr`
 * @param {string} mprPath
 * @param {{ dropTypes?: string[] }} options unit types to leave out, to simulate unreadable input
 */
export function snapshotFromMprContents(projectRoot, mprPath, options = {}) {
  const graph = ModelGraph.build(projectRoot, mprPath);
  const drop = new Set(options.dropTypes ?? []);

  const modules = graph.modules.map((info) => ({
    name: info.name,
    fromAppStore: info.fromAppStore,
    unitId: info.unitId,
    units: [],
  }));
  const byName = new Map(modules.map((m) => [m.name, m]));

  for (const type of MODULE_UNIT_TYPES) {
    if (drop.has(type)) continue;
    for (const { tree, ref } of graph.units.unitsOfType(type)) {
      const owner = graph.moduleOf(ref);
      const module = owner ? byName.get(owner.name) : undefined;
      if (!module) continue;
      const node = convertNode(tree, SHALLOW_TYPES.has(type));
      if (REFERENCE_TYPES.has(type)) node.$References = references(tree);
      module.units.push(node);
    }
  }

  const projectUnits = [];
  for (const type of PROJECT_UNIT_TYPES) {
    if (drop.has(type)) continue;
    for (const { tree } of graph.units.unitsOfType(type)) projectUnits.push(convertNode(tree, false));
  }

  return {
    schemaVersion: 1,
    source: 'mprcontents',
    app: {
      name: basename(mprPath, '.mpr'),
      directory: projectRoot,
      studioProVersion: graph.mprMetadata.productVersion,
    },
    projectUnits,
    modules,
    javaSources: javaSources(projectRoot),
    referenceIndex: options.withoutReferenceIndex ? undefined : referenceIndex(graph),
    notes: [],
    capturedAt: new Date(0).toISOString(),
  };
}

/**
 * Every unit that refers to a microflow, mirroring `ModelSnapshotReader.ReferenceIndex`: the
 * referrer's qualified name (or its type, for project-level units), its kind, and the microflow
 * names it contains.
 */
function referenceIndex(graph) {
  const microflowNames = new Set();
  for (const { tree, ref } of graph.units.unitsOfType('Microflows$Microflow')) {
    const owner = graph.moduleOf(ref);
    if (owner && tree.Name) microflowNames.add(`${owner.name}.${tree.Name}`);
  }
  const index = [];
  for (const type of Object.keys(graph.units.typeHistogram())) {
    for (const { tree, ref } of graph.units.unitsOfType(type)) {
      const found = references(tree).filter((r) => microflowNames.has(r));
      if (found.length === 0) continue;
      const owner = graph.moduleOf(ref);
      const kind = type.slice(type.indexOf('$') + 1).replace(/Impl$/, '');
      const referrer = owner && tree.Name ? `${owner.name}.${tree.Name}` : owner ? `${owner.name}.${kind}` : kind;
      index.push({ referrer, kind, references: found });
    }
  }
  return index;
}
