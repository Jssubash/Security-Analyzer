/**
 * The extractors' shared view of the model: units, their containment, and the module
 * each one belongs to.
 *
 * Nothing here interprets security, pages or entities — it answers the one question every
 * extractor asks first ("which module owns this unit?") so that no extractor has to
 * re-derive it, and so that the answer is the same for all of them.
 *
 * Module classification comes from the model, not from a name list: `ModuleImpl`
 * records `FromAppStore`, so marketplace modules identify themselves. That replaces the
 * hardcoded marketplace-name checks the old rules relied on (`rules/security.ts:270`),
 * which both missed renamed marketplace modules and mislabelled user modules whose names
 * happened to match.
 */

import { basename, dirname, join } from 'node:path';

import { bool, str } from '../bson/accessors.js';
import { UnitIndex } from '../bson/unit-index.js';
import type { UnitRef } from '../bson/unit-index.js';
import { ContainmentReadError, ContainmentTree } from '../mpr/containment.js';
import type { MprMetadata } from '../mpr/containment.js';

/** Mendix's own modules, which ship with the platform and cannot be edited. */
const SYSTEM_MODULE_NAMES = new Set(['System']);

export type ModuleOrigin = 'user' | 'marketplace' | 'system';

export interface ModuleInfo {
  readonly name: string;
  readonly unitId: string;
  readonly unitPath: string;
  readonly origin: ModuleOrigin;
  readonly fromAppStore: boolean;
  readonly isThemeModule: boolean;
  readonly appStoreVersion?: string;
}

export interface ModelGraphDiagnostics {
  /** Set when the `.mpr` containment tree could not be read at all. */
  readonly containmentError?: string;
  /** Units that exist on disk but have no row in the `.mpr` `Unit` table. */
  readonly unitsMissingContainment: string[];
  /** Units whose owning module could not be determined. */
  readonly unitsWithoutModule: string[];
  readonly unitParseFailures: { unitPath: string; reason: string }[];
}

export class ModelGraph {
  private readonly moduleByUnitId = new Map<string, ModuleInfo>();
  private readonly moduleByName = new Map<string, ModuleInfo>();
  private readonly moduleOfUnit = new Map<string, ModuleInfo>();
  private readonly diagnostics: {
    containmentError?: string;
    unitsMissingContainment: string[];
    unitsWithoutModule: string[];
  };

  private constructor(
    public readonly units: UnitIndex,
    public readonly containment: ContainmentTree | undefined,
    containmentError: string | undefined
  ) {
    this.diagnostics = {
      containmentError,
      unitsMissingContainment: [],
      unitsWithoutModule: [],
    };
    this.indexModules();
    this.attributeUnitsToModules();
  }

  /**
   * Build the graph for an extracted project.
   *
   * @param projectRoot directory containing the `.mpr` and `mprcontents/`
   * @param mprPath the primary `.mpr` file
   */
  public static build(projectRoot: string, mprPath: string): ModelGraph {
    const units = UnitIndex.build(projectRoot, join(dirname(mprPath), 'mprcontents'));
    let containment: ContainmentTree | undefined;
    let containmentError: string | undefined;
    try {
      containment = ContainmentTree.read(mprPath);
    } catch (err) {
      containmentError =
        err instanceof ContainmentReadError ? err.message : `unexpected error: ${describe(err)}`;
    }
    return new ModelGraph(units, containment, containmentError);
  }

  public get mprMetadata(): MprMetadata {
    return this.containment?.metadata ?? {};
  }

  /** Every module in the project, ordered by name for stable output. */
  public get modules(): ModuleInfo[] {
    return [...this.moduleByUnitId.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  public moduleNamed(name: string): ModuleInfo | undefined {
    return this.moduleByName.get(name);
  }

  /** The module that owns a unit, or `undefined` if containment could not resolve it. */
  public moduleOf(ref: UnitRef | string): ModuleInfo | undefined {
    return this.moduleOfUnit.get(typeof ref === 'string' ? ref : ref.unitId);
  }

  /** `Module.Name`, or the bare name when the module is unknown. */
  public qualify(ref: UnitRef, name: string | undefined): string {
    const moduleName = this.moduleOf(ref)?.name;
    const local = name ?? basename(ref.unitPath, '.mxunit');
    return moduleName ? `${moduleName}.${local}` : local;
  }

  /**
   * Whether findings about this module should be reported against the team that owns
   * the app. Marketplace and system modules are third-party code the team cannot edit;
   * design §22 calls for excluding them rather than generating noise.
   */
  public isUserModule(moduleName: string | undefined): boolean {
    if (!moduleName) return false;
    return this.moduleNamed(moduleName)?.origin === 'user';
  }

  public get diagnosticsReport(): ModelGraphDiagnostics {
    return {
      containmentError: this.diagnostics.containmentError,
      unitsMissingContainment: [...this.diagnostics.unitsMissingContainment],
      unitsWithoutModule: [...this.diagnostics.unitsWithoutModule],
      unitParseFailures: this.units.parseFailures.map((f) => ({ ...f })),
    };
  }

  private indexModules(): void {
    for (const { tree, ref } of this.units.unitsOfType('Projects$ModuleImpl')) {
      const name = str(tree, 'Name');
      if (!name) continue; // an unnamed module cannot be referenced by anything
      const fromAppStore = bool(tree, 'FromAppStore') ?? false;
      const appStoreVersion = str(tree, 'AppStoreVersion');
      const info: ModuleInfo = {
        name,
        unitId: ref.unitId,
        unitPath: ref.unitPath,
        origin: SYSTEM_MODULE_NAMES.has(name) ? 'system' : fromAppStore ? 'marketplace' : 'user',
        fromAppStore,
        isThemeModule: bool(tree, 'IsThemeModule') ?? false,
        appStoreVersion: appStoreVersion || undefined,
      };
      this.moduleByUnitId.set(ref.unitId, info);
      this.moduleByName.set(name, info);
    }
  }

  private attributeUnitsToModules(): void {
    const { containment } = this;
    for (const type of Object.keys(this.units.typeHistogram())) {
      for (const ref of this.units.refsOfType(type)) {
        if (!containment) {
          this.diagnostics.unitsWithoutModule.push(ref.unitPath);
          continue;
        }
        if (!containment.containerOf(ref.unitId) && !this.moduleByUnitId.has(ref.unitId)) {
          // No parent and not itself a module: either the project root or an orphan.
          this.diagnostics.unitsMissingContainment.push(ref.unitPath);
        }
        const ownerId = containment.owningUnit(ref.unitId, (id) => this.moduleByUnitId.has(id));
        const owner = ownerId ? this.moduleByUnitId.get(ownerId) : undefined;
        if (owner) this.moduleOfUnit.set(ref.unitId, owner);
        else if (!this.isProjectLevelUnit(ref)) {
          this.diagnostics.unitsWithoutModule.push(ref.unitPath);
        }
      }
    }
  }

  /** Units that legitimately sit outside any module (project settings, navigation, …). */
  private isProjectLevelUnit(ref: UnitRef): boolean {
    return (
      ref.type.startsWith('Settings$') ||
      ref.type.startsWith('Navigation$') ||
      ref.type === 'Projects$Project' ||
      ref.type === 'Projects$ProjectConversion' ||
      ref.type === 'Security$ProjectSecurity' ||
      ref.type === 'Texts$SystemTextCollection'
    );
  }
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
