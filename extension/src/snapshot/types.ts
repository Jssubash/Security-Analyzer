/**
 * The contract between the Studio Pro host (C#) and the analyzer running in the pane.
 *
 * The host walks Studio Pro's untyped model API and serialises the units the security rules
 * need into this shape. It deliberately does no interpretation: every property is copied under
 * the name the model gave it, so the mapping from model to IR lives in one place
 * (`build-ir.ts`), where it can be tested without Studio Pro.
 *
 * Property names differ by source. Studio Pro's untyped API uses metamodel names
 * (`enableGuestAccess`, `allowedRoles`); the `.mxunit` storage format uses storage names
 * (`EnableGuestAccess`, `AllowedModuleRoles`). Readers must go through `accessors.ts`, which
 * matches case-insensitively and accepts both spellings.
 */

export const SNAPSHOT_SCHEMA_VERSION = 1;

/**
 * A secret the host was not willing to hand over.
 *
 * Passwords are reduced to the features the weakness check needs before they leave the host,
 * so the plaintext never reaches the web view, an exported report, or a support dump.
 */
export interface RedactedSecret {
  $redacted: true;
  length: number;
  hasDigit: boolean;
  hasLower: boolean;
  hasUpper: boolean;
  hasSymbol: boolean;
}

export type SnapshotValue =
  | string
  | number
  | boolean
  | null
  | RedactedSecret
  | SnapshotNode
  | SnapshotValue[];

/** One model element or unit, with its properties copied verbatim. */
export interface SnapshotNode {
  $Type: string;
  $ID?: string;
  /** `IModelStructure.Name` where the model defines one. */
  $Name?: string;
  /** `IModelStructure.QualifiedName` where the element can be referred to by name. */
  $QualifiedName?: string;
  [property: string]: SnapshotValue | undefined;
}

export interface SnapshotModule {
  name: string;
  /** `Projects$Module.FromAppStore`, when readable. */
  fromAppStore?: boolean;
  unitId?: string;
  /** Units owned by the module: security, domain model, pages, microflows, constants, services. */
  units: SnapshotNode[];
}

export interface JavaSourceFile {
  /** Directory under `javasource/`, which is the module name in lower case. */
  moduleDirectory: string;
  fileName: string;
  /** Path relative to the app directory, with forward slashes. */
  relativePath: string;
  content: string;
}

export interface ModelSnapshot {
  schemaVersion: number;
  /** Where the snapshot came from; `studio-pro` in production, `mprcontents` in tests. */
  source: 'studio-pro' | 'mprcontents';
  app: {
    name: string;
    directory?: string;
    /** Studio Pro version hosting the extension, e.g. `10.24.0.73019`. */
    studioProVersion?: string;
  };
  /** Project-level units: `Security$ProjectSecurity`, `Navigation$NavigationDocument`. */
  projectUnits: SnapshotNode[];
  modules: SnapshotModule[];
  javaSources: JavaSourceFile[];
  /** Anything the host could not read, in plain language. */
  notes: string[];
  /**
   * For every document that refers to a microflow: its name, kind and the microflows it refers to.
   * Covers all units — pages, layouts, navigation, flows, domain models (event handlers), scheduled
   * events, workflows, published services, project settings. Absent from hosts that predate it.
   */
  referenceIndex?: { referrer: string; kind: string; references: string[] }[];
  /** What the host saw, for troubleshooting a snapshot that reads less than expected. */
  diagnostics?: {
    /** Every unit type found under a module, with a count. */
    unitTypes?: Record<string, number>;
    /** `Owner$Type.property` → CLR type, for values the host had to read by name or text. */
    unexpectedValueTypes?: Record<string, string>;
  };
  capturedAt: string;
}
