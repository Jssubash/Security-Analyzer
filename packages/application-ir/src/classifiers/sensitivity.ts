/**
 * Name-based sensitivity classification for model members and constants.
 *
 * This is a *heuristic on identifiers*, and every finding built on it must say so. It
 * exists because Mendix records no sensitivity metadata: the only signal available without
 * reading production data is what the modeller called the field. So `Password` is treated
 * as a secret and `Email` as PII, and the caller is told which term matched so a finding
 * can justify itself rather than asserting.
 *
 * The deny-list is what makes it usable in practice. Half the matches in a real Atlas-based
 * project are on names like `PasswordHelpText` and `EmailTemplate_Caption` — labels and
 * captions that contain a sensitive word but hold no sensitive value. Reporting those
 * trains reviewers to ignore the category, which is worse than not checking it.
 *
 * Lives in `application-ir` rather than in `rules` because both the extractors and the
 * rules must reach the same verdict; a second copy of these lists would drift.
 */

export type SensitivityKind = 'secret' | 'pii' | 'none';

export interface SensitivityVerdict {
  kind: SensitivityKind;
  /** The term that matched, for the evidence trail. `undefined` when `kind` is `none`. */
  matchedTerm?: string;
  /**
   * How much the name alone justifies. `High` for unambiguous secret words, `Medium` for
   * PII, `Low` when the match is a substring of a longer word and so could be incidental.
   */
  confidence: 'High' | 'Medium' | 'Low';
}

/** Credentials and secrets: a plaintext value here is a finding on its own. */
const SECRET_TERMS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'token',
  'apikey',
  'api_key',
  'privatekey',
  'private_key',
  'clientsecret',
  'client_secret',
  'credential',
  'ssn',
  'creditcard',
  'credit_card',
  'cvv',
  'pin',
] as const;

/** Personal data: not a defect in itself, but it constrains who may read the member. */
const PII_TERMS = [
  'email',
  'phone',
  'mobile',
  'address',
  'postcode',
  'zipcode',
  'dateofbirth',
  'dob',
  'passport',
  'nationalid',
  'bsn',
  'iban',
] as const;

/**
 * Names that contain a sensitive term but hold no sensitive value.
 *
 * Matched against the normalised name. `pin` in particular is why this matters: it is a
 * substring of `mapping`, `spinner`, and `pinned`.
 */
const DENY_SUBSTRINGS = [
  'tokenize',
  'passwordpolicy',
  'passwordhelptext',
  'passwordhelp',
  'passwordrequirement',
  'passwordstrength',
  'emailtemplate',
  'addressline_label',
  'hasphone',
  'hasemail',
  'mapping',
  'spinner',
  'pinned',
  'unpin',
  'pincode_label',
] as const;

/** Suffixes that mark a caption, label or hint rather than a value. */
const DENY_SUFFIXES = ['_caption', '_label', '_placeholder', '_hint', '_tooltip'] as const;

/** Whole words that are display text regardless of what else the name contains. */
const DENY_WORDS = ['caption', 'label', 'placeholder', 'tooltip', 'helptext'] as const;

/**
 * Classify a member, attribute or constant name.
 *
 * @param name unqualified or qualified; only the last segment is considered, so
 *   `MyModule.Account.Email` classifies on `Email`.
 */
export function classifySensitivity(name: string | undefined): SensitivityVerdict {
  if (!name) return { kind: 'none', confidence: 'Low' };

  const localName = name.slice(name.lastIndexOf('.') + 1);
  const normalised = localName.toLowerCase();
  const compact = normalised.replace(/[_\s-]/g, '');

  if (isDenied(normalised, compact)) return { kind: 'none', confidence: 'High' };

  for (const term of SECRET_TERMS) {
    const bare = term.replace(/_/g, '');
    if (compact.includes(bare)) {
      return {
        kind: 'secret',
        matchedTerm: term,
        // An exact name is far stronger evidence than a substring of a longer identifier.
        confidence: compact === bare ? 'High' : looksLikeWord(compact, bare) ? 'High' : 'Low',
      };
    }
  }

  for (const term of PII_TERMS) {
    const bare = term.replace(/_/g, '');
    if (compact.includes(bare)) {
      return {
        kind: 'pii',
        matchedTerm: term,
        confidence: compact === bare ? 'Medium' : looksLikeWord(compact, bare) ? 'Medium' : 'Low',
      };
    }
  }

  return { kind: 'none', confidence: 'High' };
}

function isDenied(normalised: string, compact: string): boolean {
  for (const deny of DENY_SUBSTRINGS) {
    if (compact.includes(deny.replace(/[_\s-]/g, ''))) return true;
  }
  for (const suffix of DENY_SUFFIXES) {
    if (normalised.endsWith(suffix)) return true;
  }
  for (const word of DENY_WORDS) {
    if (compact.endsWith(word)) return true;
  }
  return false;
}

/**
 * Whether `term` sits at a word boundary within `compact`.
 *
 * `compact` has had separators stripped, so boundaries are inferred from position: a term
 * at the start or end of the identifier is a word; one buried in the middle may not be.
 * This is what separates `UserPassword` (High) from `Mapping` (already denied) or
 * `Spinner` (Low if it survived the deny-list).
 */
function looksLikeWord(compact: string, term: string): boolean {
  return compact.startsWith(term) || compact.endsWith(term);
}

/** Whether a value looks like a real secret rather than a placeholder or empty default. */
export function isPlaceholderValue(value: string | undefined): boolean {
  if (!value) return true;
  const v = value.trim().toLowerCase();
  if (v.length === 0) return true;
  return [
    'changeme',
    'change_me',
    'todo',
    'tbd',
    'xxx',
    'xxxx',
    'placeholder',
    'none',
    'null',
    'n/a',
    'na',
    '<secret>',
    '${secret}',
  ].includes(v);
}
