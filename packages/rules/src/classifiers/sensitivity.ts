/**
 * The sensitivity classifier, at the path `docs/security.md` §6.6 specifies.
 *
 * The implementation lives in `@mendix-analyzer/application-ir` because the extractors
 * need the same verdict as the rules do, and `mendix-parser` cannot depend on this package.
 * Re-exporting keeps one term list rather than two that drift apart.
 */

export {
  classifySensitivity,
  isPlaceholderValue,
  type SensitivityKind,
  type SensitivityVerdict,
} from '@mendix-analyzer/application-ir';
