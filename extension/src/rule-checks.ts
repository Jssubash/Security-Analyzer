/**
 * What each rule validates, in plain language, for the expandable rows of the Rules tab.
 *
 * This describes the rule's actual conditions in `packages/rules` — what it reads from the open
 * app, when it reports, and what it deliberately leaves alone — so a reviewer can tell from the
 * pane alone why a rule passed. When a rule's logic changes, change its entry here too;
 * `tests/rule-checks.test.mjs` fails if a rule the extension runs has no entry.
 */

export interface RuleCheck {
  /** Where in Studio Pro the rule looks. */
  reads: string;
  /** Each condition that produces a finding. */
  flagged: string[];
  /** What the rule skips on purpose, or never reports. */
  notFlagged: string[];
}

const ANONYMOUS_ONLY = 'Apps with anonymous (guest) access switched off: nothing is anonymous, so the rule passes.';
const MARKETPLACE_REVIEW = 'Marketplace modules are reported as Review, one severity lower, because the team cannot edit them.';

export const RULE_CHECKS: Record<string, RuleCheck> = {
  'SEC-002': {
    reads: 'App Security → Security level.',
    flagged: ['The level is anything other than Production (CheckEverything), e.g. Prototype/demo or Off.'],
    notFlagged: ['A level that could not be read is shown as Not verified, never as a failure or a pass.'],
  },
  'SEC-011': {
    reads: 'App Security → whether security is switched on.',
    flagged: ['Security is switched off for the app.'],
    notFlagged: [],
  },
  'SEC-012': {
    reads: 'App Security → Demo users → "Enable demo users".',
    flagged: ['Demo users are enabled. The finding states how many demo accounts the model defines.'],
    notFlagged: [],
  },
  'SEC-013': {
    reads: 'App Security → Demo users, each account and its password.',
    flagged: ['One finding per demo account that has a password stored in the model.'],
    notFlagged: ['Accounts with an empty password. The password itself is never shown, only its length.'],
  },
  'SEC-014': {
    reads: 'App Security → Administrator (MxAdmin) password, judged against the app\'s own password policy.',
    flagged: [
      'The password is shorter than the policy\'s minimum length, or shorter than 8 when the policy allows less. An empty password counts as weak.',
      'It has no digit (unless the policy does not require one).',
      'It does not mix upper and lower case (unless the policy does not require it).',
      'It has no symbol while the policy requires one.',
    ],
    notFlagged: ['The password value never leaves Studio Pro: only its length and character classes are checked.'],
  },
  'SEC-015': {
    reads: 'App Security → Password policy.',
    flagged: [
      'Minimum length below 8.',
      'Digits, mixed case or a symbol not required. One finding lists every shortfall.',
    ],
    notFlagged: [],
  },
  'SEC-016': {
    reads: 'App Security → "Strict page URL check".',
    flagged: ['The check is switched off.'],
    notFlagged: [],
  },
  'SEC-006': {
    reads: 'App Security → Anonymous users → the anonymous user role, and every module role it holds.',
    flagged: [
      'Each module role held by the anonymous user role. In your own module: Failed, Critical.',
      MARKETPLACE_REVIEW + ' Some Marketplace modules need a role for public pages to work.',
    ],
    notFlagged: [
      'Module roles named exactly Anonymous or Guest (they exist for this purpose).',
      'Roles whose name contains "admin" (SEC-017 reports those).',
      'System roles, which Mendix grants to every user role.',
      ANONYMOUS_ONLY,
    ],
  },
  'SEC-017': {
    reads: 'App Security → Anonymous users → the anonymous user role, and every module role it holds.',
    flagged: ['Each module role whose name contains "admin", in any module including Marketplace ones.'],
    notFlagged: [ANONYMOUS_ONLY],
  },
  'SEC-018': {
    reads: 'Every page whose Visible-for roles include a module role the anonymous user role holds, and the entities that page uses (data views, lists, grids, snippets, data-source microflows and nanoflows, page parameters).',
    flagged: [
      'The page uses a persistable entity that the anonymous role has an access rule on: Failed, High — stored data is visible without logging in.',
      'The page uses a persistable entity the anonymous role has no access rule on: Review, Medium — nothing leaks, but the page fails for visitors.',
    ],
    notFlagged: [
      'Pages built only on non-persistable entities, such as a login page on a login helper.',
      'When a page\'s contents cannot be read, it is reported on reachability alone, except the navigation home page.',
      ANONYMOUS_ONLY,
    ],
  },
  'SEC-019': {
    reads: 'Every page in your own modules → Properties → Visible for.',
    flagged: ['A page with no module role ticked: nobody can open it while security is on.'],
    notFlagged: ['Pages in Marketplace modules.'],
  },
  'SEC-009': {
    reads: 'App Security → Anonymous users.',
    flagged: ['Advisory, off by default. When switched on: one reminder if anonymous access is enabled and the anonymous role holds a module role, to confirm rate limiting outside Mendix.'],
    notFlagged: ['It never fails a project: rate limiting cannot be seen in the model, so it is not scored.'],
  },
  'SEC-001': {
    reads: 'Domain models of your own modules → each entity → Access rules tab.',
    flagged: ['A persistable entity with no access rule at all.'],
    notFlagged: ['Non-persistable entities.', 'Entities in Marketplace modules.'],
  },
  'SEC-003': {
    reads: 'Every entity access rule, and which module roles the anonymous user role holds.',
    flagged: ['An access rule on a persistable entity, granted to an anonymous-held module role, that allows Create, allows Delete, or gives Read/Write by default to new members.'],
    notFlagged: ['Non-persistable entities.', ANONYMOUS_ONLY],
  },
  'SEC-020': {
    reads: 'Every entity access rule granted to an anonymous-held module role, member by member.',
    flagged: ['Each attribute or association set to Read/Write on such a rule, on a persistable entity.'],
    notFlagged: ['Read-only members (SEC-029 reports any anonymous access at all).', 'Non-persistable entities.', ANONYMOUS_ONLY],
  },
  'SEC-029': {
    reads: 'Every entity access rule, and which module roles the anonymous user role holds.',
    flagged: [
      'Any access rule on a persistable entity granted to an anonymous-held module role, even read-only. The finding lists the rights it gives and whether an XPath limits it.',
      'Own module: Failed, High. ' + MARKETPLACE_REVIEW,
    ],
    notFlagged: ['Non-persistable entities.', 'System module entities.', ANONYMOUS_ONLY],
  },
  'SEC-021': {
    reads: 'User roles (to find module roles held by more than one user role — "broad" roles) and every entity access rule with its member rights.',
    flagged: ['A member readable (Read or Read/Write) through a broad role whose name marks it as secret (password, token, secret, API key, PIN…) or personal data (email, phone, address, date of birth, passport, IBAN…).'],
    notFlagged: ['Members whose type cannot hold such a value, e.g. a Boolean called ShowEmail.', 'Module roles held by only one user role.'],
  },
  'SEC-022': {
    reads: 'Domain models of your own modules → entities with System members → "Store \'owner\'" ticked (directly or on their generalization), and their access rules.',
    flagged: ['Each access rule on such an entity with an empty XPath constraint, unless every role on it is an administrator role (name contains "admin"). Reported as Review, Medium.'],
    notFlagged: [
      'Entities without "Store \'owner\'" — even when they link to a user account in another way.',
      'Rules with any XPath constraint (the XPath\'s content is not inspected).',
    ],
  },
  'SEC-EE-003': {
    reads: 'Every entity access rule → "Default rights for new members".',
    flagged: [
      'The default is Read or Read/Write on a rule granted to at least one role that is not an administrator (name contains "admin") and not a System role.',
      'Own module: Failed, High. ' + MARKETPLACE_REVIEW,
    ],
    notFlagged: ['Rules whose default is None.', 'System module entities.'],
  },
  'SEC-005': {
    reads: 'Domain models of your own modules → each attribute\'s name and type.',
    flagged: ['An attribute whose name marks it as a secret (password, token, secret, API key, PIN…) and whose type is not Hashed string.'],
    notFlagged: ['Marketplace modules.'],
  },
  'SEC-008': {
    reads: 'Domain models of your own modules → String attributes.',
    flagged: ['Advisory, off by default. When on: one review per entity holding String attributes named as personal data (email, phone, address…).'],
    notFlagged: ['Mendix has no encrypted attribute type, so this is a prompt to decide, not a defect.'],
  },
  'SEC-023': {
    reads: 'App Security → User roles → each role\'s "Check security".',
    flagged: ['A user role with security checking switched off.'],
    notFlagged: [],
  },
  'SEC-024': {
    reads: 'App Security → User roles → "User management: all roles".',
    flagged: ['A user role that may manage all roles and is not the administrator role (the role App Security assigns to MxAdmin, or a role whose name starts with "Admin").'],
    notFlagged: [],
  },
  'SEC-025': {
    reads: 'Module security of your own modules, and which module roles each user role holds.',
    flagged: ['A module role that no user role holds. Reported as Review.'],
    notFlagged: ['Marketplace modules, which ship roles for features an app may not use.'],
  },
  'SEC-026': {
    reads: 'Every constant → name and default value.',
    flagged: ['A constant whose name marks it as a credential (password, secret, token, API key…) and that has a value in the model.'],
    notFlagged: ['Empty values and obvious placeholders such as "changeme". The value is never shown.'],
  },
  'SEC-027': {
    reads: 'Every constant → name, default value and "Exposed to client".',
    flagged: ['A credential-named constant with a value that is also exposed to the client, so it is sent to every browser.'],
    notFlagged: [],
  },
  'SEC-010': {
    reads: 'Constants of your own modules → name.',
    flagged: ['A constant whose name mentions localStorage or sessionStorage. Reported as Review, Low.'],
    notFlagged: ['Marketplace modules.'],
  },
  'SEC-004': {
    reads: 'Published REST services → Authentication setting, and each resource operation.',
    flagged: ['Every operation of a service that requires no authentication.'],
    notFlagged: [
      'Operation-level overrides are not assessed.',
      'Not applicable when the app publishes no REST services.',
    ],
  },
  'SEC-028': {
    reads: 'Every microflow → "Apply entity access" and "Allowed roles".',
    flagged: [
      'Apply entity access is off and at least one role may call the microflow. Own module: Failed (Critical when the anonymous role can call it, otherwise High).',
      'A Marketplace microflow only when the anonymous role can call it: Review.',
    ],
    notFlagged: ['Microflows with no allowed roles: they can only be called by other microflows.'],
  },
  'SEC-MF-001': {
    reads: 'Every microflow → "Apply entity access", "Allowed roles", and where it is used.',
    flagged: [
      'All three together: Apply entity access is off; it is allowed for a role that is not an administrator or System role; and a page, snippet, layout, navigation item, building block or page template calls it.',
      'Own module: Failed, Critical. ' + MARKETPLACE_REVIEW,
    ],
    notFlagged: ['Microflows only called by other microflows, scheduled events or services.', 'System module microflows.'],
  },
  'SEC-MF-002': {
    reads: 'Microflows the anonymous role may call, and their activities.',
    flagged: ['The microflow contains a Create, Change or Delete object activity on a persistable entity.'],
    notFlagged: [
      'Changes to non-persistable objects.',
      'Activities whose entity cannot be determined.',
      ANONYMOUS_ONLY,
    ],
  },
  'SEC-MF-003': {
    reads: 'Microflows with Apply entity access off and allowed roles, their object and list parameters, and their activities in execution order.',
    flagged: [
      'A parameter of a persistable entity that the microflow changes or deletes.',
      'A parameter of a non-persistable entity whose values ($Param/…) are written into a persistable object by a Create or Change activity.',
    ],
    notFlagged: [
      'Microflows that first check ownership: an earlier database retrieve whose XPath uses [%CurrentUser%], or a decision on $currentUser.',
      'Microflows with no allowed roles, which the client cannot call directly.',
    ],
  },
  'SEC-MF-004': {
    reads: 'Published REST operations without authentication, and the first two steps of each operation\'s microflow.',
    flagged: ['Neither of the first two steps reads the request\'s headers or a credential (HttpRequest, HttpHeader, Authorization, Bearer, API key, JWT, token).'],
    notFlagged: ['Not applicable when the app publishes no REST services.'],
  },
  'SEC-MF-005': {
    reads: 'Microflows in your own modules with allowed roles, and every place in the model that refers to a microflow.',
    flagged: ['Nothing refers to the microflow: no page, snippet, layout, navigation item, other microflow or nanoflow, entity event, scheduled event, workflow, published service, app setting, constant or Java code.'],
    notFlagged: ['Microflows without allowed roles.', 'Marketplace modules.'],
  },
};
