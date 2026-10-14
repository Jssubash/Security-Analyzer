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
    reads: 'Domain models of your own modules → each persistable entity\'s attribute names and types; every Create and Change object that sets such an attribute, with its value and its Commit setting; the Java code of each Java action (whether it encrypts with Java\'s Cipher in ENCRYPT_MODE); and which pages refer to the attribute.',
    flagged: [
      'Failed: an attribute whose name marks it as a secret (password, token, secret, API key, PIN…), whose type is not Hashed string, and that no microflow writes through a Java action whose code encrypts — or that one microflow encrypts but another writes as plain text.',
      'Review: every microflow write is encrypted, but a page also refers to the attribute (a plain Save there would store what the user types), or a plain value for it is typed into the model.',
      'The advice depends on the use: a password or PIN the app only verifies → Hashed string; a token, key or secret the app has to send on → keep it a String and encrypt it before commit with EncryptString / DecryptString from the Encryption module.',
    ],
    notFlagged: [
      'Attributes of type Hashed string.',
      'Attributes every microflow write stores encrypted, with no page referring to them. Encrypted means the value comes from an encrypting Java action, from a sub-microflow that returns such a value, or from a Create or Change variable that copies one. A plain value replaced by the encrypted one before the object is committed counts as encrypted.',
      'Non-persistable entities (directly or through their generalization): they are never written to the database.',
      'Marketplace modules.',
      'Writes by Java code, nanoflows, import mappings or REST calls, and before-commit event handlers, are not traced.',
    ],
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
    reads: 'Every microflow → "Apply entity access", "Allowed roles", where it is used, and what it does with stored data.',
    flagged: [
      '"Apply entity access" is off, a role may call the microflow, and no page, snippet, layout or navigation item starts it — the browser can still call it directly.',
      'Graded by what the microflow itself does: writes stored data → Failed, High; only reads stored data → Failed, Medium; no data step of its own but calls other microflows → Review, Low; touches no stored data → Review, Low.',
      'One level higher when the anonymous role can call it.',
      'A Marketplace microflow only when the anonymous role can call it: Review, one level lower.',
    ],
    notFlagged: [
      'Microflows started from a page for a non-administrator role: SEC-MF-001 reports those, so nothing is reported twice.',
      'Microflows with no allowed roles: they can only be called by other microflows.',
    ],
  },
  'SEC-MF-001': {
    reads: 'Every microflow → "Apply entity access", "Allowed roles", which pages, snippets, layouts and navigation items start it, and what it does with stored data.',
    flagged: [
      'All three together: "Apply entity access" is off; a role that is not an administrator or System role may call it; and a page, snippet, layout, navigation item, building block or page template starts it (a button, data source, on-change, menu item…).',
      'Graded by what the microflow itself does: writes stored data → Failed, Critical; only reads stored data → Failed, High; no data step of its own but calls other microflows → Review, Medium; touches no stored data → Review, Low.',
      'Marketplace modules: Review, one level lower, because the team cannot edit them.',
    ],
    notFlagged: [
      'Microflows only administrators may call.',
      'Microflows that no page or navigation item starts (SEC-028 covers those).',
      'System module microflows.',
    ],
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
    reads: 'Microflows with "Apply entity access" off and allowed roles (so the browser can call them), their object and list parameters, and their steps in order.',
    flagged: [
      'It changes or deletes an object parameter of a stored (persistable) entity — the record the browser sent, whose id a user can tamper with.',
      'It copies values from a helper (non-persistable) parameter ($Form/…) into stored data with a Create or Change step.',
    ],
    notFlagged: [
      'Microflows that check ownership first: an earlier database retrieve whose XPath uses [%CurrentUser%], or a decision on $currentUser.',
      'Microflows with no allowed roles: they receive objects from their caller, not from the browser.',
      'A helper object that is only changed itself: nothing reaches the database.',
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
  'SEC-MF-006': {
    reads:
      'Every microflow\'s activities that call another system or convert external data — Call REST service, Send REST request, Call web service, OData external actions and objects, Import with mapping, Export with mapping, Generate document, Call ML model, Call workflow and Java action calls — with each activity\'s error handling setting and its error flow. Activities are recognised by their type, so renaming one does not change whether it is checked; a finding names each activity by the caption you gave it (if any) and what it calls. Also where each microflow is started from, to know which run in the background (scheduled events, workflows, task queues, and the microflows these call).',
    flagged: [
      'High: the activity keeps the default error handling "Rollback" — no custom error handling.',
      'Medium: the activity has "Custom with rollback" or "Custom without rollback", but no Log message activity is on its error flow, directly or inside a microflow the error flow calls.',
      'One finding per microflow, listing every activity concerned.',
      'Java action calls: every call in your own modules; in Marketplace modules only the calls in microflows that run in the background.',
      MARKETPLACE_REVIEW,
    ],
    notFlagged: [
      'Activities that are disabled.',
      'Activities whose error handling is set to "Continue": the microflow deliberately carries on past a failure. Mendix advises "Custom without rollback" with a Log message instead where possible, because Continue logs nothing.',
      'Java action calls in Marketplace microflows that do not run in the background.',
      'Other activities (retrieve, commit, change object, call microflow …): their failures are internal to the app.',
    ],
  },
  'SEC-MF-008': {
    reads:
      'Microflows with "Apply entity access" on: their allowed module roles, the sub-microflows they call, and for each Create object, Change object, Delete object and Retrieve from database the entity\'s access rules (including those on its generalizations).',
    flagged: [
      'Critical (the user is blocked): a module role allowed to run the microflow cannot create the entity ("Create objects" off or no access rule), cannot write a member the activity sets (read only or no access), or cannot delete the entity — e.g. a Manager role that may write only Status, on a Change object that also sets personal data.',
      'Medium: a Retrieve from database on an entity the module role has no access rule for — it returns nothing for that role.',
      'Each module role is judged by its own access rules in its own module, even when a user role also holds a stronger role of that module. For an entity in another module, the roles of that module that every user role holding it also holds count.',
      'Only the access rights of the module role\'s rules count — "Create objects", "Delete objects" and Read/Write per member — whether or not a rule has an XPath constraint.',
      'Sub-microflows (also with "Apply entity access" on) are checked with the module roles of the microflows that call them.',
      'One finding per microflow, listing each module role (and the user roles holding it) and what it cannot do.',
      MARKETPLACE_REVIEW,
    ],
    notFlagged: [
      'Microflows with "Apply entity access" off (SEC-028 and SEC-MF-001 cover those).',
            'Non-persistable entities: the runtime does not hold microflows to their create, delete and write rights.',
      'Associations that no access rule of the entity mentions (their access can be set on the other entity).',
      'Calls made in a task queue, and module roles held only by user roles with security checks switched off.',
    ],
  },
  'SEC-MF-007': {
    reads:
      'Every Create object and Change object activity in every microflow: each member it sets and the expression that sets it, the entity of each object variable (parameters, created and retrieved objects, loop iterators), and the Decisions before the activity.',
    flagged: [
      'A value read from an object variable ($Object/Member, also through associations) is passed to a conversion or function — parseInteger, parseLong, parseDecimal, parseDateTime(UTC), toString, formatDateTime/Date/Time(UTC), formatDecimal, getCaption, getKey, dateTimeToEpoch, epochToDateTime, round, floor, ceil, abs, pow, sqrt, max, min, or a date function (addDays, betweenHours, beginOfMonth, trimToDays …) — and nothing checks it for empty.',
      'A value is used in a calculation (* : div mod -, or + on a number) and nothing checks it for empty.',
      'Medium; High when the microflow runs in the background (scheduled event, workflow, task queue, or called from one). One finding per microflow, listing each member and expression.',
      MARKETPLACE_REVIEW,
    ],
    notFlagged: [
      'A value checked in the same expression: if $Object/Member != empty then … else … (or = empty).',
      'A value checked by a Decision earlier in the microflow ($Object/Member != empty).',
      'A parse function with a default value, e.g. parseInteger($Object/Member, 0): it returns the default instead of failing.',
      'A value copied without conversion (String to String, Integer to Integer …), and text joined with +.',
      'Disabled activities.',
    ],
  },
};
