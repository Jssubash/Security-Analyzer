/**
 * Which entities a page works with, resolved from the names it refers to.
 *
 * A page names entities in several ways: a data view's or list's entity, a page parameter's
 * type, an attribute path (`Module.Entity.Attribute`), a snippet it embeds, and a microflow or
 * nanoflow data source whose return type is an entity. This resolves all of them to entity
 * qualified names, following snippets transitively, so a rule can ask "does this page show
 * stored data?" rather than "can this page be opened?".
 *
 * Both the archive parser and the Studio Pro extension feed this the same way — a list of
 * qualified names per page and snippet — so the two cannot reach different verdicts on one app.
 *
 * It over-approximates on purpose: a flow referenced by a button (not a data source) whose
 * return type is an entity is also counted. For a check about exposure, counting a page as
 * using an entity it only acts on is the safe direction to be wrong in.
 */

export interface PageDataContext {
  /** Qualified names of every entity in the model. */
  entities: ReadonlySet<string>;
  /** Microflow and nanoflow qualified name → the entity it returns, if any. */
  flowReturnEntities: ReadonlyMap<string, string | undefined>;
  /** Snippet qualified name → the names it refers to. */
  snippetReferences: ReadonlyMap<string, readonly string[]>;
}

export function resolveDataEntities(references: readonly string[], context: PageDataContext): string[] {
  const found = new Set<string>();
  const visitedSnippets = new Set<string>();

  const visit = (names: readonly string[]): void => {
    for (const name of names) {
      if (context.entities.has(name)) {
        found.add(name);
        continue;
      }
      if (context.flowReturnEntities.has(name)) {
        const returned = context.flowReturnEntities.get(name);
        if (returned) found.add(returned);
        continue;
      }
      const snippet = context.snippetReferences.get(name);
      if (snippet) {
        if (visitedSnippets.has(name)) continue;
        visitedSnippets.add(name);
        visit(snippet);
        continue;
      }
      // An attribute or association path: `Module.Entity.Member`.
      const parts = name.split('.');
      if (parts.length >= 3) {
        const owner = `${parts[0]}.${parts[1]}`;
        if (context.entities.has(owner)) found.add(owner);
      }
    }
  };

  visit(references);
  return [...found].sort();
}

/**
 * Candidate qualified names in a model tree: every string shaped like `Module.Name[.Member…]`.
 *
 * Deliberately broad — captions and expressions are filtered out by shape, and anything that
 * does not resolve to an entity, flow or snippet is ignored by {@link resolveDataEntities}.
 */
export function looksQualified(value: string): boolean {
  return value.length < 256 && /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$/.test(value);
}
