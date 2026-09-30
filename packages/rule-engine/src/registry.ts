import { Rule, RuleCategory, RuleSeverity } from './types.js';

export class RuleRegistry {
  private rules: Map<string, Rule> = new Map();

  public register(rule: Rule): void {
    if (this.rules.has(rule.id)) {
      throw new Error(`Rule with ID "${rule.id}" is already registered.`);
    }
    this.rules.set(rule.id, rule);
  }

  public registerMany(rules: Rule[]): void {
    for (const rule of rules) {
      this.register(rule);
    }
  }

  public get(ruleId: string): Rule | undefined {
    return this.rules.get(ruleId);
  }

  public getAll(): Rule[] {
    return Array.from(this.rules.values());
  }

  public getEnabled(): Rule[] {
    return this.getAll().filter((r) => r.enabled);
  }

  public getByCategory(category: RuleCategory): Rule[] {
    return this.getAll().filter((r) => r.category === category);
  }

  public getBySeverity(severity: RuleSeverity): Rule[] {
    return this.getAll().filter((r) => r.severity === severity);
  }

  public setEnabled(ruleId: string, enabled: boolean): boolean {
    const rule = this.rules.get(ruleId);
    if (!rule) return false;
    rule.enabled = enabled;
    return true;
  }
}
