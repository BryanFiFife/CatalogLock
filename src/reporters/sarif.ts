import type { Finding } from '../types.js';

const level = (s: Finding['severity']) => s === 'critical' || s === 'error' ? 'error' : s === 'warning' ? 'warning' : 'note';

export function sarifReport(findings: Finding[]): string {
  const ids = [...new Set(findings.map((f) => f.ruleId))].sort();
  const rules = ids.map((id) => ({ id, shortDescription: { text: id } }));
  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: level(f.severity),
    message: { text: f.message },
    ...(f.location ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.location } } }] } : {}),
    properties: { severity: f.severity, ...(f.evidence ? { evidence: f.evidence } : {}) }
  }));
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'CatalogLock', informationUri: 'https://github.com/BryanFiFife/CatalogLock', rules } }, results }]
  }, null, 2) + '\n';
}
