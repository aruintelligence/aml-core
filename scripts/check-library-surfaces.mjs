import fs from 'node:fs';

const required = {
  'library/README.md': ['ĀML Library', 'AML-LIB-001', 'AML-100'],
  'library/catalog.json': ['aml-library-catalog/1', 'AML-LIB-008', 'AML-CASE-006', 'AML-COMP-003'],
  'library/CITATION.md': ['Citing the ĀML Library', 'Git commit'],
  'library/AML-LIB-001-THE-INTERFACE-FIREWALL.md': ['The Interface Firewall', 'working research prototype'],
  'library/AML-LIB-002-RECEIPTS-FOR-GENERATED-INTERFACES.md': ['Receipts for Generated Interfaces', 'do not prove'],
  'library/AML-LIB-003-WHY-GENERATED-UI-NEEDS-A-DECISION-BOUNDARY.md': ['Generated UI Needs a Decision Boundary', 'declared/model inputs'],
  'library/AML-LIB-004-VIEW-MEANING.md': ['View Meaning', 'declared meaning'],
  'library/AML-LIB-005-MEANING-GATE.md': ['Meaning Gate', 'CI'],
  'library/AML-LIB-006-REPRODUCIBLE-INTERFACE-DECISIONS.md': ['Reproducible Interface Decisions', 'deterministic replay'],
  'library/AML-LIB-007-INDEPENDENT-VERIFICATION.md': ['Independent Verification', 'external witness'],
  'library/AML-LIB-008-DECLARED-INTERFACE-INTENT.md': ['Declared Interface Intent', 'does not'],
  'library/AML-CASE-001-AI-ASSISTANTS.md': ['AI Assistants', 'not evidence'],
  'library/AML-CASE-002-E-COMMERCE.md': ['E-Commerce', 'not evidence'],
  'library/AML-CASE-003-SOCIAL-FEEDS.md': ['Social Feeds', 'declared/model inputs'],
  'library/AML-CASE-004-HEALTH-INTERFACES.md': ['Health Interfaces', 'not evidence'],
  'library/AML-CASE-005-FINANCIAL-INTERFACES.md': ['Financial Interfaces', 'not evidence'],
  'library/AML-CASE-006-EDUCATION.md': ['Education', 'not evidence'],
  'library/AML-COMP-001-AML-AND-CSP.md': ['Content Security Policy', 'complementary'],
  'library/AML-COMP-002-AML-AND-CONSENT-BANNERS.md': ['Consent Banners', 'does not guarantee'],
  'library/AML-COMP-003-AML-AND-POLICY-ENGINES.md': ['General Policy Engines', 'complement'],
  'library/AML-100-WAYS-TO-USE-AN-INTERFACE-FIREWALL.md': ['100 Ways', 'not claims of existing adoption'],
  'library/AML-EXEC-001-EXECUTIVE-BRIEF.md': ['Executive Brief', 'Office@aruintelligence.com']
};

const failures = [];
for (const [path, needles] of Object.entries(required)) {
  if (!fs.existsSync(path)) {
    failures.push(`${path}: missing`);
    continue;
  }
  const text = fs.readFileSync(path, 'utf8');
  for (const needle of needles) {
    if (!text.includes(needle)) failures.push(`${path}: missing ${JSON.stringify(needle)}`);
  }
}

if (failures.length) {
  console.error(JSON.stringify({ verified: false, failures }, null, 2));
  process.exit(1);
}

const catalog = JSON.parse(fs.readFileSync('library/catalog.json', 'utf8'));
if (catalog.type !== 'aml-library-catalog/1') throw new Error('wrong library catalog type');
if (catalog.publications.length !== 19) throw new Error(`expected 19 catalog publications, got ${catalog.publications.length}`);

const ids = catalog.publications.map((item) => item.id);
if (new Set(ids).size !== ids.length) throw new Error('duplicate AML Library publication IDs');

console.log(JSON.stringify({
  verified: true,
  guarded_files: Object.keys(required).length,
  catalog_publications: catalog.publications.length,
  promise: 'The AML Library remains numbered, discoverable, claim-bounded, and machine-readable.'
}, null, 2));
