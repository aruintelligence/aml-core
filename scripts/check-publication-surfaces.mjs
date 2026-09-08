import fs from 'node:fs';

const required = {
  'PUBLICATIONS.md': ['ĀML Publications', 'Start Here — ĀML in 5 minutes', 'A critic\'s guide to ĀML'],
  'publications/START_HERE.md': ['Start Here — ĀML in 5 Minutes', 'Open the proof'],
  'publications/AML_IN_ONE_PAGE.md': ['ĀML in One Page', 'interface firewall'],
  'publications/WHY_AI_UI_NEEDS_A_FIREWALL.md': ['Why AI-Generated UI Needs a Firewall', 'receipt'],
  'publications/DARK_PATTERN_CASEBOOK.md': ['Dark-Pattern Casebook', 'SUPPRESS'],
  'publications/RECEIPT_ANATOMY.md': ['Receipt Anatomy', 'declared purpose'],
  'publications/VIEW_MEANING_EXPLAINER.md': ['View Meaning', 'View Source'],
  'publications/MEANING_GATE_EXPLAINER.md': ['Meaning Gate', 'CI'],
  'publications/DEVELOPER_INTEGRATION_BRIEF.md': ['Developer Integration Brief', '<aml-gate purpose='],
  'publications/AI_PRODUCT_LEADER_BRIEF.md': ['Brief for AI Product Leaders', '30-minute pilot'],
  'publications/DESIGNER_BRIEF.md': ['Brief for Product and UX Designers', 'design judgment'],
  'publications/SECURITY_PRIVACY_BRIEF.md': ['Brief for Security and Privacy Teams', 'tamper-evident'],
  'publications/RESEARCH_STANDARDS_BRIEF.md': ['Brief for Researchers and Standards Engineers', 'not a ratified standard'],
  'publications/ENTERPRISE_BUYER_BRIEF.md': ['Enterprise Buyer Brief', 'Office@aruintelligence.com'],
  'publications/FAQ_EXECUTIVE.md': ['ĀML Executive FAQ', 'working research prototype'],
  'publications/COMPARISON_LANDSCAPE.md': ['Where ĀML Fits', 'complementary accountability layer'],
  'publications/20_POST_LAUNCH_PACK.md': ['20-Post ĀML Launch Pack', 'No fake adoption'],
  'publications/EMAIL_OUTREACH_10.md': ['10 Outreach Emails', 'Office@aruintelligence.com'],
  'publications/CONFERENCE_TALK.md': ['Conference Talk Proposal', 'The Interface Firewall'],
  'publications/PODCAST_MEDIA_BRIEF.md': ['ĀML Media / Podcast Brief', '20-second demo'],
  'publications/DEMO_SCRIPT_90_SECONDS.md': ['90-Second ĀML Demo Script', 'SUPPRESS'],
  'publications/WHY_TEAMS_TRY_AML.md': ['Why Teams Might Try ĀML', 'Generated UI review'],
  'publications/CRITICS_GUIDE.md': ["A Critic's Guide to ĀML", 'Strong criticisms to test'],
  'publications/BUYER_OBJECTIONS.md': ['Buyer Objections', 'Answered Without Hype'],
  'publications/LAUNCH_RELEASE.md': ['Launch Release Draft', 'research prototype']
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

console.log(JSON.stringify({
  verified: true,
  publication_count_guarded: Object.keys(required).length,
  public_spine: ['ĀML', 'interface firewall', 'attention cost', 'restoration value', 'receipt', 'View Meaning', 'Meaning Gate'],
  promise: 'The mainstream AML publication library remains present, proof-linked, audience-specific, and bounded by prototype truth.'
}, null, 2));
