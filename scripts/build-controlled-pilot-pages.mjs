#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'pilots/action-boundary/controlled-sites.json')));
assert.equal(manifest.protocol, 'aml-controlled-site-pilots/1');
assert.equal(manifest.sites.length, 10);
const escape = s => String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

export function html(site, stage) {
  assert.ok(['before', 'after'].includes(stage));
  const href = escape(manifest.contact_href);
  const title = escape(site.title);
  const action = escape(site.action);
  const duplicate = stage === 'before' ? `
    <aside id="redundant-contact" class="duplicate ${site.placement}" data-pilot-target="redundant_duplicate" aria-label="Repeated contact action">
      <span class="overline">Repeated action · ${escape(site.placement)}</span>
      <a href="${href}">${action}</a>
    </aside>` : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} · controlled action pilot ${site.id} · ${stage}</title>
  <style>
    :root{font:16px/1.55 system-ui;color:#eff6ff;background:#091225;--accent:${site.accent}}
    *{box-sizing:border-box}body{margin:0;min-height:100vh}
    header,main,footer{max-width:860px;margin:auto;padding:24px}
    header{display:flex;align-items:center;justify-content:space-between;gap:24px;border-bottom:1px solid #33465f}
    a{color:var(--accent)}a:focus-visible{outline:3px solid white;outline-offset:4px}
    .brand{font-weight:800;letter-spacing:.12em;text-transform:uppercase}
    main{padding-top:70px;padding-bottom:120px}h1{font-size:clamp(2.5rem,7vw,4.5rem);line-height:1.05;margin:10px 0}
    .eyebrow,.overline{color:#a9bed7;font-size:.78rem;letter-spacing:.13em;text-transform:uppercase}
    .intro{font-size:1.25rem;color:#c4d3e6;max-width:580px}
    .contact{border:1px solid #59728d;border-radius:18px;background:#13243d;padding:28px;margin-top:44px}
    .contact a,.duplicate a{font-weight:750}.contact a{display:inline-block;padding:12px 17px;border-radius:10px;background:var(--accent);color:#071522}
    .contact p,footer{color:#b5c6db}
    .duplicate{border:2px solid var(--accent);border-radius:14px;background:#243d5c;padding:17px 22px;display:flex;align-items:center;justify-content:space-between;gap:12px;box-shadow:0 14px 40px #0005}
    .duplicate.banner,.duplicate.strip{margin:20px auto;max-width:860px}
    .duplicate.sidebar,.duplicate.card,.duplicate.inline,.duplicate.nav,.duplicate.badge{margin:22px 0}
    .duplicate.float{position:fixed;right:24px;top:110px;z-index:2}
    .duplicate.sticky{position:sticky;bottom:0;z-index:2;margin:0 24px}
    .duplicate.footer{margin:20px auto;max-width:860px}
    @media(max-width:730px){.duplicate.float{position:static;margin:20px}.duplicate{display:block}.duplicate a{display:block}}
  </style>
</head>
<body data-pilot-id="${site.id}" data-stage="${stage}">
  <header><span class="brand">Action boundary lab</span><span class="eyebrow">Controlled public page ${site.id}/10</span></header>${['banner','strip','nav'].includes(site.placement) ? duplicate : ''}
  <main>
    <p class="eyebrow">Receipt binding · live-site pilot</p>
    <h1>${title}</h1>
    <p class="intro">${escape(site.context)}</p>${['sidebar','card','inline','badge','float'].includes(site.placement) ? duplicate : ''}
    <section class="contact" id="contact" aria-label="Intentional contact path">
      <h2>Contact path</h2>
      <p>This is the intended public project contact route. It remains present in both page states.</p>
      <a id="contact-action" href="${href}">${action}</a>
    </section>
  </main>${site.placement === 'footer' ? duplicate : ''}
  <footer>Project-controlled test page. The duplicate label is declared by the project; no outside site or visitor is affected.</footer>${site.placement === 'sticky' ? duplicate : ''}
</body>
</html>
`;
}

const command = process.argv[2];
if (!['--write-before', '--check-before', '--write-after', '--check-after'].includes(command)) {
  throw new Error('Usage: node scripts/build-controlled-pilot-pages.mjs --write-before|--check-before|--write-after|--check-after');
}
const stage = command.endsWith('before') ? 'before' : 'after';
const dir = path.join(root, 'docs/action-pilots', stage);
if (command.startsWith('--write')) fs.mkdirSync(dir, { recursive: true });
for (const site of manifest.sites) {
  const filename = path.join(dir, `${site.id}-${site.slug}.html`);
  const expected = html(site, stage);
  if (command.startsWith('--write')) fs.writeFileSync(filename, expected);
  else assert.equal(fs.readFileSync(filename, 'utf8'), expected, filename);
}
console.log(JSON.stringify({ stage, pages: manifest.sites.length, mode: command }));
