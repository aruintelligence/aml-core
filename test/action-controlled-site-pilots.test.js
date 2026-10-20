import test from 'node:test';
import assert from 'node:assert/strict';
import { html } from '../scripts/build-controlled-pilot-pages.mjs';
import { validateSingleRemoval } from '../scripts/dispatch-controlled-pilot-pages.mjs';

const site = { id: '01', slug: 'support-hours', title: 'Support hours',
  context: 'Context', action: 'Contact the maintainers', placement: 'banner', accent: '#48d9c4' };
const href = 'https://github.com/aruintelligence/aml-core/issues/new';

test('the permitted mutation removes only the declared duplicate', () => {
  validateSingleRemoval(html(site, 'before'), html(site, 'after'), site, href);
});

test('a changed contact destination fails even when the duplicate was removed', () => {
  const after = html(site, 'after').replace(`id="contact-action" href="${href}"`,
    'id="contact-action" href="https://other.example.test"');
  assert.throws(() => validateSingleRemoval(html(site, 'before'), after, site, href));
});

test('an added payload or changed target fails before the callback can write', () => {
  assert.throws(() => validateSingleRemoval(html(site, 'before'), html(site, 'after') + '<script>extra</script>', site, href));
  assert.throws(() => validateSingleRemoval(html(site, 'before').replace('id="redundant-contact"', 'id="other"'), html(site, 'after'), site, href));
});
