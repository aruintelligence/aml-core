// Host-owned, one-use authorization receipts presented before four tool calls.
// A real host must keep its signing key and issued-token store private, and must
// have no unwrapped path to the same provider callbacks.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { canonicalJSONStringify } from '../../protocol/canonicalJson.js';
import { planAction } from './boundary.mjs';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const hash = value => sha(canonicalJSONStringify(value));
const copy = value => JSON.parse(canonicalJSONStringify(value));
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join('|') === [...fields].sort().join('|');
const nonempty = x => typeof x === 'string' && x.trim().length > 0;
const blocked = reason => ({ decision: 'SUPPRESS', reason, callback_count: 0 });

export function mailResource(args) {
  if (!exact(args, ['to', 'cc', 'bcc', 'subject', 'body']) ||
      !nonempty(args.to) || !Array.isArray(args.cc) || !Array.isArray(args.bcc) ||
      ![...args.cc, ...args.bcc].every(nonempty) ||
      typeof args.subject !== 'string' || typeof args.body !== 'string') throw Error('invalid_mail');
  const addresses = [args.to, ...args.cc, ...args.bcc];
  if (!addresses.every(x => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x)) ||
      new Set(addresses).size !== addresses.length) throw Error('invalid_mail');
  return `mail:${hash({ to: args.to, cc: args.cc, bcc: args.bcc })}`;
}

export function httpResource(args) {
  if (!exact(args, ['url', 'method', 'headers', 'body']) || !nonempty(args.url) ||
      !['GET', 'POST'].includes(args.method) ||
      !args.headers || typeof args.headers !== 'object' || Array.isArray(args.headers) ||
      !Object.values(args.headers).every(x => typeof x === 'string') ||
      !(args.body === null || typeof args.body === 'string')) throw Error('invalid_http');
  const url = new URL(args.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash ||
      url.href !== args.url || (args.method === 'GET' && args.body !== null)) throw Error('invalid_http');
  return args.url;
}

export function databaseResource(args) {
  if (!exact(args, ['table', 'key', 'value']) ||
      !/^[a-z][a-z0-9_]*$/.test(args.table) || !/^[a-zA-Z0-9_-]+$/.test(args.key)) throw Error('invalid_database');
  return `db:${args.table}/${args.key}`;
}

export function uiResource(args) {
  if (!exact(args, ['root', 'text']) || !/^#[a-zA-Z][a-zA-Z0-9_-]*$/.test(args.root) ||
      typeof args.text !== 'string') throw Error('invalid_ui');
  return `ui:${args.root}`;
}

export function createReceiptBoundAdapter({ tool, effect, policy, policyEpoch, secret, resolveTarget,
  authorize, execute, nonce = () => crypto.randomBytes(16).toString('hex') } = {}) {
  if (!nonempty(tool) || !nonempty(effect) || typeof policy !== 'function' ||
      (policyEpoch !== undefined && typeof policyEpoch !== 'function') ||
      !Buffer.isBuffer(secret) || secret.length < 32 ||
      typeof resolveTarget !== 'function' || typeof execute !== 'function' ||
      typeof nonce !== 'function') throw TypeError('host adapter configuration required');
  const issued = new Map();
  const seenNonces = new Set();
  const mac = digest => crypto.createHmac('sha256', secret).update(digest).digest('hex');
  const readEpoch = () => {
    const value = policyEpoch();
    if (!Number.isSafeInteger(value) || value < 0) throw TypeError('invalid_policy_epoch');
    return value;
  };
  const authenticate = receipt => {
    try {
      if (!receipt || typeof receipt !== 'object' || !/^[0-9a-f]{64}$/.test(receipt.receipt_sha256) ||
          !/^[0-9a-f]{64}$/.test(receipt.host_mac_sha256)) return false;
      const { receipt_sha256, host_mac_sha256, ...body } = receipt;
      if (hash(body) !== receipt_sha256) return false;
      return crypto.timingSafeEqual(Buffer.from(mac(receipt_sha256), 'hex'),
        Buffer.from(host_mac_sha256, 'hex'));
    } catch { return false; }
  };
  async function issue(proposal) {
    const frozen = copy(proposal);
    const initialEpoch = policyEpoch === undefined ? undefined : readEpoch();
    const hostPolicy = copy(policy());
    const policySha = hash(hostPolicy);
    const plan = planAction(frozen, hostPolicy);
    const proposalSha = hash(frozen);
    let target = null;
    try { target = resolveTarget(copy(frozen.arguments)); } catch { /* fail closed */ }
    let decision = 'SUPPRESS';
    let reason = target !== frozen.resource ? 'target_mismatch_or_invalid' : plan.reason;
    if (frozen.tool !== tool || frozen.effect !== effect) reason = 'wrong_adapter';
    else if (target === frozen.resource && plan.decision === 'allow') {
      decision = 'ALLOW'; reason = 'exact_rule';
    } else if (target === frozen.resource && plan.decision === 'requires_approval' &&
               typeof authorize === 'function') {
      let grant;
      try { grant = await authorize({ proposal: copy(frozen), proposal_sha256: proposalSha }); }
      catch { /* fail closed */ }
      if (grant?.approved === true && grant.proposal_sha256 === proposalSha) {
        decision = 'ALLOW'; reason = 'approved_exact_rule';
      } else reason = 'approval_missing_or_mismatched';
    }
    if (decision === 'ALLOW') {
      // An approval can outlive the rule or host destination mapping it saw.
      // Recheck both immediately before minting a usable receipt.
      let currentTarget;
      try { currentTarget = resolveTarget(copy(frozen.arguments)); }
      catch { currentTarget = null; }
      if (currentTarget !== target || currentTarget !== frozen.resource) {
        decision = 'SUPPRESS'; reason = 'target_changed';
      } else {
        let currentPolicy;
        try { currentPolicy = copy(policy()); } catch { /* fail closed */ }
        if (!currentPolicy || hash(currentPolicy) !== policySha) {
          decision = 'SUPPRESS'; reason = 'policy_changed';
        }
      }
      if (decision === 'ALLOW' && policyEpoch !== undefined) {
        let currentEpoch;
        try { currentEpoch = readEpoch(); } catch { /* fail closed */ }
        if (currentEpoch !== initialEpoch) {
          decision = 'SUPPRESS'; reason = 'policy_epoch_changed';
        }
      }
    }
    const token = nonce();
    assert.ok(nonempty(token) && !seenNonces.has(token), 'nonce must be unique');
    seenNonces.add(token);
    const body = { protocol: 'aml-host-action-authorization/1', nonce: token,
      proposal: frozen, proposal_sha256: proposalSha, host_policy: hostPolicy,
      policy_sha256: policySha,
      ...(policyEpoch === undefined ? {} : { policy_epoch: initialEpoch }),
      plan, resolved_target: target, decision, reason };
    const receiptSha = hash(body);
    const receipt = { ...body, receipt_sha256: receiptSha, host_mac_sha256: mac(receiptSha) };
    if (decision === 'ALLOW') issued.set(token, { receiptSha, proposal: copy(frozen) });
    return receipt;
  }
  async function dispatch(receipt, candidateProposal) {
    if (!authenticate(receipt)) return blocked('invalid_receipt');
    if (receipt.decision !== 'ALLOW') return blocked('receipt_suppressed');
    const registered = issued.get(receipt.nonce);
    if (!registered || registered.receiptSha !== receipt.receipt_sha256) return blocked('receipt_reused_or_unknown');
    let candidate;
    try { candidate = copy(candidateProposal); } catch { return blocked('proposal_mismatch'); }
    if (hash(candidate) !== receipt.proposal_sha256 ||
        hash(registered.proposal) !== receipt.proposal_sha256) return blocked('proposal_mismatch');
    let currentPolicy;
    try { currentPolicy = copy(policy()); }
    catch { issued.delete(receipt.nonce); return blocked('policy_changed'); }
    if (hash(currentPolicy) !== receipt.policy_sha256 ||
        JSON.stringify(planAction(candidate, currentPolicy)) !== JSON.stringify(receipt.plan)) {
      issued.delete(receipt.nonce);
      return blocked('policy_changed');
    }
    let actualTarget;
    try { actualTarget = resolveTarget(candidate.arguments); }
    catch { issued.delete(receipt.nonce); return blocked('target_mismatch'); }
    if (actualTarget !== candidate.resource || actualTarget !== receipt.resolved_target ||
        candidate.tool !== tool || candidate.effect !== effect) {
      issued.delete(receipt.nonce);
      return blocked('target_mismatch');
    }
    if (policyEpoch !== undefined) {
      let currentEpoch;
      try { currentEpoch = readEpoch(); }
      catch { issued.delete(receipt.nonce); return blocked('policy_epoch_unavailable'); }
      if (currentEpoch !== receipt.policy_epoch) {
        issued.delete(receipt.nonce);
        return blocked('policy_epoch_changed');
      }
    }
    // Consume before calling the provider: a throw can follow a partial effect.
    issued.delete(receipt.nonce);
    try { return { decision: 'ALLOW', status: 'DISPATCHED', callback_count: 1,
      result: await execute(copy(registered.proposal.arguments)) }; }
    catch { return { decision: 'ALLOW', status: 'UNKNOWN', reason: 'callback_error', callback_count: 1 }; }
  }
  return { issue, dispatch };
}

export function createEmailAdapter({ provider, ...host }) {
  if (typeof provider?.send !== 'function') throw TypeError('host mail provider required');
  return createReceiptBoundAdapter({ ...host, tool: 'send_email', effect: 'send',
    resolveTarget: mailResource, execute: args => provider.send(args) });
}
export function createHttpAdapter({ fetchImpl, ...host }) {
  if (typeof fetchImpl !== 'function') throw TypeError('host fetch required');
  return createReceiptBoundAdapter({ ...host, tool: 'http_request', effect: 'write',
    resolveTarget: httpResource, execute: args => fetchImpl(args.url,
      { method: args.method, headers: args.headers, body: args.body ?? undefined, redirect: 'manual' }) });
}
export function createDatabaseAdapter({ database, ...host }) {
  if (typeof database?.put !== 'function') throw TypeError('host database required');
  return createReceiptBoundAdapter({ ...host, tool: 'database_write', effect: 'write',
    resolveTarget: databaseResource, execute: args => database.put(args.table, args.key, args.value) });
}
export function createUiAdapter({ renderer, ...host }) {
  if (typeof renderer?.setText !== 'function') throw TypeError('host renderer required');
  return createReceiptBoundAdapter({ ...host, tool: 'render_ui', effect: 'write',
    resolveTarget: uiResource, execute: args => renderer.setText(args.root, args.text) });
}
