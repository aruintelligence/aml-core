/**
 * @name Verification result used as permission without an authorization decision
 * @description A success outcome (exit 0, HTTP 2xx, or a guarded privileged
 *              call) depends on a verification field such as `valid`,
 *              `verified`, `accepted`, `quorum_met` or `official`, and no
 *              explicit `authorized` decision controls the same outcome.
 *              Fields are tracked through property reads (including
 *              constant computed names), `Reflect.get`, and `Map` set/get.
 *              For a conditional status (`a ? 0 : b ? 0 : 1`) every success
 *              branch is checked separately: an `authorized` read on a
 *              different branch does not control it.
 *              Directive 010 invariant: verification is a precondition,
 *              never permission.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id aml/js/verification-without-authorization
 * @tags security
 *       external/cwe/cwe-285
 */

import javascript

/** Field names that report verification or consistency only. */
string verificationField() {
  result =
    [
      "valid", "verified", "accepted", "quorum_met", "official", "claim_verified", "consistent",
      "signature_valid", "signatureValid", "threshold_met", "requested_conditions_met",
      "integrity_valid", "witness_met", "policy_met"
    ]
}

/** A constant string an expression evaluates to: literals, `+` of constants, and locally flowing values. */
string constantString(Expr e) {
  result = e.getStringValue()
  or
  result = constantString(e.(AddExpr).getLeftOperand()) + constantString(e.(AddExpr).getRightOperand())
  or
  result = constantString(e.(ParExpr).getExpression())
  or
  exists(DataFlow::Node src | src = e.flow().getALocalSource() and src.asExpr() != e |
    result = constantString(src.asExpr())
  )
  or
  // a variable with exactly one assigned value (covers script-scope globals)
  exists(Variable v | v = e.(VarAccess).getVariable() and strictcount(v.getAnAssignedExpr()) = 1 |
    result = constantString(v.getAnAssignedExpr())
  )
}

/** The constant property name of `read`, including computed names such as `r[k]` with a constant `k`. */
string readName(DataFlow::PropRead read) {
  result = read.getPropertyName()
  or
  not exists(read.getPropertyName()) and
  result = constantString(read.getPropertyNameExpr())
}

/**
 * `n` reads the field `name`: `r.name`, `r[k]` with a constant `k`, or
 * `Reflect.get(r, k)` with a constant `k`.
 */
string fieldName(DataFlow::Node n) {
  result = readName(n)
  or
  exists(DataFlow::CallNode c | c = n and
    c = DataFlow::globalVarRef("Reflect").getAMemberCall("get") and
    result = constantString(c.getArgument(1).asExpr())
  )
}

/** Two `Map` keys that may be equal (equal constants, or either unknown). */
bindingset[a, b]
predicate mayBeSameKey(Expr a, Expr b) {
  constantString(a) = constantString(b)
  or
  not exists(constantString(a))
  or
  not exists(constantString(b))
}

/** `m.set(k, v)` flows `v` to every `m.get(k')` on the same local map whose key may equal `k`. */
predicate mapStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(DataFlow::MethodCallNode set, DataFlow::MethodCallNode get, DataFlow::SourceNode map |
    set.getMethodName() = "set" and get.getMethodName() = "get" and
    (
      set.getReceiver().getALocalSource() = map and get.getReceiver().getALocalSource() = map
      or
      // script-scope `const m = new Map()` is a global variable, not a local source
      map = set.getReceiver() and
      set.getReceiver().asExpr().(VarAccess).getVariable() = get.getReceiver().asExpr().(VarAccess).getVariable()
    ) and
    mayBeSameKey(set.getArgument(0).asExpr(), get.getArgument(0).asExpr()) and
    pred = set.getArgument(1) and succ = get
  )
}

/** A privileged call that a guard may gate. */
predicate privilegedCall(DataFlow::CallNode call) {
  call.getCalleeName().regexpMatch("(?i)(execute|exec|run|deploy|release|publish|spawn|apply|merge|grant|perform)\\w*")
  or
  call = DataFlow::globalVarRef("process").getAMemberCall("exit") and
  call.getArgument(0).asExpr().getIntValue() = 0
}

/** A status expression that can never be a success (exit 0 or HTTP 2xx). */
predicate neverSuccess(Expr e) {
  exists(int v | v = e.getIntValue() | v != 0 and (v < 200 or v > 299))
  or
  neverSuccess(e.(ConditionalExpr).getConsequent()) and neverSuccess(e.(ConditionalExpr).getAlternate())
  or
  neverSuccess(e.(ParExpr).getExpression())
}

/** `n` produces an exit status or an HTTP status that may be a success. */
predicate statusSink(DataFlow::Node n) {
  statusSink0(n) and not neverSuccess(n.asExpr())
}

Expr stripParens(Expr e) {
  if e instanceof ParExpr then result = stripParens(e.(ParExpr).getExpression()) else result = e
}

/** `c` is `root` or a conditional nested in a branch of a conditional in its chain. */
ConditionalExpr chainOf(ConditionalExpr root) {
  result = root
  or
  exists(ConditionalExpr p | p = chainOf(root) |
    result = stripParens([p.getConsequent(), p.getAlternate()])
  )
}

/** A branch result of the status conditional `root` that may be a success. */
Expr successLeaf(ConditionalExpr root) {
  exists(ConditionalExpr c | c = chainOf(root) |
    result = stripParens([c.getConsequent(), c.getAlternate()]) and
    not result instanceof ConditionalExpr and
    not neverSuccess(result)
  )
}

/** `e` decides whether `leaf` is selected: a condition on its path, or the leaf itself. */
Expr pathElement(ConditionalExpr root, Expr leaf) {
  leaf = successLeaf(root) and
  (
    result = leaf
    or
    exists(ConditionalExpr c | c = chainOf(root) and leaf.getParentExpr+() = c |
      result = c.getCondition() and not leaf.getParentExpr*() = c.getCondition()
    )
  )
}

/** A status conditional sink, analysed per success branch rather than as a whole. */
predicate conditionalStatus(DataFlow::Node n, ConditionalExpr root) {
  statusSink(n) and
  (
    root = stripParens(n.asExpr())
    or
    // `const code = c ? 0 : 1; process.exit(code)`
    root = stripParens(n.getALocalSource().asExpr())
  )
}

predicate pathSink(DataFlow::Node n) {
  exists(ConditionalExpr root, Expr leaf | conditionalStatus(_, root) and n = pathElement(root, leaf).flow())
}

predicate statusSink0(DataFlow::Node n) {
  n = DataFlow::globalVarRef("process").getAMemberCall("exit").getArgument(0)
  or
  n = DataFlow::globalVarRef("process").getAPropertyWrite("exitCode").getRhs()
  or
  exists(DataFlow::CallNode send | send.getCalleeName() = "send" and n = send.getArgument(1))
  or
  exists(DataFlow::MethodCallNode m |
    m.getMethodName() = ["writeHead", "status", "sendStatus"] and n = m.getArgument(0)
  )
  or
  exists(DataFlow::PropWrite w | w.getPropertyName() = "statusCode" and n = w.getRhs())
}

/** The whole test of a branch that guards a privileged call. */
predicate guardCondition(Expr cond) {
  // A whole branch condition. Short-circuit operands of `&&`/`||` get their
  // own guard nodes in the CFG; they are not conditions by themselves.
  exists(ConditionGuardNode g, DataFlow::CallNode call |
    privilegedCall(call) and
    g.dominates(call.getBasicBlock()) and
    not g.getTest().getParentExpr*() instanceof LogicalBinaryExpr and
    cond = g.getTest()
  )
  or
  exists(IfStmt s, DataFlow::CallNode call |
    privilegedCall(call) and
    call.asExpr().getEnclosingStmt().getParentStmt*() = s.getThen() and
    cond = s.getCondition()
  )
}

/** The non-logical operands of a condition (`a`, `b`, `c` in `a && (b || !c)`). */
Expr atom(Expr e) {
  not e instanceof LogicalBinaryExpr and not e instanceof LogNotExpr and not e instanceof ParExpr and
  result = e
  or
  result = atom([e.(LogicalBinaryExpr).getAnOperand(), e.(LogNotExpr).getOperand(), e.(ParExpr).getExpression()])
}

/** An operand that must hold for the condition to hold (through `&&` and parentheses only). */
Expr conjunct(Expr e) {
  result = e
  or
  result = conjunct(e).(LogAndExpr).getAnOperand()
  or
  result = conjunct(e).(ParExpr).getExpression()
}

/** Every operand of a guarding condition is a sink; the decision is made per condition below. */
predicate guardSink(DataFlow::Node n) {
  exists(Expr cond | guardCondition(cond) and n = atom(cond).flow())
}

/** `e` reads the `authorized` decision directly or through a local alias. */
predicate authorizationRead(Expr e) {
  fieldName(e.flow()) = "authorized"
  or
  exists(DataFlow::SourceNode src | src = e.flow().getALocalSource() and src != e.flow() and fieldName(src) = "authorized")
}

/** `test` evaluating to `outcome` implies that `authorized` is true (simple, polarity-aware forms only). */
predicate authorizesOn(Expr test, boolean outcome) {
  authorizationRead(test) and outcome = true
  or
  exists(EqualityTest eq | eq = test |
    eq.getAnOperand().(BooleanLiteral).getValue() = "true" and
    authorizesOn(eq.getAnOperand(), true) and
    outcome = eq.getPolarity()
  )
  or
  authorizesOn(test.(LogNotExpr).getOperand(), outcome.booleanNot())
  or
  authorizesOn(test.(ParExpr).getExpression(), outcome)
  or
  outcome = true and authorizesOn(test.(LogAndExpr).getAnOperand(), true)
}

/**
 * `n` is only reached after a branch on which `authorized` is true, e.g.
 * after `if (r.authorized !== true) return deny();`.
 */
predicate dominatedByAuthorization(DataFlow::Node n) {
  exists(ConditionGuardNode g |
    g.dominates(n.getBasicBlock()) and authorizesOn(g.getTest(), g.getOutcome())
  )
}

/** Taint steps that a boolean decision travels through. */
predicate decisionStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(ConditionalExpr c | pred = c.getCondition().flow() and succ = c.flow())
  or
  exists(LogNotExpr e | pred = e.getOperand().flow() and succ = e.flow())
  or
  exists(EqualityTest e | pred = e.getAnOperand().flow() and succ = e.flow())
  or
  exists(LogicalBinaryExpr e | pred = e.getAnOperand().flow() and succ = e.flow())
  or
  exists(DataFlow::CallNode c | c = DataFlow::globalVarRef("Boolean").getACall() and
    pred = c.getArgument(0) and succ = c)
}

module VerificationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldName(n) = verificationField() }

  predicate isSink(DataFlow::Node n) { statusSink(n) or guardSink(n) or pathSink(n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    decisionStep(pred, succ) or mapStep(pred, succ)
  }
}

module AuthorizationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldName(n) = "authorized" }

  predicate isSink(DataFlow::Node n) { statusSink(n) or guardSink(n) or pathSink(n) }

  // `x || authorized` does not make x conditional on authorization.
  predicate isBarrier(DataFlow::Node n) {
    n.asExpr() instanceof LogicalOrExpr or n.asExpr() instanceof NullishCoalescingExpr
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    decisionStep(pred, succ) or mapStep(pred, succ)
  }
}

module VerificationFlow = TaintTracking::Global<VerificationConfig>;

module AuthorizationFlow = TaintTracking::Global<AuthorizationConfig>;

/**
 * `sink` is a success outcome that verification reaches without an
 * authorization decision controlling it.
 */
predicate unauthorizedOutcome(DataFlow::Node source, DataFlow::Node sink) {
  // a whole, non-conditional status
  statusSink(sink) and
  VerificationFlow::flow(source, sink) and
  not conditionalStatus(sink, _) and
  not AuthorizationFlow::flowTo(sink)
  or
  // a guarding condition: some operand carries verification and no operand
  // that must hold (an `&&` conjunct, not an `||` alternative or a negation)
  // carries the authorization decision
  exists(Expr cond |
    guardCondition(cond) and
    sink = atom(cond).flow() and
    VerificationFlow::flow(source, sink) and
    not exists(Expr c | c = conjunct(cond) and c = atom(cond) and AuthorizationFlow::flowTo(c.flow()))
  )
  or
  // a conditional status: some success branch is selected by verification
  // while no condition on that branch's path (nor the branch value) carries
  // the authorization decision
  exists(ConditionalExpr root, Expr leaf |
    conditionalStatus(sink, root) and
    VerificationFlow::flow(source, pathElement(root, leaf).flow()) and
    not exists(Expr e | e = pathElement(root, leaf) and AuthorizationFlow::flowTo(e.flow()))
  )
}

from DataFlow::Node source, DataFlow::Node sink
where
  unauthorizedOutcome(source, sink) and
  // an authorization check that dominates the outcome controls it
  not dominatedByAuthorization(sink)
select sink,
  "Success outcome depends on verification field '" + fieldName(source) +
    "' ($@) without an explicit authorization decision.", source, fieldName(source)
