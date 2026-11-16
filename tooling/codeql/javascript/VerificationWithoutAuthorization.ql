/**
 * @name Verification result used as permission without an authorization decision
 * @description A success outcome (exit 0, HTTP 2xx, or a guarded privileged
 *              call) depends on a verification field such as `valid`,
 *              `verified`, `accepted`, `quorum_met` or `official`, and no
 *              explicit `authorized` decision reaches the same outcome.
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

/** The test of a branch that guards a privileged call. */
predicate guardSink(DataFlow::Node n) {
  // A whole branch condition. Short-circuit operands of `&&`/`||` get their
  // own guard nodes in the CFG; they are not sinks by themselves, otherwise
  // `if (r.authorized && r.verified)` would be reported on `r.verified`.
  exists(ConditionGuardNode g, DataFlow::CallNode call |
    privilegedCall(call) and
    g.dominates(call.getBasicBlock()) and
    not g.getTest().getParentExpr*() instanceof LogicalBinaryExpr and
    n = g.getTest().flow()
  )
  or
  exists(IfStmt s, DataFlow::CallNode call |
    privilegedCall(call) and
    call.asExpr().getEnclosingStmt().getParentStmt*() = s.getThen() and
    n = s.getCondition().flow()
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
  predicate isSource(DataFlow::Node n) { readName(n) = verificationField() }

  predicate isSink(DataFlow::Node n) { statusSink(n) or guardSink(n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module AuthorizationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { readName(n) = "authorized" }

  predicate isSink(DataFlow::Node n) { statusSink(n) or guardSink(n) }

  // `x || authorized` does not make x conditional on authorization.
  predicate isBarrier(DataFlow::Node n) {
    n.asExpr() instanceof LogicalOrExpr or n.asExpr() instanceof NullishCoalescingExpr
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module VerificationFlow = TaintTracking::Global<VerificationConfig>;

module AuthorizationFlow = TaintTracking::Global<AuthorizationConfig>;

from DataFlow::Node source, DataFlow::Node sink
where
  VerificationFlow::flow(source, sink) and
  not AuthorizationFlow::flowTo(sink)
select sink,
  "Success outcome depends on verification field '" + readName(source) +
    "' ($@) without an explicit authorization decision.", source, readName(source)
