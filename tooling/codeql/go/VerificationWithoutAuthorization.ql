/**
 * @name Verification result used as permission without an authorization decision
 * @description An exit status of 0 or a guarded privileged call depends on a
 *              verification field (`Valid`, `Verified`, `Accepted`,
 *              `QuorumMet`, `Official`, ...) through aliases or wrapper
 *              functions, and no `Authorized` decision reaches the same
 *              outcome. Directive 010 invariant.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id aml/go/verification-without-authorization
 * @tags security
 *       external/cwe/cwe-285
 */

import go

string verificationField() {
  result =
    [
      "Valid", "Verified", "Accepted", "QuorumMet", "Official", "ClaimVerified", "Consistent",
      "SignatureValid", "ThresholdMet", "RequestedConditionsMet", "IntegrityValid", "valid",
      "verified", "accepted", "quorum_met", "official"
    ]
}

predicate fieldRead(DataFlow::Node n, string name) {
  exists(DataFlow::FieldReadNode r | n = r and r.getField().getName() = name)
  or
  exists(IndexExpr ix | n.asExpr() = ix and ix.getIndex().getStringValue() = name)
  or
  // reflect.ValueOf(r).FieldByName("Valid") (and .Bool() on it via taint)
  exists(DataFlow::MethodCallNode c | n = c and c.getTarget().getName() = "FieldByName" and
    c.getArgument(0).getStringValue() = name)
}

predicate exitSink(DataFlow::Node n) {
  exists(DataFlow::CallNode c | c.getTarget().hasQualifiedName("os", "Exit") and n = c.getArgument(0))
}

/** A statement that grants: os.Exit(0), `return ..., 0`, or a privileged call. */
predicate privilegedStmt(Stmt s) {
  exists(CallExpr c | c = s.(ExprStmt).getExpr() |
    c.getTarget().hasQualifiedName("os", "Exit") and c.getArgument(0).getIntValue() = 0
    or
    c.getTarget().getName().regexpMatch("(?i)(execute|exec|run|deploy|release|publish|spawn|apply|merge|grant|perform)\\w*")
  )
  or
  exists(ReturnStmt r | r = s and r.getNumExpr() > 0 and r.getExpr(r.getNumExpr() - 1).getIntValue() = 0)
}

/** An `if` whose then-branch contains a privileged statement. */
predicate guardingIf(IfStmt i) { exists(Stmt s | s.getParent*() = i.getThen() and privilegedStmt(s)) }

/** The non-logical operands of a condition (`a`, `b`, `c` in `a && (b || !c)`). */
Expr atom(Expr e) {
  not e instanceof LogicalBinaryExpr and not e instanceof NotExpr and not e instanceof ParenExpr and result = e
  or
  result = atom(e.(LogicalBinaryExpr).getAnOperand())
  or
  result = atom(e.(NotExpr).getOperand())
  or
  result = atom(e.(ParenExpr).getExpr())
}

/** An operand that must hold for the condition to hold (reached through `&&` and parentheses only). */
Expr conjunct(Expr e) {
  result = e
  or
  result = conjunct(e).(LandExpr).getAnOperand()
  or
  result = conjunct(e).(ParenExpr).getExpr()
}

/**
 * Each operand of a guarding condition is a sink: Go lowers `&&`/`||` to
 * control flow, so the whole condition has no single data-flow node.
 */
predicate guardSink(DataFlow::Node n) {
  exists(IfStmt i | guardingIf(i) and n.asExpr() = atom(i.getCond()))
}

predicate decisionStep(DataFlow::Node pred, DataFlow::Node succ) {
  // reflect.Value accessors: v.FieldByName("Valid").Bool()
  exists(DataFlow::MethodCallNode c |
    c.getReceiver().getType().hasQualifiedName("reflect", "Value") and
    c.getTarget().getName() = ["Bool", "Interface", "Int", "String"] and
    pred = c.getReceiver() and succ = c
  )
  or
  exists(NotExpr e | pred.asExpr() = e.getOperand() and succ.asExpr() = e)
  or
  exists(EqualityTestExpr e | pred.asExpr() = e.getAnOperand() and succ.asExpr() = e)
  or
  exists(LogicalBinaryExpr e | pred.asExpr() = e.getAnOperand() and succ.asExpr() = e)
}

module VerificationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldRead(n, verificationField()) }

  predicate isSink(DataFlow::Node n) { exitSink(n) or guardSink(n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module AuthorizationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldRead(n, ["Authorized", "authorized"]) }

  predicate isSink(DataFlow::Node n) { exitSink(n) or guardSink(n) }

  // `x || authorized` does not make x conditional on authorization.
  predicate isBarrier(DataFlow::Node n) { n.asExpr() instanceof LorExpr }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module VerificationFlow = TaintTracking::Global<VerificationConfig>;

module AuthorizationFlow = TaintTracking::Global<AuthorizationConfig>;

predicate unauthorizedOutcome(DataFlow::Node source, DataFlow::Node sink) {
  // exit statuses
  exitSink(sink) and
  VerificationFlow::flow(source, sink) and
  not AuthorizationFlow::flowTo(sink)
  or
  // a guarding condition: some operand carries verification and no operand
  // that must hold (an `&&` conjunct, not an `||` alternative or a negation)
  // carries the authorization decision
  exists(IfStmt i |
    guardingIf(i) and
    sink.asExpr() = atom(i.getCond()) and
    VerificationFlow::flow(source, sink) and
    not exists(Expr c |
      c = conjunct(i.getCond()) and c = atom(i.getCond()) and AuthorizationFlow::flowTo(DataFlow::exprNode(c))
    )
  )
}

from DataFlow::Node source, DataFlow::Node sink, string name
where
  unauthorizedOutcome(source, sink) and
  fieldRead(source, name) and
  name = verificationField()
select sink,
  "Success outcome depends on verification field '" + name +
    "' ($@) without an explicit authorization decision.", source, name
