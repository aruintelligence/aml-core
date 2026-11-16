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

predicate guardSink(DataFlow::Node n) {
  exists(IfStmt i, Stmt s | n.asExpr() = i.getCond() and s.getParent*() = i.getThen() and privilegedStmt(s))
}

predicate decisionStep(DataFlow::Node pred, DataFlow::Node succ) {
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

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module VerificationFlow = TaintTracking::Global<VerificationConfig>;

module AuthorizationFlow = TaintTracking::Global<AuthorizationConfig>;

from DataFlow::Node source, DataFlow::Node sink, string name
where
  VerificationFlow::flow(source, sink) and
  fieldRead(source, name) and
  name = verificationField() and
  not AuthorizationFlow::flowTo(sink)
select sink,
  "Success outcome depends on verification field '" + name +
    "' ($@) without an explicit authorization decision.", source, name
