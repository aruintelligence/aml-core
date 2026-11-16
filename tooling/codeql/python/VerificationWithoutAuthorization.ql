/**
 * @name Verification result used as permission without an authorization decision
 * @description An exit status of 0 or a guarded privileged call depends on a
 *              verification field (`valid`, `verified`, `accepted`,
 *              `quorum_met`, `official`, ...) and no explicit `authorized`
 *              decision reaches the same outcome. Directive 010 invariant.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id aml/py/verification-without-authorization
 * @tags security
 *       external/cwe/cwe-285
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

string verificationField() {
  result =
    [
      "valid", "verified", "accepted", "quorum_met", "official", "claim_verified", "consistent",
      "signature_valid", "threshold_met", "requested_conditions_met", "integrity_valid",
      "witness_met", "policy_met"
    ]
}

/** A constant string key, including one held in a local variable or built by `+`. */
string constantKey(Expr e) {
  result = e.(StringLiteral).getText()
  or
  exists(BinaryExpr b | b = e and b.getOp() instanceof Add |
    result = constantKey(b.getLeft()) + constantKey(b.getRight())
  )
  or
  exists(DataFlow::Node src | DataFlow::localFlow(src, DataFlow::exprNode(e)) and src != DataFlow::exprNode(e) |
    result = constantKey(src.asExpr())
  )
}

/** A read of a field named `name`: `r["name"]`, `r[k]`, `r.get("name")`, `r.name`. */
predicate fieldRead(DataFlow::Node n, string name) {
  exists(Subscript s | n.asExpr() = s and name = constantKey(s.getIndex()))
  or
  exists(Call c, Attribute a |
    n.asExpr() = c and c.getFunc() = a and a.getName() = "get" and name = constantKey(c.getArg(0))
  )
  or
  exists(Attribute a | n.asExpr() = a and a.getName() = name and a.getCtx() instanceof Load)
}

/** An exit-status expression that can never be 0 (for example `3 if ok else 1`). */
predicate neverZero(Expr e) {
  e.(IntegerLiteral).getValue() != 0
  or
  neverZero(e.(IfExp).getBody()) and neverZero(e.(IfExp).getOrelse())
}

predicate exitSink(DataFlow::Node n) {
  exitSink0(n) and not neverZero(n.asExpr())
}

predicate exitSink0(DataFlow::Node n) {
  n = API::moduleImport("sys").getMember("exit").getACall().getArg(0)
  or
  exists(Raise r, Call c | r.getException() = c and c.getFunc().(Name).getId() = "SystemExit" and
    n.asExpr() = c.getArg(0))
  or
  // `return <status>` from a function named main
  exists(Return r | r.getScope().(Function).getName() = "main" and n.asExpr() = r.getValue())
}

predicate privilegedStmt(Stmt s) {
  exists(Call c | c = s.(ExprStmt).getValue() |
    c.getFunc().(Name).getId().regexpMatch("(?i)(execute|exec|run|deploy|release|publish|spawn|apply|merge|grant|perform)\\w*")
    or
    c.getFunc().(Attribute).getName().regexpMatch("(?i)(execute|exec|run|deploy|release|publish|spawn|apply|merge|grant|perform)\\w*")
  )
  or
  s.(Return).getValue().(IntegerLiteral).getValue() = 0
}

/** The test of an `if` whose body contains a privileged statement. */
predicate guardSink(DataFlow::Node n) {
  exists(If i, Stmt top, Stmt s |
    n.asExpr() = i.getTest() and top = i.getBody().getAnItem() and (s = top or top.contains(s)) and privilegedStmt(s)
  )
}

predicate decisionStep(DataFlow::Node pred, DataFlow::Node succ) {
  exists(IfExp e | pred.asExpr() = e.getTest() and succ.asExpr() = e)
  or
  exists(UnaryExpr u | u.getOp() instanceof Not and pred.asExpr() = u.getOperand() and succ.asExpr() = u)
  or
  exists(Compare c | pred.asExpr() = c.getAChildNode() and succ.asExpr() = c)
  or
  exists(BoolExpr b | pred.asExpr() = b.getAValue() and succ.asExpr() = b)
  or
  exists(Call c | c.getFunc().(Name).getId() = "bool" and pred.asExpr() = c.getArg(0) and succ.asExpr() = c)
}

module VerificationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldRead(n, verificationField()) }

  predicate isSink(DataFlow::Node n) { exitSink(n) or guardSink(n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module AuthorizationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldRead(n, "authorized") }

  predicate isSink(DataFlow::Node n) { exitSink(n) or guardSink(n) }

  // `x or authorized` does not make x conditional on authorization.
  predicate isBarrier(DataFlow::Node n) { n.asExpr().(BoolExpr).getOp() instanceof Or }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module VerificationFlow = TaintTracking::Global<VerificationConfig>;

module AuthorizationFlow = TaintTracking::Global<AuthorizationConfig>;

from DataFlow::Node source, DataFlow::Node sink, string name
where
  VerificationFlow::flow(source, sink) and
  fieldRead(source, name) and
  name = verificationField() and
  not AuthorizationFlow::flowTo(sink) and
  // a literal status that cannot be 0 is not a success outcome
  not sink.asExpr().(IntegerLiteral).getValue() != 0
select sink,
  "Success outcome depends on verification field '" + name +
    "' ($@) without an explicit authorization decision.", source, name
