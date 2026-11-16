/**
 * @name Verification result used as permission without an authorization decision
 * @description An exit status of 0 or a guarded privileged call depends on a
 *              verification field (`valid`, `verified`, `accepted`,
 *              `quorum_met`, `official`, ...) and no explicit `authorized`
 *              decision controls the same outcome. Directive 010 invariant.
 *              Fields are tracked through subscripts, `.get`, attributes and
 *              `getattr` with constant (including computed-constant) names.
 *              For a conditional status (`0 if a else 0 if b else 1`) every
 *              success branch is checked separately.
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

/** A read of a field named `name`: `r["name"]`, `r[k]`, `r.get("name")`, `r.name`, `getattr(r, k)`. */
predicate fieldRead(DataFlow::Node n, string name) {
  exists(Call c | n.asExpr() = c and c.getFunc().(Name).getId() = "getattr" and name = constantKey(c.getArg(1)))
  or
  exists(Subscript s | n.asExpr() = s and name = constantKey(s.getIndex()))
  or
  exists(Call c, Attribute a |
    n.asExpr() = c and c.getFunc() = a and a.getName() = "get" and name = constantKey(c.getArg(0))
  )
  or
  exists(Attribute a | n.asExpr() = a and a.getName() = name and a.getCtx() instanceof Load)
}

/** An exit-status expression that can never be 0 (for example `3 if ok else 1`). */
predicate neverZero0(Expr e) {
  e.(IntegerLiteral).getValue() != 0
  or
  // a module-level constant such as EXIT_NOT_AUTHORIZED = 3, assigned once
  exists(string name, Module m | name = e.(Name).getId() and m = e.getEnclosingModule() |
    strictcount(AssignStmt a | a.getATarget().(Name).getId() = name and a.getEnclosingModule() = m) = 1 and
    forall(AssignStmt a | a.getATarget().(Name).getId() = name and a.getEnclosingModule() = m |
      a.getScope() = m and a.getValue().(IntegerLiteral).getValue() != 0
    )
  )
  or
  neverZero0(e.(IfExp).getBody()) and neverZero0(e.(IfExp).getOrelse())
}

/**
 * An exit status that can never be 0, including a call to a same-module
 * function whose every `return` is such a value and that cannot fall off its
 * end (falling off returns None, which exits 0).
 */
predicate neverZero(Expr e) {
  neverZero0(e)
  or
  exists(Function f, Call c | c = e and c.getFunc().(Name).getId() = f.getName() and
    f.getEnclosingModule() = c.getEnclosingModule() and f.getScope() = f.getEnclosingModule() and
    f.getBody().getLastItem() instanceof Return and
    forall(Return r | r.getScope() = f | neverZero0(r.getValue()))
  )
}

predicate exitSink(DataFlow::Node n) {
  exitSink0(n) and not neverZero(n.asExpr())
}

/** `c` is `root` or a conditional expression nested in a branch of one in its chain. */
IfExp chainOf(IfExp root) {
  result = root
  or
  exists(IfExp p | p = chainOf(root) | result = [p.getBody(), p.getOrelse()])
}

/** A branch value of the exit conditional `root` that may be 0. */
Expr successLeaf(IfExp root) {
  exists(IfExp c | c = chainOf(root) |
    result = [c.getBody(), c.getOrelse()] and
    not result instanceof IfExp and
    not neverZero(result)
  )
}

/** `e` decides whether `leaf` is selected: a test on its path, or the leaf itself. */
Expr pathElement(IfExp root, Expr leaf) {
  leaf = successLeaf(root) and
  (
    result = leaf
    or
    exists(IfExp c | c = chainOf(root) and c.getAChildNode+() = leaf |
      result = c.getTest() and not c.getTest().getAChildNode*() = leaf
    )
  )
}

predicate conditionalExit(DataFlow::Node n, IfExp root) {
  exitSink(n) and
  (
    root = n.asExpr()
    or
    // `code = 0 if ok else 1` then `sys.exit(code)`
    exists(DataFlow::Node src | DataFlow::localFlow(src, n) and src != n and root = src.asExpr())
  )
}

predicate pathSink(DataFlow::Node n) {
  exists(IfExp root, Expr leaf | conditionalExit(_, root) and n.asExpr() = pathElement(root, leaf))
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
predicate guardCondition(Expr cond) {
  exists(If i, Stmt top, Stmt s |
    cond = i.getTest() and top = i.getBody().getAnItem() and (s = top or top.contains(s)) and privilegedStmt(s)
  )
}

/** The non-logical operands of a condition (`a`, `b`, `c` in `a and (b or not c)`). */
Expr atom(Expr e) {
  not e instanceof BoolExpr and not (e instanceof UnaryExpr and e.(UnaryExpr).getOp() instanceof Not) and
  result = e
  or
  result = atom(e.(BoolExpr).getAValue())
  or
  exists(UnaryExpr u | u = e and u.getOp() instanceof Not | result = atom(u.getOperand()))
}

/** An operand that must hold for the condition to hold (through `and` only). */
Expr conjunct(Expr e) {
  result = e
  or
  exists(BoolExpr b | b = conjunct(e) and b.getOp() instanceof And | result = b.getAValue())
}

/** Every operand of a guarding condition is a sink; the decision is made per condition below. */
predicate guardSink(DataFlow::Node n) {
  exists(Expr cond | guardCondition(cond) and n.asExpr() = atom(cond))
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

  predicate isSink(DataFlow::Node n) { exitSink(n) or guardSink(n) or pathSink(n) }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module AuthorizationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { fieldRead(n, "authorized") }

  predicate isSink(DataFlow::Node n) { exitSink(n) or guardSink(n) or pathSink(n) }

  // `x or authorized` does not make x conditional on authorization.
  predicate isBarrier(DataFlow::Node n) { n.asExpr().(BoolExpr).getOp() instanceof Or }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) { decisionStep(pred, succ) }
}

module VerificationFlow = TaintTracking::Global<VerificationConfig>;

module AuthorizationFlow = TaintTracking::Global<AuthorizationConfig>;

predicate unauthorizedOutcome(DataFlow::Node source, DataFlow::Node sink) {
  exitSink(sink) and
  VerificationFlow::flow(source, sink) and
  not conditionalExit(sink, _) and
  not AuthorizationFlow::flowTo(sink)
  or
  // a guarding condition: some operand carries verification and no operand
  // that must hold (an `and` conjunct, not an `or` alternative or a negation)
  // carries the authorization decision
  exists(Expr cond |
    guardCondition(cond) and
    sink.asExpr() = atom(cond) and
    VerificationFlow::flow(source, sink) and
    not exists(Expr c |
      c = conjunct(cond) and c = atom(cond) and AuthorizationFlow::flowTo(DataFlow::exprNode(c))
    )
  )
  or
  exists(IfExp root, Expr leaf |
    conditionalExit(sink, root) and
    VerificationFlow::flow(source, DataFlow::exprNode(pathElement(root, leaf))) and
    not exists(Expr e | e = pathElement(root, leaf) and AuthorizationFlow::flowTo(DataFlow::exprNode(e)))
  )
}

from DataFlow::Node source, DataFlow::Node sink, string name
where
  unauthorizedOutcome(source, sink) and
  fieldRead(source, name) and
  name = verificationField() and
  // a literal status that cannot be 0 is not a success outcome
  not sink.asExpr().(IntegerLiteral).getValue() != 0
select sink,
  "Success outcome depends on verification field '" + name +
    "' ($@) without an explicit authorization decision.", source, name
