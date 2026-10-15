// Compatibility names for the original pilot. New integrations import from aml-core.
export {
  applyLockedHttpDecision as applyVerifiedDecision,
  evaluateLockedHttpAndRender as evaluateAndGate
} from "../../runtime/lockedHttpRenderGate.js";
