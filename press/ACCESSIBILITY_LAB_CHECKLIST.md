# ĀML Live Lab Accessibility Checklist

**Status: DRAFT — requires independent accessibility review**

- [ ] Entire playground usable by keyboard only.
- [ ] Visible focus indicator on every interactive control.
- [ ] Logical tab order.
- [ ] No keyboard trap in editor, dialogs, or receipt inspector.
- [ ] Page landmarks and headings form a logical hierarchy.
- [ ] Form controls have explicit accessible names.
- [ ] Compile/suppress/verify state is announced without relying only on color.
- [ ] Error text is programmatically associated with the relevant control.
- [ ] Text remains usable at 200% zoom.
- [ ] Layout works at narrow mobile widths without horizontal scrolling for core tasks.
- [ ] Reduced-motion preference disables nonessential motion.
- [ ] Contrast is manually checked, not assumed from declared AML metadata.
- [ ] Code examples remain readable in high contrast modes.
- [ ] Receipt output can be navigated with screen-reader reading order.
- [ ] RTL layout is tested independently for Arabic strings.
- [ ] Language changes set the correct document language.
- [ ] Buttons use verbs: Compile, Verify, View Meaning.
- [ ] Suppressed content has a text explanation.
- [ ] Demo can be completed without drag, hover, or precise pointer movement.
- [ ] Real assistive-technology testing is documented separately.

This checklist is supplemental. Passing it does not establish WCAG conformance.

Open the demo. Change `restoration_value`. Screenshot the decision and receipt. File it.
