# 20-Post ĀML Launch Pack

**Status: PITCH — ready to publish externally**

1. AI can generate interfaces faster than humans can review them. ĀML adds an interface firewall before pixels. Try the proof: https://aruintelligence.github.io/aml-core/proof.html

2. Change one number. Watch the same interface go from SUPPRESS to ALLOW. That is the shortest ĀML demo: https://aruintelligence.github.io/aml-core/proof.html

3. The interesting part of ĀML is not a score. It is that the decision leaves a receipt you can inspect afterward. View Meaning: https://aruintelligence.github.io/aml-core/view-meaning.html

4. HTML tells the browser what to display. ĀML asks why an interface element deserves to be displayed.

5. Generated UI needs a review layer that understands declared purpose, not only code validity.

6. ĀML does not replace React. It can wrap existing HTML with `<aml-gate>` and make a render decision before the user sees it.

7. Keep your DOM. Add meaning with `data-aml-*`. Existing-HTML demo: https://aruintelligence.github.io/aml-core/dom-gate-demo.html

8. A dark pattern should not become unreviewable just because an AI generated it 30 milliseconds ago. Gallery: https://aruintelligence.github.io/aml-core/gallery.html

9. ĀML now has five public ALLOW fixtures and five SUPPRESS fixtures. A useful firewall has to know when not to block.

10. The proof is shareable by exact state. Send someone the same declared scores and reproduce the same decision.

11. The public AML verifier contract is pinned to an immutable Git commit. Compatibility should mean exact bytes, not vibes.

12. Python and Go reference verifiers consume the same public witness contract without importing the JavaScript verifier.

13. ĀML keeps an external witness registry at zero until somebody outside the project actually reproduces it. No fake adoption.

14. Meaning Gate asks a pull request question ordinary code review often misses: did the interface become materially more demanding or less accountable?

15. View Source helped us inspect code. View Meaning explores how to inspect declared interface intent.

16. A cryptographic hash can prove a receipt changed. It cannot prove the declared purpose was truthful. AML documents that boundary explicitly.

17. ĀML is a working research prototype, not a ratified global standard. The fastest way to make it stronger is to break it publicly.

18. Want to challenge AML? Implement the verifier contract in another runtime and run the black-box harness: https://github.com/aruintelligence/aml-core/blob/main/VERIFY.md

19. AI-generated interfaces should eventually be able to answer: what did you mean, what rule judged you, and why did the human see this?

20. Don't trust the pitch. Open the proof. Change `restoration_value`. Screenshot the decision and receipt. File what happened: https://aruintelligence.github.io/aml-core/proof.html
