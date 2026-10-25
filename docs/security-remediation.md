# Production security remediation

These changes intentionally replace vulnerable training behavior with production controls.

The PR sequence is:

1. Identity and SQL: rotate the bundled JWT signing authority, restrict algorithms, and bind login/search SQL values.
2. Customer authorization: enforce public-registration fields, catalog roles, customer ownership, and review selectors.
3. Files and parsers: remove profile evaluation, constrain extraction, disable external XML entities, and reject remote image imports while retaining file uploads.
4. Commerce and chat: enforce positive quantities and authentic coupons, require verified chat identity, and disable financial issuance lacking trusted settlement or eligibility records.

Set `JWT_PRIVATE_KEY` to a deployment-managed RSA private key for stable sessions across restarts and replicas. Without it the process generates an ephemeral 2048-bit RSA key and restart invalidates sessions. The previously bundled signing key is rejected. Rotate deployed keys and invalidate old tokens when adopting this change.

Wallet topups require a real settlement integration before re-enablement. Chat coupon issuance requires trusted order eligibility state before re-enablement. Neither a saved card nor model-generated assertions constitute authorization.

Checkout accepts wallet payment only until another payment method has verified settlement. Remote image URL imports return 410; image file uploads remain supported. Existing orders without an immutable UserId are not exposed through customer order tools; migrate their ownership from authoritative records, never masked email. Coupons issued before signing-key rotation are invalid.

Validation on the combined stack: 64 focused API/integration tests, 55 focused server tests and 1,372 frontend unit tests passed. Server TypeScript compilation, backend ESLint, configuration lint, frontend lint/SCSS lint, and production frontend build passed. The original full API suite and Refactoring Safety Net do not pass: training tests/36 codefix fixtures still encode the intentionally vulnerable baseline. The full server suite attempted in the sandbox did not complete its network precondition checks. Cypress E2E and coverage measurement remain unverified. These PRs are drafts pending completion of those gates; no findings are marked verified or closed.
