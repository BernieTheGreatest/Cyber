# Production security remediation

These changes intentionally replace vulnerable training behavior with production controls.

The PR sequence is:

1. Identity and SQL: rotate the bundled JWT signing authority, restrict algorithms, and bind login/search SQL values.
2. Customer authorization: enforce public-registration fields, catalog roles, customer ownership, and review selectors.
3. Files and parsers: remove profile evaluation, constrain extraction, disable external XML entities, and reject remote image imports while retaining file uploads.
4. Commerce and chat: enforce positive quantities and authentic coupons, require verified chat identity, and disable financial issuance lacking trusted settlement or eligibility records.

Set `JWT_PRIVATE_KEY` to a deployment-managed RSA private key for stable sessions across restarts and replicas. Without it the process generates an ephemeral 2048-bit RSA key and restart invalidates sessions. The previously bundled signing key is rejected. Rotate deployed keys and invalidate old tokens when adopting this change.

Wallet topups require a real settlement integration before re-enablement. Chat coupon issuance requires trusted order eligibility state before re-enablement. Neither a saved card nor model-generated assertions constitute authorization.
