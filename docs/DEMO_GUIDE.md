# Demonstration guide

## Preparation

- Use the [production interface](https://apk-inspector-snowy.vercel.app), or
  start the project locally with `docker compose up --build`.
- Confirm the production API health endpoint at
  `https://apk-inspector-api.onrender.com/api/v1/health`, or use the local
  endpoint at `http://localhost:8000/api/v1/health`.
- Keep the three team-owned demonstration APKs in a folder outside this Git
  repository. APK binaries are ignored by Git by design.
- Use placeholder secrets and the reserved `demo.invalid` domain only.

## Suggested sequence

1. Open **View safe demonstration report** to explain the score, evidence,
   remediation, package identity, certificate fingerprint, and code signals.
2. Upload the low-risk team APK and show how a small permission set and current
   target SDK produce fewer findings.
3. Upload the intentionally insecure team APK and connect each finding to the
   manifest or source configuration that caused it.
4. Enable **Compare with trusted APK**. Select the differently signed test
   variant as the submitted file and the original build as the reference.
5. Explain the certificate mismatch, added capabilities, and risk-score delta.
6. Export JSON and use **Print or save PDF** to demonstrate report portability.

## Safety statement

APKInspector never installs or executes the uploaded application. Static
analysis is an indicator-based review and does not prove that an APK is safe.
