# Shared repository controls

## Secret scanning

`.github/workflows/secret-scan.yml` is a reusable, read-only GitHub Actions
workflow. Call it from a workflow triggered by `pull_request`, `push`, and
`workflow_dispatch`, with no path filters. Pin the `uses` reference to a reviewed
full commit SHA. It accepts no secrets or inputs.

The `secret-scan / Secret scan` job scans all fetched Git history with Gitleaks
8.30.1. Checkout and the downloaded scanner are pinned by commit and SHA-256,
respectively. Repository configuration, `.gitleaksignore`, and inline
`gitleaks:allow` comments cannot suppress findings. A detection or execution
error fails the job. Logs show only finding path, rule type, and fingerprint;
source, scanner diagnostics, and full reports are not uploaded.

This is a merge-gate building block, **not push protection**: CI runs after GitHub
receives a push. It is not enforced until repository owners require its observed
check context on every release/policy branch. Native scanning and native push
protection remain the preferred additional controls where entitlement is
confirmed. Disabled settings alone say nothing about entitlement.

### Rollout and rollback

1. Review the shared workflow and pin a caller to its full commit SHA.
2. Open a caller PR in each repository with its owner; never edit another
   owner's remediation branch. Preserve existing CI and human deployment gates.
3. Run the scanner against full history, triage findings without circulating
   values, and use the credential owner's approved incident procedure. Do not
   add blanket historical baselines or rewrite history.
4. Record the actual emitted check name and app identity. An authorized human
   reviews branch coverage, automation behavior, and required-check enforcement
   before changing repository or organization rules.
5. Verify one harmless PR passes, a synthetic-secret fixture fails, and release
   automation still follows the existing approval path. No production deployment
   is necessary to test this scanner.

Rollback uses a reviewed PR reverting the caller pin or scanner change. A
required check is not removed or bypassed by an agent to unblock a release;
temporary exceptions need explicit owner approval and a recorded compensating
control. Credential rotation and history rewriting are separate human gates.

### Verification

Run the real workflow shell in isolated repositories (Python 3 and PyYAML):

```sh
SCAN_TEST_ROOT="$PWD/.scanner-test" python3 tests/test_secret_scan.py -v
```

The three regressions cover clean history, a deleted synthetic credential despite
repository/inline ignores, and scanner execution failure. They download and
checksum the same pinned scanner as CI. `SCAN_TEST_ROOT` points to owned,
disk-backed scratch space; no fixture values are printed.

### Limits

Only fetched Git objects and Gitleaks' built-in rules are scanned. This does not
prove credentials are absent, detect every application-specific password, revoke
an exposed credential, scan external stores, or block a push before receipt.
The workflow needs outbound access to the pinned GitHub release asset; download,
checksum, timeout, and scanner failures block the check rather than pass.