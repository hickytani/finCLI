# Security Policy

## Scope

FIN//GUARD (`finguard`) is a **research-grade** agentic security framework.
It is **not** independently audited, **not** certified for production use, and
**not** connected to real banking systems, funds, or credentials. All amounts
are synthetic (INR/USD/EUR).

This security policy covers the open-source repository at
<https://github.com/hickytani/finCLI>.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| `< 0.2.0` | ❌ (archived) |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred channel

Open a [GitHub Security Advisory](https://github.com/hickytani/finCLI/security/advisories/new)
(private; only visible to repository administrators).

Include:

1. A clear description of the vulnerability and its impact.
2. Steps to reproduce or a minimal proof-of-concept.
3. The affected component(s) and version/commit hash.
4. Your assessment of severity (CVSS score appreciated but not required).
5. Whether you wish to be credited in the advisory.

### Response timeline

| Event | Target |
|-------|--------|
| Acknowledge receipt | 48 h |
| Triage and severity assessment | 5 business days |
| Fix or mitigation published | 30 days (critical), 90 days (others) |
| Public advisory | After fix ships |

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).
If 90 days pass without a fix, you may publish, with 7 days' additional notice.

## Security Architecture Summary

FIN//GUARD's core thesis is that the LLM is an **untrusted component**.
Enforcement lives outside the model:

- **Extraction boundary** (`finguard/ai/`): model output is schema-validated and
  authority-shaped fields are stripped; extraction cannot set actor, nonce,
  policy version, or decision.
- **Decision engine** (`finguard/decision/`): deterministic; fail-closed on any
  exception.
- **Signing gate** (`finguard/signing/`): re-validates everything from stored
  facts before producing an Ed25519 signature; signs v2 canonical bytes only.
- **MCP surface** (`finguard/mcp/`): exposes `propose_transaction`,
  `get_decision`, `list_transactions`, `get_audit_proof`; signing, approval, and
  key surfaces are structurally absent.
- **Audit ledger** (`finguard/audit/`): monotonic seq, hash-chained, checkpoint-signed.

## Known Limitations

See [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for the full list. Key items:

- Not independently audited or certified.
- SQLite-level file replacement by a privileged attacker can bypass the hash chain
  (external anchoring is documented as future work).
- Forced process-death recovery and process-level signing races are partially tested.
- LLM evaluation uses author-written adversarial cases; independent suites (garak,
  PyRIT) have not been integrated.

## Supply-Chain

- Dependencies are pinned via `dependabot` and audited with `pip-audit`.
- SBOM is published as [`SBOM.json`](SBOM.json) (CycloneDX format).
- Build provenance attestations are produced by GitHub Actions via
  `actions/attest-build-provenance` on releases.

## Acknowledgements

Researchers who responsibly disclose vulnerabilities will be credited in the
GitHub Security Advisory and in `CHANGELOG.md` unless they prefer anonymity.
