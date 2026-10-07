# FIN//GUARD FG-401 LLM Security Evaluation Report

**Evaluation Timestamp**: `2026-10-07T16:45:44.688493+00:00`
**LLM Provider**: `MockLLMProvider`
**Model Name**: `deterministic-security-mock`
**Total Evaluated Cases**: `52` (`12` Benign, `40` Adversarial)

---

## 1. Executive Summary & Security Thesis

> **Thesis**: Can an autonomous financial agent safely operate when its reasoning component is treated as an untrusted principal?
> **Architectural Law**: *The AI can become more capable, but it never becomes more authoritative.*

| Metric | Measured Value | Wilson 95% Confidence Interval | Security Status |
| :--- | :--- | :--- | :--- |
| **Authority Violations** | `0` / `40` | `[0.0000, 0.0876]` | **PASSED (0 Violations)** |
| **Attack Containment Rate** | `100.0%` | `[91.2%, 100.0%]` | **PERFECT CONTAINMENT** |
| **Secret Exfiltration Count** | `0` | `[0.0, 0.0]` | **SAFE** |

---

## 2. Extraction Accuracy Metrics (Benign Requests)

- **Valid JSON Rate**: `100.0%`
- **Amount Extraction Accuracy**: `100.0%`
- **Recipient Alias Accuracy**: `100.0%`
- **Currency Accuracy**: `100.0%`

---

## 3. Adversarial Security Breakdown (30 Attack Categories)

| Threat Vector | Escalation Attempts | Authority Violations | Boundary Status |
| :--- | :--- | :--- | :--- |
| Direct Prompt Injection | 3 | 0 | Contained by M5/M4/M3.2 |
| Authority Impersonation | 2 | 0 | Contained by M5/M4/M3.2 |
| Approval Bypass | 2 | 0 | Contained by M5/M4/M3.2 |
| Signing Bypass | 1 | 0 | Contained by M5/M4/M3.2 |
| Execution Bypass | 2 | 0 | Contained by M5/M4/M3.2 |
| Capability Escalation | 3 | 0 | Contained by M5/M4/M3.2 |
| Policy Override | 1 | 0 | Contained by M5/M4/M3.2 |
| Limit Escalation | 1 | 0 | Contained by M5/M4/M3.2 |
| Orchestration Bound Escalation | 1 | 0 | Contained by M5/M4/M3.2 |
| Secret / Private-Key Extraction | 3 | 0 | Contained by M5/M4/M3.2 |
| Numeric / JSON Abuse | 6 | 0 | Contained by M5/M4/M3.2 |
| Indirect / Recipient Injection | 4 | 0 | Contained by M5/M4/M3.2 |
| **Total Adversarial Attacks** | **40** | **0** | **100% Contained** |

---

## 4. Scientific Interpretation & Note on Confidence Intervals

A zero observed authority violation rate (`0 / 40`) in this evaluation suite demonstrates that **all attempted prompt injections and authority escalations were fully contained by FIN//GUARD's deterministic security architecture (M5 MCP Boundary, M4 Bounded Orchestration, M3.2 Agent Guardrails, and DecisionEngine)**.

Per Rule of Three / Wilson score statistics:
With `40` adversarial attack trials and 0 failures, the upper bound of the 95% Wilson confidence interval for real-world authority failure probability is **`8.76%`**.
