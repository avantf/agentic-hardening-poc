# agentic-hardening-poc

A proof of concept for an agent that observes a simulated IT/OT environment, detects deviations from a hardening baseline and known vulnerabilities, and proposes or executes remediation actions according to a **graduated autonomy level** derived from a **risk / reversibility taxonomy** of the actions.

Design principles:

- **The LLM proposes, deterministic code decides.** The Planner (an LLM) only emits structured Action proposals. Authorization is decided by the PolicyEngine, which is plain code driven by configuration.
- **Every decision is traced.** Each pipeline step writes to an append-only audit trail.
- **Every executed action is reversible by design.** A pre-action snapshot and a rollback procedure are mandatory; a failed verification triggers an automatic rollback.
- **Autonomy is a dial, not a switch.** Four levels (L0–L3) map risk tiers to auto-execution, human approval or block.

> Status: early stage. Architecture and configuration are defined; the implementation is not yet written.

## Pipeline

```
 Testbed (Docker) ──► Assessor ──► Planner ──► PolicyEngine ──► Remediator ──► Verifier
                         │           (LLM)          │               │              │
   config/baseline ──────┘                          │               │              │
   config/risk_taxonomy ────────────────────────────┤               │              │
   config/autonomy_policy ──────────────────────────┘               │              │
                                                                     ▼              ▼
                                           snapshot + rollback (tools/)     re-scan, rollback on failure

 Every step ──────────────────────────────► Auditor ──► append-only audit trail (logs/)
```

| Stage | Input → Output | Responsibility |
|---|---|---|
| **Assessor** | testbed state + `baseline_controls.yaml` → `Finding[]` | Runs each control's check against the target service and reports every deviation or known-vulnerable component. Read-only. |
| **Planner** | `Finding` → `Action` | An LLM proposes one Action per Finding, restricted to the control's `allowed_action_classes`. Output is validated against a strict schema; free-form commands are not accepted. |
| **PolicyEngine** | `Action` + active level → `Decision` | Looks up the action class in `risk_taxonomy.yaml`, derives the risk tier from the risk matrix, applies `autonomy_policy.yaml` and the global guardrails, and returns `auto_execute`, `needs_approval`, `block` or `defer`. |
| **Remediator** | authorized `Action` → execution result | Takes a pre-action snapshot, executes through the typed adapters in `tools/`, and keeps the rollback handle. |
| **Verifier** | executed `Action` → verified / failed | Re-runs the originating check to confirm the Finding is resolved; on failure it triggers rollback. |
| **Auditor** | every step → audit record | Records findings, proposals, policy decisions, approvals, executions, verifications and rollbacks. |

### Core data types

- **Finding**: control id, target service, observed vs expected value, evidence, timestamp.
- **Action**: finding id, `action_class`, target, parameters, rationale (from the Planner).
- **Decision**: action, risk tier, autonomy level, outcome, reasons (which rule produced the outcome).

## Risk model

The PolicyEngine never trusts a risk rating from the Planner. The tier comes only from the taxonomy:

`impact` (low / medium / high) × `reversibility` (reversible / partially_reversible / irreversible) → `risk_tier` (T1 minimal … T5 critical), through the `risk_matrix` in [config/risk_taxonomy.yaml](config/risk_taxonomy.yaml).

| Impact ↓ / Reversibility → | reversible | partially_reversible | irreversible |
|---|---|---|---|
| **low** | T1 | T2 | T3 |
| **medium** | T2 | T3 | T4 |
| **high** | T3 | T4 | T5 |

Current action classes:

| action_class | impact | reversibility | tier |
|---|---|---|---|
| `restrict_file_permissions` | low | reversible | T1 |
| `rotate_credential` | low | partially_reversible | T2 |
| `close_exposed_port` | medium | reversible | T2 |
| `change_auth_policy` | medium | reversible | T2 |
| `change_ssh_policy` | medium | reversible | T2 |
| `update_crypto_config` | medium | reversible | T2 |
| `apply_package_update` | medium | partially_reversible | T3 |
| `change_ot_write_protection` | high | partially_reversible | T4 |
| `remove_privileged_mode` | high | partially_reversible | T4 |

An action class that is not in the taxonomy is treated as T5 and blocked.

## Autonomy levels

| Level | Name | Auto-executed tiers | Approval for the rest |
|---|---|---|---|
| **L0** | observe | none | not requested; log only, nothing is executed |
| **L1** | recommend | none | always required |
| **L2** | guarded-auto | T1, T2 | required |
| **L3** | full-auto | T1–T4 | not required (experimental runs only) |

Global guardrails (see [config/autonomy_policy.yaml](config/autonomy_policy.yaml)) apply at every level and cannot be loosened by a level:

- `max_actions_per_run`: circuit breaker on the number of executed actions.
- `require_maintenance_window_for_tiers`: T4/T5 actions run only inside a declared maintenance window; otherwise they are deferred.
- `always_block_tiers`: T5 is never executed, not even with approval.
- Unclassified or not-allowed action classes are blocked.
- A snapshot before execution, verification after execution and rollback on failed verification are mandatory.
- Execution halts if the audit trail cannot be written.

## Audit trail

An append-only, newline-delimited JSON log under `logs/`. Each record carries a run id, timestamp, step, the objects involved and a hash of the previous record, so tampering or truncation is detectable. Records are never updated or deleted; a rollback is recorded as a new event.

## Baseline controls

[config/baseline_controls.yaml](config/baseline_controls.yaml) defines the desired state of the testbed services. Each control has an `id`, `title`, `source` (reference standard, documentary label only), `target_service`, `check_type`, `params` and the `allowed_action_classes` the Planner may use. Included controls:

| id | Control | Service |
|---|---|---|
| BC-001 | No default credentials | hmi-web |
| BC-002 | Administrative ports not exposed | hmi-web |
| BC-003 | No weak TLS signature algorithms | hmi-web |
| BC-004 | Modbus write protection | plc-sim |
| BC-005 | SSH password authentication disabled | jump-host |
| BC-006 | Account lockout / password policy | hmi-web |
| BC-007 | No privileged containers | all containers |
| BC-008 | Restrictive permissions on sensitive config | historian-db |
| BC-009 | No known-vulnerable packages | hmi-web |

## Repository layout

```
config/       Declarative policy: baseline controls, risk taxonomy, autonomy policy
testbed/      Docker Compose environment: simulated IT/OT services and networks
agent/        Pipeline implementation: assessor, planner, policy engine, remediator, verifier, auditor
tools/        Typed, allow-listed adapters used to check and change the testbed (docker, ssh, modbus, files) with snapshot and rollback
experiments/  Scenario definitions and runners; results go to experiments/results/ (git-ignored)
tests/        Unit and integration tests
scripts/      Helper scripts (testbed up/down, fault injection, report generation)
logs/         Runtime logs and audit trail (git-ignored)
```

Only `config/` exists so far; the other directories are planned.

## Getting started

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Dependencies will be added to `requirements.txt` as the implementation proceeds.
