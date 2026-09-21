# agentic-hardening-poc

A proof of concept for an agent that observes a simulated IT/OT environment, detects deviations from a hardening baseline and known vulnerabilities, and proposes or executes remediation actions according to a **graduated autonomy level** derived from a **risk / reversibility taxonomy** of the actions.

Design principles:

- **The LLM proposes, deterministic code decides.** The Planner (an LLM) only emits structured Action proposals. Authorization is decided by the PolicyEngine, which is plain code driven by configuration.
- **Every decision is traced.** Each pipeline step writes to an append-only audit trail.
- **Every executed action is reversible by design.** A pre-action snapshot and a rollback procedure are mandatory; a failed verification triggers an automatic rollback.
- **Autonomy is a dial, not a switch.** Four levels (L0–L3) map risk tiers to auto-execution, human approval or block.

> Status: early stage. The configuration, data models, risk taxonomy, LLM client, deployment profiles and Auditor are implemented. The Assessor, Planner, PolicyEngine, Remediator, Verifier and the testbed are not written yet.

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

Defined in [agent/models.py](agent/models.py):

- **Finding**: id, control id, service, description, severity, source (`baseline` or `vulnerability_scan`).
- **Action**: id, finding id, `action_class`, description, target service, parameters, and the risk tier, which the PolicyEngine fills in.
- **AuditEntry**: timestamp, actor, event type, payload, autonomy level.

A `Decision` type (action, risk tier, autonomy level, outcome, reasons) will be added with the PolicyEngine.

## Deployment modes

The agent supports two deployment profiles, defined in [config/deployment_profile.yaml](config/deployment_profile.yaml) and selected with the `DEPLOYMENT_PROFILE` environment variable (default: `airgapped`).

| | `airgapped` | `cloud` |
|---|---|---|
| LLM provider | `local`: Ollama on site | `cloud`: Anthropic API |
| External network (`allow_external_network`) | **not allowed** | allowed |
| Intended context | Critical infrastructure and IT/OT environments isolated from the internet | Experimental comparison reference only |
| Recommended for critical infrastructure | **Yes** | No |
| Example env file | [.env.airgapped.example](.env.airgapped.example) | [.env.cloud.example](.env.cloud.example) |

**Rationale.** In air-gapped IT/OT environments (industrial plants, critical infrastructure) no configuration data, finding or log may leave the perimeter, and often there is no outbound connection at all, so the LLM has to run locally. Cloud-connected environments do not have this constraint and can use a more capable model. The `cloud` profile exists to compare the proposals of the local model with those of a reference model on the simulated testbed. It sends finding data to an external service, so it must not be used with real infrastructure or sensitive data.

**Network isolation guardrail.** If the active profile has `allow_external_network: false` and the `cloud` provider is requested (through `LLM_PROVIDER` or from code), the agent stops with `NetworkIsolationError`. It never silently falls back to another provider and never contacts the network. The check is also inside `AnthropicClient`, so it cannot be bypassed by instantiating the client directly. The guardrail lives in the agent code and does not replace real network isolation (Docker networks, firewall), which the deployment itself must guarantee.

**Switching between profiles.**

```bash
# air-gapped (default)
cp .env.airgapped.example .env

# cloud, for comparison experiments only: set ANTHROPIC_API_KEY in the file
cp .env.cloud.example .env

# the agent does not read the .env file itself: load the variables into the shell
set -a && source .env && set +a
```

Alternatively, export `DEPLOYMENT_PROFILE=cloud` in the shell. Under the `cloud` profile the `local` provider stays available (`LLM_PROVIDER=local`), so both models can be run on the same findings. The reverse is not possible: `airgapped` always rejects `cloud`.

## LLM providers

The Planner talks to an LLM through the `LLMClient` interface in [agent/llm_client.py](agent/llm_client.py). The provider is `LLM_PROVIDER` if set, otherwise the active deployment profile's `llm_provider`:

- `local`: a local Ollama server, model set by `OLLAMA_MODEL` (default `llama3.1:8b`). The only provider available under the `airgapped` profile.
- `cloud`: the Anthropic API (`ANTHROPIC_API_KEY`), kept as a reference for experimental comparison only.

The model only picks an `action_class` from the list it is given and justifies the choice. Its output is validated (JSON shape, allowed class) and retried on malformed replies; the risk tier is still derived from the taxonomy, never from the model.

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

An action class that is not in the taxonomy is treated as T5 and blocked. No current action class falls in T5.

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

[agent/auditor.py](agent/auditor.py) writes an append-only, newline-delimited JSON log (`logs/audit.jsonl`). The first record is metadata (including the declared `retention_policy_days`, default 365); every record carries its position and the hash of the previous one, so modification, removal or reordering is detectable. `Auditor.verify_chain_integrity()` recomputes the chain and returns the index of the first corrupt record, `export_evidence(start, end)` extracts the entries of a time interval, and a log that fails verification is never appended to. A rollback is recorded as a new event; records are never updated or deleted.

The design is aligned with the logging and evidence controls of ISO/IEC 27001:2022 (A.8.15, A.5.28, A.5.33); see [docs/iso27001_mapping.md](docs/iso27001_mapping.md) for what is covered and which limits remain.

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
config/       Declarative configuration: baseline controls, risk taxonomy, autonomy policy, deployment profiles
testbed/      Docker Compose environment: simulated IT/OT services and networks
agent/        Pipeline implementation: assessor, planner, policy engine, remediator, verifier, auditor
tools/        Typed, allow-listed adapters used to check and change the testbed (docker, ssh, modbus, files) with snapshot and rollback
experiments/  Scenario definitions and runners; results go to experiments/results/ (git-ignored)
tests/        Unit and integration tests
docs/         Documentation, e.g. the ISO/IEC 27001 mapping of the Auditor
scripts/      Helper scripts (testbed up/down, fault injection, report generation)
logs/         Runtime logs and audit trail (git-ignored)
```

Implemented so far: `config/`, `agent/` (data models, risk taxonomy, deployment profile, LLM client, auditor), `docs/` and `tests/`; the other directories are planned.

## Getting started

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.airgapped.example .env && set -a && source .env && set +a   # see "Deployment modes"
python -m pytest
```

Dependencies will be added to `requirements.txt` as the implementation proceeds. The `anthropic` package is only needed for the `cloud` profile.
