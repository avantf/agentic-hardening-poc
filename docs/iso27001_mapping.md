# ISO/IEC 27001:2022 mapping of the Auditor

This document maps the technical features of [agent/auditor.py](../agent/auditor.py) to three Annex A controls of ISO/IEC 27001:2022: **A.8.15 Logging**, **A.5.28 Collection of evidence** and **A.5.33 Protection of records**. It lists what the code contributes and what it leaves open.

It is this project's own reading of the controls, written for a proof of concept. It is not an assessment, a certification claim or legal advice. **Conformity with ISO/IEC 27001 is a property of an organisation's management system, not of a software module: full compliance also requires organisational measures that this code does not and cannot provide** (see [Organisational measures not covered](#organisational-measures-not-covered)).

## Summary

| Control | Addressed by | Main residual gap |
|---|---|---|
| A.8.15 Logging | Structured, timestamped, append-only records; tamper-evident hash chain; verification on open and on demand; fail-closed writes | No monitoring or analysis of the logs; unkeyed chain with no external anchor |
| A.5.28 Collection of evidence | `export_evidence()` time-bounded extraction with per-record hashes; refuses to export from a log that fails verification | No evidence-handling procedure, chain of custody or sealed export |
| A.5.33 Protection of records | Falsification detection; fsync on every append; owner-only permissions; retention declared in tamper-evident metadata | Retention is declared, not enforced; no protection against deletion, no encryption or backup |

## Log format

`logs/audit.jsonl` holds one JSON object per line.

- Record 0 is a `metadata` record: schema version, hash algorithm (SHA-256), creation time and `retention_policy_days`.
- Every following record is an `entry` with `timestamp` (UTC, ISO 8601), `actor`, `event_type`, `payload` and `autonomy_level`.
- Every record carries `seq` (its position), `prev_hash` (the previous record's `hash`; a fixed genesis value for record 0) and `hash` (SHA-256 of the record's canonical JSON without the `hash` field).

## A.8.15 Logging

*Intent (paraphrased):* logs that record activities, exceptions, faults and other relevant events are produced, stored, protected and analysed.

**Technical features**

- **Production.** Each pipeline step can be recorded as an `AuditEntry` carrying who (`actor`), what (`event_type`, `payload`), when (timezone-aware timestamp, stored in UTC) and under which autonomy level. Naive timestamps, unknown autonomy levels and non-JSON-serializable payloads are rejected before anything is written.
- **Storage.** Append-only writes in a machine-readable format, flushed to disk (`fsync`) on every record.
- **Fail closed.** A failed write raises `AuditWriteError`, and the Auditor then refuses further appends until it is recreated and the log re-verified. This supports the `halt_on_audit_failure` guardrail in `config/autonomy_policy.yaml`.
- **Protection from tampering.** Any modification, removal or reordering of a record breaks the hash chain from that point on. `verify_chain_integrity()` recomputes the whole chain and returns `(True, None)` or `(False, index_of_first_corrupt_record)`. An existing log is verified when the Auditor opens it, and a log that fails is never appended to.

**Remaining limits**

- **Tamper-evident, not tamper-proof.** Someone with write access to the file can still delete or rewrite it. The chain is an unkeyed SHA-256: it does not detect removal of the *last* records, or a complete rewrite by someone who recomputes every hash. Mitigations left to the deployment: OS-level append-only flags, separate or write-once log storage, and anchoring `head_hash` where the log's writer cannot alter it. A keyed (HMAC) or signed chain is not implemented.
- **No analysis or monitoring.** Nothing reviews the logs, raises alerts or correlates events (related control: A.8.16 Monitoring activities).
- **Time source.** Timestamps come from the host clock; synchronisation and its protection are not addressed (A.8.17 Clock synchronization).
- **Completeness depends on the callers.** The Auditor records what it is given; it cannot ensure every relevant event is logged. The `actor` is a self-declared string, not an authenticated identity.
- **Sensitive data.** Payloads are stored as given. There is no redaction or masking, so anything placed in a payload is retained as-is.
- **Operational scope.** A single file, one writer process at a time, no rotation or size management.

## A.5.28 Collection of evidence

*Intent (paraphrased):* procedures exist for the identification, collection, acquisition and preservation of evidence related to information security events.

**Technical features**

- `export_evidence(start_ts, end_ts)` extracts the entries in a time interval (both ends inclusive; datetimes or ISO 8601 strings; timezone required), in log order, excluding the metadata record.
- Extracted records are returned exactly as stored, including `seq`, `prev_hash` and `hash`. Each record's hash can be recomputed independently, and contiguous records can be checked against each other.
- Evidence is not exported from a log whose integrity cannot be established: a failing chain raises `AuditIntegrityError` with the index of the first corrupt record.
- Timestamps are normalised to UTC, so ranges compare consistently regardless of the timezone used by the requester.

**Remaining limits**

- **No procedure.** Deciding what counts as evidence, who may request an extract, how it is handled and how its authenticity is later demonstrated are organisational matters. The code provides an extraction primitive only.
- **No chain of custody.** An export is a plain list: it is not signed or sealed, the export itself is not logged, and there is no export format for forensic tooling.
- **Subsets are only partly verifiable.** An extract proves internal consistency, and gaps in `seq` are visible, but showing that it belongs to the original log needs the full log or an externally anchored `head_hash`.
- **Corruption blocks export.** If verification fails, nothing is exported, including the intact part of the log. An investigator would read the file directly through other means.
- **Preservation over time** depends on storage, backup and media handling, none of which are implemented.

## A.5.33 Protection of records

*Intent (paraphrased):* records are protected from loss, destruction, falsification, unauthorised access and unauthorised release, and kept for the periods that requirements demand.

**Technical features**

- **Falsification:** the hash chain (see A.8.15).
- **Loss:** every append is flushed with `fsync`; write errors are raised, never swallowed.
- **Unauthorised access:** the log is created with mode `0600` and its directory, when created by the Auditor, with `0700`.
- **Retention declaration:** `retention_policy_days` (default 365, configurable at creation) is stored in the chained metadata record, so the declared value travels with the log and cannot be changed without breaking the chain. Reopening an existing log with a different value raises `ValueError` instead of silently overriding it.

**Remaining limits**

- **Retention is declared, not enforced.** Nothing is deleted, archived or put under legal hold, and there is no rotation. The default of 365 days is a placeholder, not derived from any legal, regulatory or contractual requirement.
- **Destruction is not prevented.** A deleted log is detected by `verify_chain_integrity()` (reported as `(False, 0)`) only while the Auditor object still exists. Starting a new Auditor on a path where the file no longer exists creates a fresh log without complaint; noticing the loss needs an external inventory or anchor.
- **No confidentiality beyond file permissions.** No encryption at rest or in transit, no classification or labelling, no controlled release of records.
- **No backup or replication** (related control: A.8.13 Information backup).
- **Personal and sensitive data** in payloads are not handled (related control: A.8.11 Data masking).

## Organisational measures not covered

The technical features above support the three controls but do not satisfy them alone. A conforming ISMS would also need, at least:

- documented policies and defined roles for logging, evidence handling and records management;
- a retention schedule based on legal, regulatory and contractual requirements, with the means to enforce it;
- access management and segregation of duties over log storage, including who may read, export or administer logs;
- secure storage, backup and protection of the log host, and time synchronisation;
- a process to review logs, to verify the chain periodically and to keep or check the external anchor;
- incident-handling and evidence procedures, including chain of custody and the handling of exports;
- treatment of personal data contained in logs, under the applicable data-protection rules;
- awareness and training of the people involved, and internal audit and management review of all of the above.

## Checking the chain

```python
from agent.auditor import Auditor

auditor = Auditor()                       # verifies logs/audit.jsonl on open
ok, first_bad_index = auditor.verify_chain_integrity()
evidence = auditor.export_evidence("2026-01-01T00:00:00+00:00", "2026-01-31T23:59:59+00:00")
```

Tests covering these behaviours are in [tests/test_auditor.py](../tests/test_auditor.py), including the documented limitation on tail truncation.
