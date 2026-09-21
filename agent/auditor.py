"""Append-only, hash-chained audit trail (logs/audit.jsonl).

File format: one JSON object per line ("record"), in this order:

  record 0     "metadata": schema version, hash algorithm, creation time and the
               declared retention_policy_days.
  record 1..n  "entry": one AuditEntry (timestamp, actor, event_type, payload,
               autonomy_level).

Every record carries its position (`seq`), the `hash` of the previous record
(`prev_hash`, a fixed genesis value for record 0) and its own `hash`, the
SHA-256 of its canonical JSON without the `hash` field. Modifying, removing or
reordering any record breaks the chain from that point on, which
`verify_chain_integrity` detects. See docs/iso27001_mapping.md for what this
does and does not cover.

Limits worth knowing: the chain alone cannot detect removal of the *last*
records or a full rewrite by someone who can recompute every hash; anchor
`head_hash` somewhere the log's writer cannot modify to close that gap. Only one
process should write to a given log at a time.
"""

import hashlib
import hmac
import json
import os
import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, get_args

from agent.models import AuditEntry, AutonomyLevel

DEFAULT_AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "audit.jsonl"
DEFAULT_RETENTION_POLICY_DAYS = 365
SCHEMA_VERSION = 1
HASH_ALGORITHM = "sha256"
GENESIS_HASH = "0" * 64


class AuditError(Exception):
    """Base class for audit trail errors."""


class AuditWriteError(AuditError):
    """A record could not be durably written. The caller must halt (halt_on_audit_failure)."""


class AuditIntegrityError(AuditError):
    """The log fails hash-chain verification.

    Attributes:
        index: Position of the first corrupt record (0 is the metadata record).
    """

    def __init__(self, index: int) -> None:
        super().__init__(f"audit log integrity check failed at record {index}")
        self.index = index


class _CorruptRecord(Exception):
    def __init__(self, index: int) -> None:
        super().__init__(index)
        self.index = index


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _seal(record: dict[str, Any]) -> dict[str, Any]:
    """Return `record` with its `hash` field added."""
    return {**record, "hash": hashlib.sha256(_canonical(record)).hexdigest()}


def _to_utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _validate_retention(days: int) -> None:
    if isinstance(days, bool) or not isinstance(days, int) or days < 1:
        raise ValueError("retention_policy_days must be a positive integer")


class Auditor:
    """Writes and verifies the audit trail.

    Args:
        path: Log file. Created (owner-only permissions) with a metadata record if
            it does not exist. An existing file is verified first; a log that fails
            verification is never appended to.
        retention_policy_days: Declared retention period, stored in the metadata
            record. It is a declaration only: nothing is deleted automatically. For
            an existing log the stored value applies, and passing a different one
            raises ValueError. Default 365 for a new log.
        clock: Time source for `log()`; injectable for tests.

    Raises:
        AuditIntegrityError: the existing log fails verification.
        AuditWriteError: the new log could not be created.
        ValueError: invalid or conflicting `retention_policy_days`.
    """

    def __init__(
        self,
        path: Path | str = DEFAULT_AUDIT_LOG_PATH,
        retention_policy_days: int | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self._failed = False
        if retention_policy_days is not None:
            _validate_retention(retention_policy_days)

        if self._path.exists():
            self._load_existing(retention_policy_days)
        else:
            self._create(retention_policy_days or DEFAULT_RETENTION_POLICY_DAYS)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def retention_policy_days(self) -> int:
        """Declared retention period stored in the log's metadata record."""
        return self._retention_policy_days

    @property
    def head_hash(self) -> str:
        """Hash of the last record. Anchor it externally to detect tail truncation."""
        return self._head_hash

    def log(
        self,
        actor: str,
        event_type: str,
        payload: dict[str, Any],
        autonomy_level: AutonomyLevel,
    ) -> AuditEntry:
        """Record an event stamped with the current time and return the AuditEntry."""
        entry = AuditEntry(self._clock(), actor, event_type, payload, autonomy_level)
        self.append(entry)
        return entry

    def append(self, entry: AuditEntry) -> dict[str, Any]:
        """Append `entry`, durably (fsync), and return the record as written.

        Raises:
            ValueError / TypeError: the entry is invalid or its payload is not
                JSON-serializable. Nothing is written.
            AuditWriteError: the write failed. The Auditor then refuses further
                appends until it is recreated (which re-verifies the log).
        """
        if entry.timestamp.tzinfo is None:
            raise ValueError("entry.timestamp must be timezone-aware")
        if entry.autonomy_level not in get_args(AutonomyLevel):
            raise ValueError(f"invalid autonomy_level {entry.autonomy_level!r}")
        if not entry.actor or not entry.event_type:
            raise ValueError("actor and event_type must be non-empty")
        # Round-trip so the stored payload is exactly what verification will re-hash.
        payload = json.loads(json.dumps(entry.payload, sort_keys=True, allow_nan=False))

        with self._lock:
            if self._failed:
                raise AuditWriteError("a previous write failed; recreate the Auditor to re-verify the log")
            record = _seal(
                {
                    "seq": self._next_seq,
                    "type": "entry",
                    "timestamp": _to_utc(entry.timestamp).isoformat(),
                    "actor": entry.actor,
                    "event_type": entry.event_type,
                    "payload": payload,
                    "autonomy_level": entry.autonomy_level,
                    "prev_hash": self._head_hash,
                }
            )
            self._write(record)
            self._next_seq += 1
            self._head_hash = record["hash"]
        return record

    def verify_chain_integrity(self) -> tuple[bool, int | None]:
        """Recompute the whole hash chain of the log file.

        Checks, for every record: valid JSON on a complete line, correct position
        (`seq`), link to the previous record (`prev_hash`) and the recomputed hash.

        Returns:
            (True, None) if the chain is intact, otherwise (False, index) with the
            position of the first corrupt record (0 is the metadata record). A
            missing or empty log is reported as (False, 0).
        """
        with self._lock:
            try:
                for _ in self._iter_verified():
                    pass
            except _CorruptRecord as e:
                return False, e.index
        return True, None

    def export_evidence(
        self, start_ts: datetime | str, end_ts: datetime | str
    ) -> list[dict[str, Any]]:
        """Extract the entries whose timestamp is within [start_ts, end_ts], both inclusive.

        Simulates evidence extraction for an audit. Records are returned as stored
        (including `seq`, `prev_hash` and `hash`), in log order, so the extract can
        be checked against the chain. The metadata record is not included.

        Args:
            start_ts, end_ts: Timezone-aware datetimes or ISO 8601 strings.

        Raises:
            ValueError: naive timestamp, or end before start.
            AuditIntegrityError: the log fails verification; evidence is not
                exported from a log whose integrity cannot be established.
        """
        start, end = _to_utc(start_ts), _to_utc(end_ts)
        if end < start:
            raise ValueError("end_ts must not be before start_ts")
        with self._lock:
            try:
                return [
                    record
                    for _, record in self._iter_verified()
                    if record["type"] == "entry"
                    and start <= datetime.fromisoformat(record["timestamp"]) <= end
                ]
            except _CorruptRecord as e:
                raise AuditIntegrityError(e.index) from None

    # -- internals ---------------------------------------------------------

    def _create(self, retention_policy_days: int) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as e:
            raise AuditWriteError(f"cannot create {self._path.parent}: {e}") from e
        header = _seal(
            {
                "seq": 0,
                "type": "metadata",
                "schema_version": SCHEMA_VERSION,
                "hash_algorithm": HASH_ALGORITHM,
                "created_at": _to_utc(self._clock()).isoformat(),
                "retention_policy_days": retention_policy_days,
                "prev_hash": GENESIS_HASH,
            }
        )
        self._write(header, exclusive=True)
        self._retention_policy_days = retention_policy_days
        self._next_seq = 1
        self._head_hash = header["hash"]

    def _load_existing(self, requested_retention: int | None) -> None:
        last: dict[str, Any] | None = None
        header: dict[str, Any] | None = None
        try:
            for index, record in self._iter_verified():
                header = header or record
                last = record
        except _CorruptRecord as e:
            raise AuditIntegrityError(e.index) from None
        assert header is not None and last is not None  # an empty file fails verification
        stored = header["retention_policy_days"]
        try:
            _validate_retention(stored)
        except ValueError:
            raise AuditIntegrityError(0) from None
        if requested_retention is not None and requested_retention != stored:
            raise ValueError(
                f"log {self._path.name} declares retention_policy_days={stored}; "
                f"cannot open it with {requested_retention}"
            )
        self._retention_policy_days = stored
        self._next_seq = last["seq"] + 1
        self._head_hash = last["hash"]

    def _iter_verified(self) -> Iterator[tuple[int, dict[str, Any]]]:
        """Yield (index, record) while verifying the chain; raise _CorruptRecord at the first bad one."""
        try:
            f = self._path.open("r", encoding="utf-8", newline="\n")
        except FileNotFoundError:
            raise _CorruptRecord(0) from None
        except OSError as e:
            raise AuditError(f"cannot read {self._path}: {e}") from e
        with f:
            prev_hash = GENESIS_HASH
            count = 0
            try:
                for line in f:
                    record = self._check_record(count, line, prev_hash)
                    prev_hash = record["hash"]
                    yield count, record
                    count += 1
            except UnicodeDecodeError:
                raise _CorruptRecord(count) from None
            if count == 0:
                raise _CorruptRecord(0)

    @staticmethod
    def _check_record(index: int, line: str, prev_hash: str) -> dict[str, Any]:
        if not line.endswith("\n"):  # torn or partial write
            raise _CorruptRecord(index)
        try:
            record = json.loads(line)
        except ValueError:
            raise _CorruptRecord(index) from None
        if not isinstance(record, dict):
            raise _CorruptRecord(index)
        if record.get("seq") != index or record.get("prev_hash") != prev_hash:
            raise _CorruptRecord(index)
        if record.get("type") != ("metadata" if index == 0 else "entry"):
            raise _CorruptRecord(index)
        stored = record.get("hash")
        body = {k: v for k, v in record.items() if k != "hash"}
        try:
            recomputed = hashlib.sha256(_canonical(body)).hexdigest()
        except (TypeError, ValueError):
            raise _CorruptRecord(index) from None
        if not isinstance(stored, str) or not hmac.compare_digest(stored, recomputed):
            raise _CorruptRecord(index)
        return record

    def _write(self, record: dict[str, Any], exclusive: bool = False) -> None:
        data = _canonical(record) + b"\n"
        # New files are owner-only. Appends never create the file: a log deleted
        # under us must fail loudly rather than restart without its history.
        flags = os.O_WRONLY | os.O_APPEND | (os.O_CREAT | os.O_EXCL if exclusive else 0)
        try:
            fd = os.open(self._path, flags, 0o600)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as e:
            self._failed = True
            raise AuditWriteError(f"cannot write to {self._path}: {e}") from e
