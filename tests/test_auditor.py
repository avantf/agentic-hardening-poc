"""Tests for agent.auditor: hash chain, tamper detection, retention metadata, evidence export."""

import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from agent import auditor as auditor_module
from agent.auditor import (
    GENESIS_HASH,
    Auditor,
    AuditIntegrityError,
    AuditWriteError,
)
from agent.models import AuditEntry

T0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def entry(minutes: int, event_type: str = "finding_detected", **payload) -> AuditEntry:
    return AuditEntry(T0 + timedelta(minutes=minutes), "assessor", event_type, payload, "L1")


@pytest.fixture
def path(tmp_path):
    return tmp_path / "logs" / "audit.jsonl"


@pytest.fixture
def auditor(path):
    return Auditor(path, clock=lambda: T0)


def read_lines(path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def write_lines(path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def independent_hash(record: dict) -> str:
    """Recompute a record hash from the documented format, without using the Auditor."""
    body = {k: v for k, v in record.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --- hash chain --------------------------------------------------------------


def test_new_log_starts_with_metadata_record_and_verifies(auditor, path):
    header = json.loads(read_lines(path)[0])
    assert header["type"] == "metadata"
    assert header["seq"] == 0
    assert header["prev_hash"] == GENESIS_HASH
    assert header["hash_algorithm"] == "sha256"
    assert auditor.verify_chain_integrity() == (True, None)


def test_hash_chain_is_written_correctly(auditor, path):
    auditor.append(entry(0, control="BC-005"))
    auditor.append(entry(1, event_type="action_proposed", action_class="change_ssh_policy"))
    auditor.log("policy_engine", "decision_made", {"outcome": "needs_approval"}, "L1")

    records = [json.loads(line) for line in read_lines(path)]
    assert [r["seq"] for r in records] == [0, 1, 2, 3]
    assert records[0]["prev_hash"] == GENESIS_HASH
    for previous, current in zip(records, records[1:]):
        assert current["prev_hash"] == previous["hash"]
    for record in records:
        assert record["hash"] == independent_hash(record)
    assert auditor.head_hash == records[-1]["hash"]
    assert records[2]["payload"] == {"action_class": "change_ssh_policy"}
    assert records[3]["actor"] == "policy_engine"


def test_reopening_continues_the_same_chain(path):
    Auditor(path).append(entry(0))
    reopened = Auditor(path)
    reopened.append(entry(1))

    assert reopened.verify_chain_integrity() == (True, None)
    assert [json.loads(line)["seq"] for line in read_lines(path)] == [0, 1, 2]


def test_log_file_is_owner_only(auditor, path):
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# --- retention metadata --------------------------------------------------------


def test_retention_defaults_to_365_days_and_is_stored_in_metadata(auditor, path):
    assert auditor.retention_policy_days == 365
    assert json.loads(read_lines(path)[0])["retention_policy_days"] == 365


def test_custom_retention_is_stored_and_survives_reopen(path):
    Auditor(path, retention_policy_days=730)
    assert json.loads(read_lines(path)[0])["retention_policy_days"] == 730
    assert Auditor(path).retention_policy_days == 730
    assert Auditor(path, retention_policy_days=730).retention_policy_days == 730


def test_conflicting_retention_on_existing_log_is_rejected(path):
    Auditor(path, retention_policy_days=730)
    with pytest.raises(ValueError, match="730"):
        Auditor(path, retention_policy_days=30)


@pytest.mark.parametrize("bad", [0, -5, 1.5, True])
def test_invalid_retention_is_rejected(path, bad):
    with pytest.raises(ValueError):
        Auditor(path, retention_policy_days=bad)


# --- tamper detection ----------------------------------------------------------


@pytest.fixture
def populated(auditor, path):
    for i in range(5):
        auditor.append(entry(i, n=i))
    return auditor


def test_modified_entry_is_detected_at_its_index(populated, path):
    lines = read_lines(path)
    record = json.loads(lines[3])
    record["payload"]["n"] = 999  # edit content, keep the old hash
    lines[3] = json.dumps(record)
    write_lines(path, lines)

    assert populated.verify_chain_integrity() == (False, 3)


def test_modified_and_rehashed_entry_is_detected_at_the_next_entry(populated, path):
    lines = read_lines(path)
    record = json.loads(lines[2])
    record["payload"]["n"] = 999
    record["hash"] = independent_hash(record)  # attacker recomputes the hash
    lines[2] = json.dumps(record)
    write_lines(path, lines)

    assert populated.verify_chain_integrity() == (False, 3)


def test_modified_metadata_is_detected(populated, path):
    lines = read_lines(path)
    header = json.loads(lines[0])
    header["retention_policy_days"] = 1
    lines[0] = json.dumps(header)
    write_lines(path, lines)

    assert populated.verify_chain_integrity() == (False, 0)


def test_removed_entry_is_detected(populated, path):
    lines = read_lines(path)
    del lines[2]
    write_lines(path, lines)

    assert populated.verify_chain_integrity() == (False, 2)


def test_swapped_entries_are_detected(populated, path):
    lines = read_lines(path)
    lines[2], lines[3] = lines[3], lines[2]
    write_lines(path, lines)

    assert populated.verify_chain_integrity() == (False, 2)


def test_garbage_and_torn_lines_are_detected(populated, path):
    lines = read_lines(path)
    path.write_text("\n".join(lines[:3]) + "\n" + '{"seq": 3, "typ', encoding="utf-8")
    assert populated.verify_chain_integrity() == (False, 3)


def test_missing_and_empty_log_are_reported_as_corrupt(populated, path):
    path.write_text("")
    assert populated.verify_chain_integrity() == (False, 0)
    path.unlink()
    assert populated.verify_chain_integrity() == (False, 0)


def test_tail_truncation_is_not_detected_by_the_chain_but_head_hash_differs(populated, path):
    """Documented limit: dropping the last records leaves a valid chain.

    Anchoring head_hash outside the log's writer is what closes the gap.
    """
    anchored = populated.head_hash
    write_lines(path, read_lines(path)[:-2])

    assert populated.verify_chain_integrity() == (True, None)
    assert Auditor(path).head_hash != anchored


def test_tampered_log_is_not_opened_or_appended_to(populated, path):
    lines = read_lines(path)
    lines[1] = lines[1].replace("assessor", "attacker")
    write_lines(path, lines)

    with pytest.raises(AuditIntegrityError) as excinfo:
        Auditor(path)
    assert excinfo.value.index == 1


def test_emptied_log_is_not_silently_recreated(populated, path):
    path.write_text("")
    with pytest.raises(AuditIntegrityError):
        Auditor(path)


# --- evidence export -----------------------------------------------------------


@pytest.fixture
def timeline(auditor):
    for minute in (0, 10, 20, 30, 40):
        auditor.append(entry(minute, minute=minute))
    return auditor


def test_export_returns_entries_within_range_inclusive(timeline):
    result = timeline.export_evidence(T0 + timedelta(minutes=10), T0 + timedelta(minutes=30))

    assert [r["payload"]["minute"] for r in result] == [10, 20, 30]
    assert all(r["type"] == "entry" for r in result)


def test_export_records_carry_hashes_and_are_in_log_order(timeline):
    result = timeline.export_evidence(T0 + timedelta(minutes=10), T0 + timedelta(minutes=30))

    assert [r["seq"] for r in result] == [2, 3, 4]
    assert result[1]["prev_hash"] == result[0]["hash"]
    assert all(r["hash"] == independent_hash(r) for r in result)


def test_export_excludes_metadata_and_handles_empty_ranges(timeline):
    everything = timeline.export_evidence(T0 - timedelta(days=1), T0 + timedelta(days=1))
    assert len(everything) == 5
    assert timeline.export_evidence(T0 + timedelta(hours=5), T0 + timedelta(hours=6)) == []


def test_export_accepts_iso_strings_and_other_timezones(timeline):
    result = timeline.export_evidence("2026-01-01T13:10:00+01:00", "2026-01-01T13:20:00+01:00")
    assert [r["payload"]["minute"] for r in result] == [10, 20]


def test_export_rejects_naive_timestamps_and_inverted_ranges(timeline):
    with pytest.raises(ValueError, match="timezone-aware"):
        timeline.export_evidence(datetime(2026, 1, 1), T0)
    with pytest.raises(ValueError, match="before"):
        timeline.export_evidence(T0 + timedelta(hours=1), T0)


def test_export_refuses_a_log_that_fails_verification(timeline, path):
    lines = read_lines(path)
    lines[2] = lines[2].replace("assessor", "attacker")
    write_lines(path, lines)

    with pytest.raises(AuditIntegrityError) as excinfo:
        timeline.export_evidence(T0 - timedelta(days=1), T0 + timedelta(days=1))
    assert excinfo.value.index == 2


# --- write validation and failures ---------------------------------------------


def test_invalid_entries_are_rejected_without_writing(auditor, path):
    before = path.read_text()
    with pytest.raises(TypeError):
        auditor.append(entry(0, bad={1, 2}))  # a set is not JSON-serializable
    with pytest.raises(ValueError, match="timezone-aware"):
        auditor.append(AuditEntry(datetime(2026, 1, 1), "a", "e", {}, "L1"))
    with pytest.raises(ValueError, match="autonomy_level"):
        auditor.append(AuditEntry(T0, "a", "e", {}, "L9"))  # type: ignore[arg-type]

    assert path.read_text() == before
    assert auditor.verify_chain_integrity() == (True, None)


def test_write_failure_raises_and_blocks_further_appends(auditor, monkeypatch):
    def failing_write(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(auditor_module.os, "write", failing_write)
    with pytest.raises(AuditWriteError, match="disk full"):
        auditor.append(entry(0))

    monkeypatch.undo()
    with pytest.raises(AuditWriteError, match="previous write failed"):
        auditor.append(entry(1))


def test_append_does_not_recreate_a_deleted_log(auditor, path):
    path.unlink()
    with pytest.raises(AuditWriteError):
        auditor.append(entry(0))
    assert not path.exists()
