from dataclasses import dataclass
import hashlib
import json
from typing import Any


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    prev_hash: str
    event_type: str
    fencing_token: int
    payload_json: str
    entry_hash: str


def compute_entry_hash(seq: int, prev_hash: str, event_type: str, fencing_token: int, payload_json: str) -> str:
    raw = f"{seq}|{prev_hash}|{event_type}|{fencing_token}|{payload_json}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class HashChainedAuditLog:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, event_type: str, fencing_token: int, payload: dict[str, Any]) -> AuditRecord:
        seq = len(self._records) + 1
        prev_hash = self._records[-1].entry_hash if self._records else "0" * 64
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        entry_hash = compute_entry_hash(seq, prev_hash, event_type, fencing_token, payload_json)
        rec = AuditRecord(
            seq=seq,
            prev_hash=prev_hash,
            event_type=event_type,
            fencing_token=fencing_token,
            payload_json=payload_json,
            entry_hash=entry_hash,
        )
        self._records.append(rec)
        return rec

    def verify_chain(self) -> tuple[bool, str]:
        expected_prev = "0" * 64
        for idx, rec in enumerate(self._records, start=1):
            if rec.seq != idx:
                return False, f"sequence gap at index {idx}"
            if rec.prev_hash != expected_prev:
                return False, f"broken prev_hash at seq {rec.seq}"
            recomputed = compute_entry_hash(rec.seq, rec.prev_hash, rec.event_type, rec.fencing_token, rec.payload_json)
            if recomputed != rec.entry_hash:
                return False, f"hash mismatch at seq {rec.seq}"
            expected_prev = rec.entry_hash
        return True, "ok"

    def records(self) -> list[AuditRecord]:
        return list(self._records)
