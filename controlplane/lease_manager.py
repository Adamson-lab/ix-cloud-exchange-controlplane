from dataclasses import dataclass
from datetime import datetime, timezone
import threading
import time
from typing import Any

from storage.audit_chain import HashChainedAuditLog


class LeaseConflictError(Exception):
    pass


@dataclass
class ExchangeLease:
    port_id: str
    holder_id: str
    fencing_token: int
    expires_at_utc: float


class FencingLeaseManager:
    # Monotonic counter prevents a stalled node from reusing an older token after partition recovery.
    def __init__(self, audit_log: HashChainedAuditLog | None = None, default_ttl_sec: float = 30.0) -> None:
        self._lock = threading.Lock()
        self._leases: dict[str, ExchangeLease] = {}
        self._epoch_counter: int = 0
        self._audit = audit_log or HashChainedAuditLog()
        self._default_ttl_sec = default_ttl_sec

    def acquire(
        self,
        port_id: str,
        holder_id: str,
        now_utc: float | None = None,
        grace_extension_sec: float = 0.0,
    ) -> ExchangeLease:
        # Compare in UTC epoch seconds so local Daylight Saving Time shifts never alter lease TTLs.
        now = time.time() if now_utc is None else now_utc
        effective_grace = min(max(grace_extension_sec, 0.0), 900.0)
        with self._lock:
            existing = self._leases.get(port_id)
            if existing is not None and existing.expires_at_utc > now and existing.holder_id != holder_id:
                raise LeaseConflictError(f"port {port_id} actively leased by {existing.holder_id}")

            self._epoch_counter += 1
            lease = ExchangeLease(
                port_id=port_id,
                holder_id=holder_id,
                fencing_token=self._epoch_counter,
                expires_at_utc=now + self._default_ttl_sec + effective_grace,
            )
            self._leases[port_id] = lease
            self._audit.append(
                event_type="lease_acquired",
                fencing_token=lease.fencing_token,
                payload={
                    "port_id": port_id,
                    "holder_id": holder_id,
                    "expires_at_utc": lease.expires_at_utc,
                    "grace_sec": effective_grace,
                    "recorded_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                },
            )
            return lease

    def validate_token(self, port_id: str, fencing_token: int, now_utc: float | None = None) -> bool:
        now = time.time() if now_utc is None else now_utc
        with self._lock:
            current = self._leases.get(port_id)
            if current is None:
                return False
            if current.expires_at_utc <= now:
                return False
            return fencing_token == current.fencing_token

    def audit_log(self) -> HashChainedAuditLog:
        return self._audit

    def state_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "active_leases": {
                    k: {
                        "holder_id": v.holder_id,
                        "fencing_token": v.fencing_token,
                        "expires_at_utc": v.expires_at_utc,
                    }
                    for k, v in self._leases.items()
                },
                "audit_entries": len(self._audit.records()),
            }
