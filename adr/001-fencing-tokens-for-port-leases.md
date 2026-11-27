# ADR 001: Monotonic Fencing Tokens for Exchange Port Leases

## Context
Two control-plane workers can race on virtual circuit provisioning for the same exchange port during network partitions or failover.

## Decision
Assign a strictly increasing `fencing_token` on every lease acquisition in `FencingLeaseManager` and require `ExchangeDataPlane.provision_virtual_circuit` to validate the token before calling AWS or writing audit records.

## Consequences
Stale writes carrying an older token are rejected immediately even if a delayed worker wakes up after a lease expires or transfers. In-memory lease state is single-process unless backed by a shared transactional store.
