# ADR 002: SHA-256 Hash-Chained Audit Log

## Context
Exchange port assignments and virtual circuit changes need tamper-evident ordering so operators and auditors can detect altered or missing sequence entries.

## Decision
Chain each `AuditRecord` in `storage/audit_chain.py` using `sha256(seq|prev_hash|event_type|fencing_token|payload_json)` and expose `verify_chain()`.

## Consequences
Any modification to an earlier record invalidates subsequent hashes. The current log is kept in process memory and flushed per circuit to S3 rather than written to an external append-only database.
