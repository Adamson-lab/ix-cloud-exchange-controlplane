# Design Notes: Cloud Exchange Control Plane

This service separates lease and audit coordination (`controlplane/lease_manager.py`, `storage/audit_chain.py`, `controlplane/server.py`) from virtual circuit execution (`dataplane/provisioner.py`) over AWS EC2 and S3 with Open Policy Agent (OPA) policy checks.

## Control vs. Data Plane Topology

```mermaid
flowchart TB
    subgraph ControlPlane["Control Plane (:8080)"]
        API["FastAPI Server :8080"]
        LeaseMgr["FencingLeaseManager"]
        AuditLog["HashChainedAuditLog"]
        API --> LeaseMgr
        LeaseMgr --> AuditLog
    end

    subgraph External["External Policy & Cloud"]
        OPA["OPA :8181"]
        AWS["LocalStack / AWS EC2 & S3 :4566"]
    end

    subgraph DataPlane["Data Plane"]
        Prov["ExchangeDataPlane"]
    end

    Client["Client"] -->|"POST /v1/exchange/circuits"| API
    API -->|"POST /v1/data/exchange/*"| OPA
    API --> Prov
    Prov -->|"validate_token"| LeaseMgr
    Prov -->|"ec2:describe_vpcs / s3:put_object"| AWS
```

## Lease Handover and Fencing Sequence

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Control Plane :8080
    participant O as OPA :8181
    participant L as FencingLeaseManager
    participant D as ExchangeDataPlane

    C->>S: POST /v1/exchange/circuits (HMAC headers)
    S->>S: verify_webhook
    alt Invalid HMAC or stale timestamp
        S-->>C: 401 Unauthorized
    else Signature valid
        S->>O: Evaluate peering and window policies
        alt Policy denied
            S-->>C: 403 Forbidden
        else Policy allowed
            S->>L: acquire(port_id, holder_id)
            alt Active non-expired lease held by another worker
                S-->>C: 409 Conflict
            else Lease acquired with monotonic token
                S->>D: provision_virtual_circuit(fencing_token)
                alt Stale or expired token
                    D-->>S: DataPlaneError
                    S-->>C: 409 Conflict
                else Token valid
                    D-->>S: ProvisionResult
                    S-->>C: 200 OK
                end
            end
        end
    end
```

## Lease State Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Unleased
    Unleased --> Leased: acquire() increments fencing_token
    Leased --> Leased: same holder re-acquires or extends grace
    Leased --> Expired: expires_at_utc reached
    Expired --> Leased: new holder acquires next fencing_token
    Leased --> [*]
```

## Trade-Offs and Limitations

All lease expirations and UTC window checks evaluate in UTC timestamps rather than local wall-clock time so Daylight Saving Time changes do not alter timeouts. Off-window changes allow up to a 15-minute grace extension when an active incident ID is supplied. AWS calls retry transient errors up to 4 times with per-attempt sleep capped at `2.0s`.

Limitations: `FencingLeaseManager` and `HashChainedAuditLog` live in single-process memory rather than a distributed consensus store or relational database, and `describe_vpcs` does not paginate across `NextToken`.
