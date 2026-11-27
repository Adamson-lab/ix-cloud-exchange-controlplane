# ix-cloud-exchange-controlplane

Python FastAPI control plane and data-plane provisioner for cloud exchange virtual circuits with monotonic fencing tokens, SHA-256 hash-chained audit records, Open Policy Agent (OPA) checks, and AWS EC2/S3 calls.

## Prerequisites

- Python 3.10+
- Docker and Docker Compose
- `curl` and `openssl`

## Local Setup

Start LocalStack (`ec2,s3`) and OPA:

```bash
make up
```

Run the control-plane API:

```bash
make run
```

Run tests, chaos test, and benchmark:

```bash
make test
make chaos
make bench
```

Stop containers:

```bash
make down
```

## Sample Request

```bash
BODY='{"port_id":"port-equinix-ny5","holder_id":"worker-1","vlan_id":205,"asn":65010,"region":"us-east-1","operator_role":"ix-netops"}'
TS=$(date -u +%s)
SIG="sha256=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac 'local-dev-exchange-secret' | awk '{print $2}')"

curl -s -X POST http://localhost:8080/v1/exchange/circuits   -H "Content-Type: application/json"   -H "X-Timestamp: $TS"   -H "X-Signature-256: $SIG"   -d "$BODY"
```

## Measured Output

From running `python3 -m unittest discover -s tests -p "test_*.py" -v`:

- 5 tests ran in `0.068s` (`OK`).
- `BENCH acquire+validate+chain (2000 ops)`: `65.17 ms` (`32.58 us/op`).

## Known Limitations

- In-memory `FencingLeaseManager` and `HashChainedAuditLog` are per-process rather than backed by a shared database or consensus store.
- Single AWS region per process (`AWS_REGION`).
- `describe_vpcs` reads the first response page without `NextToken` pagination.
