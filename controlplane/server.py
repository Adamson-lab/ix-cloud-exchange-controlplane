from datetime import datetime, timezone
import json
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
import httpx

from controlplane.lease_manager import FencingLeaseManager, LeaseConflictError
from dataplane.provisioner import DataPlaneError, ExchangeDataPlane, verify_webhook
from storage.audit_chain import HashChainedAuditLog

app = FastAPI(title="ix-cloud-exchange-controlplane", version="0.1.0")

AUDIT_LOG = HashChainedAuditLog()
LEASE_MGR = FencingLeaseManager(audit_log=AUDIT_LOG, default_ttl_sec=30.0)


def _check_opa(opa_url: str, opa_input: dict[str, Any]) -> tuple[bool, str]:
    base = opa_url.rstrip("/")
    with httpx.Client(timeout=3.0) as client:
        r1 = client.post(f"{base}/v1/data/exchange/peering", json={"input": opa_input})
        r1.raise_for_status()
        d1 = r1.json().get("result") or {}
        if not d1.get("allow", False):
            return False, d1.get("reason", "denied by peering boundary policy")

        r2 = client.post(f"{base}/v1/data/exchange/window", json={"input": opa_input})
        r2.raise_for_status()
        d2 = r2.json().get("result") or {}
        if not d2.get("allow", False):
            return False, d2.get("reason", "denied by maintenance window policy")

        return True, d2.get("reason", "allowed")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    chain_ok, chain_msg = AUDIT_LOG.verify_chain()
    return {
        "status": "ok" if chain_ok else "degraded",
        "audit_chain": chain_msg,
        "utc_time": datetime.now(timezone.utc).isoformat(),
        "state": LEASE_MGR.state_snapshot(),
    }


@app.post("/v1/exchange/circuits")
async def create_circuit(
    request: Request,
    x_signature_256: str | None = Header(default=None, alias="X-Signature-256"),
    x_timestamp: str | None = Header(default=None, alias="X-Timestamp"),
) -> dict[str, Any]:
    raw_body = await request.body()
    secret = os.getenv("WEBHOOK_HMAC_SECRET", "local-dev-exchange-secret")
    ok, reason = verify_webhook(secret, x_signature_256, x_timestamp, raw_body)
    if not ok:
        raise HTTPException(status_code=401, detail={"error": reason})

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "malformed json payload"})

    port_id = str(payload.get("port_id", "ix-port-nyc1-01"))
    holder_id = str(payload.get("holder_id", "worker-a"))
    vlan_id = int(payload.get("vlan_id", 200))
    asn = int(payload.get("asn", 65001))
    region = str(payload.get("region", os.getenv("AWS_REGION", "us-east-1")))
    role = str(payload.get("operator_role", "ix-netops"))
    grace_ext = payload.get("grace_extension") or {}
    grace_mins = int(grace_ext.get("extra_minutes", 0)) if grace_ext.get("active") else 0
    now_utc = datetime.now(timezone.utc)

    opa_url = os.getenv("OPA_URL", "http://localhost:8181")
    try:
        allowed, policy_reason = _check_opa(
            opa_url,
            {
                "port_id": port_id,
                "vlan_id": vlan_id,
                "asn": asn,
                "region": region,
                "operator_role": role,
                "utc_hour": now_utc.hour,
                "grace_extension": grace_ext,
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": f"opa evaluation error: {exc}"})

    if not allowed:
        raise HTTPException(status_code=403, detail={"error": policy_reason})

    try:
        lease = LEASE_MGR.acquire(
            port_id=port_id,
            holder_id=holder_id,
            now_utc=now_utc.timestamp(),
            grace_extension_sec=grace_mins * 60.0,
        )
    except LeaseConflictError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc)})

    dp = ExchangeDataPlane(
        lease_manager=LEASE_MGR,
        region=region,
        endpoint_url=os.getenv("AWS_ENDPOINT_URL", "http://localhost:4566"),
        bucket=os.getenv("EXCHANGE_BUCKET", "ix-exchange-audit-trail"),
    )
    try:
        res = dp.provision_virtual_circuit(
            port_id=port_id,
            vlan_id=vlan_id,
            asn=asn,
            fencing_token=lease.fencing_token,
            now_utc=now_utc.timestamp(),
        )
    except DataPlaneError as exc:
        raise HTTPException(status_code=409, detail={"error": str(exc)})
    except Exception as exc:
        raise HTTPException(status_code=502, detail={"error": f"dataplane provisioning failed: {exc}"})

    chain_valid, _ = AUDIT_LOG.verify_chain()
    return {
        "status": "provisioned",
        "policy_reason": policy_reason,
        "fencing_token": lease.fencing_token,
        "audit_chain_valid": chain_valid,
        "circuit": {
            "port_id": res.port_id,
            "vlan_id": res.vlan_id,
            "asn": res.asn,
            "s3_bucket": res.s3_bucket,
            "s3_key": res.s3_key,
            "audit_hash": res.audit_hash,
        },
    }
