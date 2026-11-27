from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import time
from typing import Any

from controlplane.lease_manager import FencingLeaseManager

logger = logging.getLogger("ix_exchange.dataplane")


class DataPlaneError(Exception):
    pass


def sign_webhook(secret: str, ts_unix: int, body: bytes) -> str:
    msg = f"{ts_unix}.".encode("utf-8") + body
    mac = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify_webhook(
    secret: str,
    signature: str | None,
    timestamp: str | None,
    body: bytes,
    max_skew_sec: int = 300,
    now_unix: int | None = None,
) -> tuple[bool, str]:
    if not signature or not timestamp:
        return False, "missing X-Signature-256 or X-Timestamp header"
    try:
        ts = int(timestamp.strip())
    except ValueError:
        return False, "invalid X-Timestamp header"

    now = int(time.time()) if now_unix is None else now_unix
    if abs(now - ts) > max_skew_sec:
        return False, "timestamp outside replay window"

    expected = sign_webhook(secret, ts, body)
    if not hmac.compare_digest(expected, signature.strip()):
        return False, "hmac signature mismatch"
    return True, "ok"


def _retryable_err(exc: Any) -> bool:
    resp = getattr(exc, "response", {}) or {}
    code = resp.get("Error", {}).get("Code", "")
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 0)
    return code in {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
    } or status in {429, 502, 503, 504}


def _call_with_retry(op: str, fn: Any, exc_cls: Any, max_attempts: int = 4) -> Any:
    delay = 0.1
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except exc_cls as exc:
            if not _retryable_err(exc) or attempt == max_attempts:
                raise
            # Cap per-retry delay at 2.0s so a throttled EC2/S3 call does not stall the request path.
            sleep_sec = min(delay, 2.0)
            logger.warning("retrying aws call op=%s attempt=%d sleep_s=%.2f err=%s", op, attempt, sleep_sec, exc)
            time.sleep(sleep_sec)
            delay *= 2.0


@dataclass
class ProvisionResult:
    port_id: str
    vlan_id: int
    asn: int
    fencing_token: int
    s3_bucket: str
    s3_key: str
    audit_hash: str


class ExchangeDataPlane:
    def __init__(
        self,
        lease_manager: FencingLeaseManager,
        region: str = "us-east-1",
        endpoint_url: str | None = "http://localhost:4566",
        bucket: str = "ix-exchange-audit-trail",
        ec2_client: Any | None = None,
        s3_client: Any | None = None,
        client_error_cls: Any | None = None,
    ) -> None:
        self.leases = lease_manager
        self.region = region
        self.bucket = bucket

        if client_error_cls is not None:
            self._client_error = client_error_cls
            boto3_mod = None
        else:
            try:
                import boto3
                from botocore.exceptions import ClientError

                boto3_mod = boto3
                self._client_error = ClientError
            except ImportError:
                boto3_mod = None

                class _FallbackClientError(Exception):
                    response: dict[str, Any] = {}

                self._client_error = _FallbackClientError

        client_kwargs: dict[str, Any] = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url
            client_kwargs["aws_access_key_id"] = "test"
            client_kwargs["aws_secret_access_key"] = "test"

        if ec2_client is not None:
            self.ec2 = ec2_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when ec2_client is not provided")
            self.ec2 = boto3_mod.client("ec2", **client_kwargs)

        if s3_client is not None:
            self.s3 = s3_client
        else:
            if boto3_mod is None:
                raise RuntimeError("boto3 is required when s3_client is not provided")
            self.s3 = boto3_mod.client("s3", **client_kwargs)

    def _ensure_bucket(self) -> None:
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except self._client_error:
            try:
                self.s3.create_bucket(Bucket=self.bucket)
            except self._client_error as exc:
                code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
                if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                    raise

    def provision_virtual_circuit(
        self,
        port_id: str,
        vlan_id: int,
        asn: int,
        fencing_token: int,
        now_utc: float | None = None,
    ) -> ProvisionResult:
        # Reject stale or expired fencing tokens before issuing any data-plane cloud calls.
        if not self.leases.validate_token(port_id=port_id, fencing_token=fencing_token, now_utc=now_utc):
            raise DataPlaneError(f"fencing token {fencing_token} rejected for port {port_id}")

        _call_with_retry(
            "ec2:describe_vpcs",
            lambda: self.ec2.describe_vpcs(),
            self._client_error,
        )
        self._ensure_bucket()

        ts = time.time() if now_utc is None else now_utc
        dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        audit_rec = self.leases.audit_log().append(
            event_type="virtual_circuit_provisioned",
            fencing_token=fencing_token,
            payload={
                "port_id": port_id,
                "vlan_id": vlan_id,
                "asn": asn,
                "region": self.region,
                "provisioned_at": dt_utc.isoformat(),
            },
        )
        key = f"circuits/{dt_utc.strftime('%Y-%m-%d')}/{port_id}-token-{fencing_token}.json"
        doc = {
            "port_id": port_id,
            "vlan_id": vlan_id,
            "asn": asn,
            "fencing_token": fencing_token,
            "audit_hash": audit_rec.entry_hash,
        }
        _call_with_retry(
            "s3:put_object",
            lambda: self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=json.dumps(doc, indent=2).encode("utf-8"),
                ContentType="application/json",
            ),
            self._client_error,
        )
        return ProvisionResult(
            port_id=port_id,
            vlan_id=vlan_id,
            asn=asn,
            fencing_token=fencing_token,
            s3_bucket=self.bucket,
            s3_key=key,
            audit_hash=audit_rec.entry_hash,
        )
