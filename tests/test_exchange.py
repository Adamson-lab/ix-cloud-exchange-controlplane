import os
import sys
import time
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from controlplane.lease_manager import FencingLeaseManager, LeaseConflictError
from dataplane.provisioner import DataPlaneError, ExchangeDataPlane, sign_webhook, verify_webhook
from storage.audit_chain import HashChainedAuditLog


class TestExchangeControlPlane(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = HashChainedAuditLog()
        self.leases = FencingLeaseManager(audit_log=self.audit, default_ttl_sec=30.0)
        self.fake_ec2 = MagicMock()
        self.fake_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-ix-01"}]}
        self.fake_s3 = MagicMock()
        self.dp = ExchangeDataPlane(
            lease_manager=self.leases,
            region="us-east-1",
            endpoint_url=None,
            bucket="test-ix-bucket",
            ec2_client=self.fake_ec2,
            s3_client=self.fake_s3,
        )

    def test_provision_and_verify_hash_chain(self) -> None:
        t0 = 1764267000.0
        lease = self.leases.acquire("port-equinix-ny5", "worker-1", now_utc=t0, grace_extension_sec=900.0)
        res = self.dp.provision_virtual_circuit(
            port_id="port-equinix-ny5",
            vlan_id=205,
            asn=65010,
            fencing_token=lease.fencing_token,
            now_utc=t0 + 1,
        )
        self.assertEqual(res.fencing_token, 1)
        ok, msg = self.audit.verify_chain()
        self.assertTrue(ok, msg)
        self.fake_s3.put_object.assert_called_once()

    def test_lease_conflict_while_active(self) -> None:
        t0 = 1764267000.0
        self.leases.acquire("port-megaport-1", "worker-1", now_utc=t0)
        with self.assertRaises(LeaseConflictError):
            self.leases.acquire("port-megaport-1", "worker-2", now_utc=t0 + 5)

    def test_chaos_stale_fencing_token_rejected(self) -> None:
        t0 = 1764267000.0
        stale_lease = self.leases.acquire("port-equinix-ny5", "worker-1", now_utc=t0)
        # Simulate worker-1 stalling past lease expiry and worker-2 taking over with token 2.
        new_lease = self.leases.acquire("port-equinix-ny5", "worker-2", now_utc=t0 + 35)
        self.assertGreater(new_lease.fencing_token, stale_lease.fencing_token)

        with self.assertRaises(DataPlaneError):
            self.dp.provision_virtual_circuit(
                port_id="port-equinix-ny5",
                vlan_id=205,
                asn=65010,
                fencing_token=stale_lease.fencing_token,
                now_utc=t0 + 36,
            )

    def test_webhook_signature_and_skew(self) -> None:
        secret = "ix-secret"
        body = b'{"port_id":"port-1","vlan_id":120,"asn":65001}'
        now = 1764267000
        sig = sign_webhook(secret, now, body)
        ok, _ = verify_webhook(secret, sig, str(now), body, now_unix=now)
        self.assertTrue(ok)
        bad_ok, _ = verify_webhook(secret, sig, str(now - 301), body, now_unix=now)
        self.assertFalse(bad_ok)

    def test_bench_lease_and_audit_chain(self) -> None:
        chain = HashChainedAuditLog()
        mgr = FencingLeaseManager(audit_log=chain, default_ttl_sec=60.0)
        base_ts = 1764267000.0
        iters = 2000
        t0 = time.perf_counter()
        for i in range(iters):
            port = f"port-{i % 16}"
            lease = mgr.acquire(port, f"w-{i % 4}", now_utc=base_ts + i)
            self.assertTrue(mgr.validate_token(port, lease.fencing_token, now_utc=base_ts + i))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        valid, _ = chain.verify_chain()
        self.assertTrue(valid)
        print(f"BENCH acquire+validate+chain ({iters} ops): {elapsed_ms:.2f} ms ({(elapsed_ms / iters) * 1000:.2f} us/op)")


if __name__ == "__main__":
    unittest.main()
