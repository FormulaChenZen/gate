import os
import sys
import unittest
from unittest.mock import Mock, patch

with patch.dict(sys.modules, {"requests": Mock()}):
    import vpngate


NODE = {
    "host": "vpn12345.opengw.net",
    "port": 443,
    "ip": "192.0.2.1",
    "country": "Japan",
    "country_code": "JP",
}


class DeploymentChecks(unittest.TestCase):
    def test_check_worker_receives_bearer_token(self):
        session = Mock()
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {"success": True}
        with patch.dict(os.environ, {"CHECK_TOKEN": "test-only-check-token"}):
            result = vpngate.check_one(NODE, session)
        self.assertTrue(result["success"])
        session.get.assert_called_once_with(
            vpngate.WORKER_CHECK_URL + "vpn12345.opengw.net%3A443",
            timeout=vpngate.CHECK_TIMEOUT,
            headers={
                "User-Agent": "Mozilla/5.0 (gate-checker)",
                "Authorization": "Bearer test-only-check-token",
            },
        )
        self.assertNotIn("test-only-check-token", str(result))

    def test_zero_success_never_writes_output(self):
        for worker_error in (False, True):
            with self.subTest(worker_error=worker_error):
                with patch.object(vpngate, "fetch_vpngate", return_value=([{}], "test")), \
                     patch.object(vpngate, "to_sstp_nodes", return_value=[NODE]), \
                     patch.object(vpngate, "check_all", return_value=[{"success": False, "worker_error": worker_error}]), \
                     patch.object(vpngate, "build_outputs") as build, \
                     patch.object(vpngate, "write_outputs") as write, \
                     patch.object(vpngate, "log"):
                    with self.assertRaises(SystemExit) as exited:
                        vpngate.main()
                    self.assertEqual(exited.exception.code, 1)
                    build.assert_not_called()
                    write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
