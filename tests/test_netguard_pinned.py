"""批次 6 安全修复回归：netguard IP 绑定、test-engine SSRF 校验、助手域边界。"""
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.netguard import (  # noqa: E402
    SsrfBlocked,
    assert_safe_outbound_url,
    pinned_outbound_request,
)


class PinnedOutboundTest(unittest.TestCase):
    """pinned_outbound_request：URL host 替换为校验通过的 IP，Host/SNI 保持原域名。"""

    def test_http_pin(self):
        import socket
        infos = socket.getaddrinfo("example.com", 80, proto=socket.IPPROTO_TCP)
        first_ip = infos[0][4][0]
        pinned = pinned_outbound_request("http://example.com/api/v1/x?k=1")
        self.assertTrue(pinned["url"].startswith(f"http://{first_ip}"))
        self.assertIn("/api/v1/x?k=1", pinned["url"])
        self.assertEqual(pinned["headers"]["Host"], "example.com")
        self.assertEqual(pinned["extensions"], {})

    def test_https_pin_keeps_sni(self):
        import socket
        infos = socket.getaddrinfo("example.com", 443, proto=socket.IPPROTO_TCP)
        first_ip = infos[0][4][0]
        pinned = pinned_outbound_request("https://example.com/v1/models")
        self.assertTrue(pinned["url"].startswith(f"https://{first_ip}"))
        self.assertEqual(pinned["extensions"]["sni_hostname"], "example.com")
        self.assertEqual(pinned["headers"]["Host"], "example.com")

    def test_loopback_blocked_even_with_port(self):
        with self.assertRaises(SsrfBlocked):
            pinned_outbound_request("http://127.0.0.1:18800/x")

    def test_private_blocked(self):
        with self.assertRaises(SsrfBlocked):
            pinned_outbound_request("http://10.0.0.5/admin")
        with self.assertRaises(SsrfBlocked):
            pinned_outbound_request("http://[::ffff:127.0.0.1]/x")  # mapped IPv6
        with self.assertRaises(SsrfBlocked):
            pinned_outbound_request("http://169.254.169.254/latest/meta-data/")

    def test_metadata_host_by_name_blocked(self):
        with self.assertRaises(SsrfBlocked):
            pinned_outbound_request("http://metadata.tencentyun.com/")

    def test_extra_host_bypasses_pin(self):
        pinned = pinned_outbound_request(
            "http://fofa-proxy.internal/api", allow_extra_hosts={"fofa-proxy.internal"}
        )
        self.assertEqual(pinned["url"], "http://fofa-proxy.internal/api")
        self.assertEqual(pinned["headers"], {})


class AllowPrivateFlagTest(unittest.TestCase):
    def test_private_allowed_but_loopback_not(self):
        assert_safe_outbound_url("http://10.1.2.3/fofa", allow_private=True)
        assert_safe_outbound_url("http://192.168.1.1:9200", allow_private=True)
        with self.assertRaises(SsrfBlocked):
            assert_safe_outbound_url("http://127.0.0.1/x", allow_private=True)
        with self.assertRaises(SsrfBlocked):
            assert_safe_outbound_url("http://169.254.169.254/", allow_private=True)


class AssistantScopeTest(unittest.TestCase):
    """报告助手域边界：http_request/run_shell 仅允许目标 host 及其子域。"""

    def _allowed(self, url, target="jwxt.example.edu.cn"):
        from app.api.findings import _assistant_url_allowed
        return _assistant_url_allowed(url, target)

    def test_target_and_subdomain_allowed(self):
        self.assertTrue(self._allowed("https://jwxt.example.edu.cn/login"))
        self.assertTrue(self._allowed("http://api.jwxt.example.edu.cn/x"))

    def test_other_host_blocked(self):
        self.assertFalse(self._allowed("http://www.other.edu.cn/api"))
        # 前缀相似但不是子域
        self.assertFalse(self._allowed("http://jwxt.example.edu.cn.evil.com/x"))
        self.assertFalse(self._allowed("http://127.0.0.1:8500/v1/kv"))

    def test_non_http_scheme_blocked(self):
        self.assertFalse(self._allowed("file:///etc/passwd"))

    def test_empty_target_allows(self):
        self.assertTrue(self._allowed("http://anything.example.com/x", target=""))

    def test_target_host_extraction(self):
        from app.api.findings import _assistant_target_host

        class F:
            target_url = "https://jwxt.example.edu.cn:8443/a"

        self.assertEqual(_assistant_target_host(F()), "jwxt.example.edu.cn")


class TestEngineSsrfTest(unittest.TestCase):
    """test-engine 接入 SSRF 校验：内网 base_url 默认 400 + ssrf 错误类型。"""

    def test_private_base_url_rejected(self):
        import asyncio
        from types import SimpleNamespace
        from unittest import mock

        import app.api.settings as settings_mod

        engine = Mock()
        engine.test_connection = mock.AsyncMock(return_value={"ok": True})
        body = SimpleNamespace(engine="fofa", key="k", base_url="http://10.0.0.9")
        with mock.patch.object(settings_mod, "get_engine", return_value=engine), \
             mock.patch.object(settings_mod, "resolve_engine_key", return_value="k"), \
             mock.patch.object(settings_mod, "refresh_cache", new=mock.AsyncMock()):
            res = asyncio.run(settings_mod.test_engine(body, None))
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_type"], "ssrf")
        engine.test_connection.assert_not_awaited()

    def test_public_base_url_passes_guard(self):
        import asyncio
        from types import SimpleNamespace
        from unittest import mock

        import app.api.settings as settings_mod

        engine = Mock()
        engine.test_connection = mock.AsyncMock(return_value={"ok": True})
        body = SimpleNamespace(engine="fofa", key="k", base_url="https://fofa.info")
        with mock.patch.object(settings_mod, "get_engine", return_value=engine), \
             mock.patch.object(settings_mod, "resolve_engine_key", return_value="k"), \
             mock.patch.object(settings_mod, "refresh_cache", new=mock.AsyncMock()):
            res = asyncio.run(settings_mod.test_engine(body, None))
        self.assertTrue(res["ok"])
        engine.test_connection.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
