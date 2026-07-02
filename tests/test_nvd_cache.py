"""Tests for vulnerability.nvd_cache — NVD API Cache."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from vulnerability.nvd_cache import NVDCache


@pytest.fixture
def cache(tmp_path):
    """Create a cache with a temporary directory."""
    return NVDCache(cache_dir=tmp_path, ttl_seconds=3600)


class TestNVDCache:
    """Test the NVD caching layer."""

    def test_init_creates_directory(self, tmp_path):
        cache_dir = tmp_path / "nvd_test"
        cache = NVDCache(cache_dir=cache_dir)
        assert cache_dir.exists()

    def test_write_and_read_cache(self, cache, tmp_path):
        results = [{"id": "CVE-2024-1234", "severity": "high"}]
        cache._write_cache("test_key", results)

        cached = cache._read_cache("test_key")
        assert cached is not None
        assert len(cached) == 1
        assert cached[0]["id"] == "CVE-2024-1234"

    def test_expired_cache_returns_none(self, tmp_path):
        cache = NVDCache(cache_dir=tmp_path, ttl_seconds=1)
        cache._write_cache("test_key", [{"id": "CVE-test"}])

        # Manually backdate the timestamp
        cache_file = tmp_path / "test_key.json"
        data = json.loads(cache_file.read_text())
        data["timestamp"] = time.time() - 10
        cache_file.write_text(json.dumps(data))

        assert cache._read_cache("test_key") is None

    def test_clear_cache(self, cache, tmp_path):
        cache._write_cache("key1", [{"id": "CVE-1"}])
        cache._write_cache("key2", [{"id": "CVE-2"}])

        removed = cache.clear_cache()
        assert removed == 2
        assert list(tmp_path.glob("*.json")) == []

    def test_clear_expired(self, tmp_path):
        cache = NVDCache(cache_dir=tmp_path, ttl_seconds=3600)

        # Write one fresh and one expired
        cache._write_cache("fresh", [{"id": "CVE-fresh"}])
        cache._write_cache("old", [{"id": "CVE-old"}])

        old_file = tmp_path / "old.json"
        data = json.loads(old_file.read_text())
        data["timestamp"] = time.time() - 7200  # 2 hours ago
        old_file.write_text(json.dumps(data))

        removed = cache.clear_expired()
        assert removed == 1

        # Fresh one should still be there
        assert cache._read_cache("fresh") is not None
        assert cache._read_cache("old") is None

    def test_rate_limiting(self, cache):
        # Record max requests
        for _ in range(cache._max_requests):
            cache._record_request()

        assert cache._check_rate_limit() is False

    def test_rate_limit_window_expires(self, cache):
        # Record requests with old timestamps
        cache._request_times = [time.time() - 60] * cache._max_requests
        assert cache._check_rate_limit() is True

    def test_parse_nvd_response(self):
        response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [
                            {"lang": "en", "value": "Test vulnerability description"}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ]
        }

        results = NVDCache._parse_nvd_response(response, "test_product")
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2024-1234"
        assert results[0]["severity"] == "critical"
        assert results[0]["cvss"] == 9.8

    def test_parse_nvd_response_empty(self):
        results = NVDCache._parse_nvd_response({"vulnerabilities": []}, "test")
        assert results == []

    def test_lookup_product_uses_cache(self, cache, tmp_path):
        # Pre-populate cache
        cache._write_cache("product_openssh_9.5", [{"id": "CVE-2024-6387"}])

        results = cache.lookup_product("openssh", "9.5")
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2024-6387"

    def test_api_key_increases_rate_limit(self, tmp_path):
        cache = NVDCache(cache_dir=tmp_path, api_key="test-key")
        assert cache._max_requests == 50
