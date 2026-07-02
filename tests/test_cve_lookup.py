"""Tests for vulnerability.cve_lookup — CVE Lookup Engine."""

from __future__ import annotations

import pytest

from vulnerability.cve_lookup import CVELookup
from vulnerability.advisory_database import get_all_advisories, get_advisories_by_product


class TestAdvisoryDatabase:
    """Test the expanded advisory database."""

    def test_total_advisories_over_100(self):
        advisories = get_all_advisories()
        assert len(advisories) >= 100, f"Expected 100+ advisories, got {len(advisories)}"

    def test_all_advisories_have_required_fields(self):
        for adv in get_all_advisories():
            assert "id" in adv, f"Missing id in advisory: {adv}"
            assert "product" in adv
            assert "severity" in adv
            assert "description" in adv
            assert "remediation" in adv
            assert adv["severity"] in ("critical", "high", "medium", "low")

    def test_advisories_by_product_windows(self):
        windows = get_advisories_by_product("windows")
        assert len(windows) >= 20

    def test_advisories_by_product_macos(self):
        macos = get_advisories_by_product("macos")
        assert len(macos) >= 12

    def test_advisories_by_product_linux_kernel(self):
        linux = get_advisories_by_product("linux_kernel")
        assert len(linux) >= 12

    def test_advisories_by_product_openssh(self):
        ssh = get_advisories_by_product("openssh")
        assert len(ssh) >= 8

    def test_no_duplicate_cve_ids(self):
        ids = [a["id"] for a in get_all_advisories()]
        assert len(ids) == len(set(ids)), "Duplicate CVE IDs found"


class TestCVELookup:
    """Test the CVE lookup engine."""

    def test_init_without_api(self):
        lookup = CVELookup(use_api=False)
        assert lookup.advisory_count >= 100

    def test_lookup_openssh_regresshion(self):
        lookup = CVELookup()
        results = lookup.lookup_product("openssh", "9.5")
        cve_ids = [r["id"] for r in results]
        assert "CVE-2024-6387" in cve_ids

    def test_lookup_specific_cve(self):
        lookup = CVELookup()
        result = lookup.lookup_cve("CVE-2024-6387")
        assert result is not None
        assert result["severity"] == "critical"

    def test_lookup_unknown_cve_returns_none(self):
        lookup = CVELookup()
        assert lookup.lookup_cve("CVE-9999-99999") is None

    def test_lookup_unknown_product(self):
        lookup = CVELookup()
        results = lookup.lookup_product("nonexistent_product", "1.0")
        assert results == []

    def test_get_products(self):
        lookup = CVELookup()
        products = lookup.get_products()
        assert "windows" in products
        assert "macos" in products
        assert "openssh" in products
        assert "linux_kernel" in products

    def test_get_stats(self):
        lookup = CVELookup()
        stats = lookup.get_stats()
        assert stats["total_advisories"] >= 100
        assert "windows" in stats["products"]
        assert "critical" in stats["severities"]

    def test_windows_cve_lookup(self):
        lookup = CVELookup()
        results = lookup.lookup_product("windows", "10.0.1")
        assert len(results) >= 10  # Should match many Windows CVEs

    def test_macos_cve_lookup(self):
        lookup = CVELookup()
        results = lookup.lookup_product("macos", "14.1")
        cve_ids = [r["id"] for r in results]
        assert "CVE-2024-23222" in cve_ids
