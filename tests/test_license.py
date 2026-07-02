"""Tests for the license and edition management system."""

import json
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.license import (
    LicenseEdition,
    LicenseManager,
    LicenseToken,
    require_pro,
)


# ---------------------------------------------------------------------------
# TestLicenseToken
# ---------------------------------------------------------------------------

class TestLicenseToken:

    def test_token_not_expired(self):
        """Token with future date is not expired."""
        token = LicenseToken(
            edition=LicenseEdition.PRO,
            expiry_date="2030-01-01",
        )
        assert not token.is_expired()

    def test_token_expired(self):
        """Token with past date is expired."""
        token = LicenseToken(
            edition=LicenseEdition.PRO,
            expiry_date="2020-01-01",
        )
        assert token.is_expired()

    def test_token_invalid_date(self):
        """Token with bad date string is expired (safe default)."""
        token = LicenseToken(
            edition=LicenseEdition.PRO,
            expiry_date="not-a-date",
        )
        assert token.is_expired()

    def test_token_roundtrip(self):
        """to_dict/from_dict preserves all fields."""
        original = LicenseToken(
            edition=LicenseEdition.ENTERPRISE,
            expiry_date="2030-06-15",
            device_limit=10,
            issued_at="2025-01-01T00:00:00",
            customer_id="cust-abc-123",
            signature="sig-placeholder",
        )
        data = original.to_dict()
        restored = LicenseToken.from_dict(data)

        assert restored.edition == original.edition
        assert restored.expiry_date == original.expiry_date
        assert restored.device_limit == original.device_limit
        assert restored.issued_at == original.issued_at
        assert restored.customer_id == original.customer_id
        assert restored.signature == original.signature


# ---------------------------------------------------------------------------
# TestLicenseManager
# ---------------------------------------------------------------------------

class TestLicenseManager:

    def test_generate_and_activate(self):
        """Generate a PRO key, activate it, verify edition is PRO."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            key = LicenseManager.generate_license_key(
                edition=LicenseEdition.PRO,
                expiry_date="2030-01-01",
                customer_id="test-customer",
            )
            success, msg = mgr.activate(key)
            assert success, msg
            assert "PRO" in msg
            assert mgr.get_current_edition() == LicenseEdition.PRO

    def test_activate_invalid_key(self):
        """Random string fails activation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            success, msg = mgr.activate("not-a-valid-license-key!!!")
            assert not success
            assert "Invalid" in msg

    def test_activate_expired_key(self):
        """Key with past expiry fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            key = LicenseManager.generate_license_key(
                edition=LicenseEdition.PRO,
                expiry_date="2020-01-01",
            )
            success, msg = mgr.activate(key)
            assert not success
            assert "expired" in msg.lower()

    def test_activate_tampered_key(self):
        """Modify base64 payload, signature check fails."""
        import base64

        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            key = LicenseManager.generate_license_key(
                edition=LicenseEdition.PRO,
                expiry_date="2030-01-01",
            )
            # Decode, tamper, re-encode
            decoded = json.loads(base64.b64decode(key))
            decoded["edition"] = "enterprise"  # tamper with edition
            tampered_key = base64.b64encode(json.dumps(decoded).encode()).decode()

            success, msg = mgr.activate(tampered_key)
            assert not success
            assert "signature" in msg.lower() or "Invalid" in msg

    def test_deactivate(self):
        """Activate then deactivate, verify back to FREE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            key = LicenseManager.generate_license_key(
                edition=LicenseEdition.PRO,
                expiry_date="2030-01-01",
            )
            mgr.activate(key)
            assert mgr.get_current_edition() == LicenseEdition.PRO

            success, msg = mgr.deactivate()
            assert success
            # Need a fresh manager to clear the cache
            mgr2 = LicenseManager(license_dir=Path(tmpdir))
            assert mgr2.get_current_edition() == LicenseEdition.FREE

    def test_get_current_edition_free(self):
        """No license = FREE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            assert mgr.get_current_edition() == LicenseEdition.FREE

    def test_trial_start_and_check(self):
        """Start trial, verify is_pro_feature_available() is True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            success, msg = mgr.start_trial()
            assert success
            assert "14-day" in msg
            assert mgr.check_trial()
            assert mgr.is_pro_feature_available()

    def test_trial_expired(self):
        """Write trial with past date, verify check_trial() is False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            # Write a trial file with a start date 30 days in the past
            past_start = (datetime.now() - timedelta(days=30)).isoformat()
            trial_data = {"trial_start": past_start, "device_id": "test-device"}
            trial_file = Path(tmpdir) / "trial.json"
            trial_file.write_text(json.dumps(trial_data))

            assert not mgr.check_trial()
            assert mgr.get_current_edition() == LicenseEdition.FREE

    def test_trial_double_start(self):
        """Starting trial twice returns 'already active'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            success1, _ = mgr.start_trial()
            assert success1

            success2, msg2 = mgr.start_trial()
            assert not success2
            assert "already active" in msg2.lower()

    def test_get_license_info(self):
        """Verify info dict has expected keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = LicenseManager(license_dir=Path(tmpdir))
            key = LicenseManager.generate_license_key(
                edition=LicenseEdition.PRO,
                expiry_date="2030-01-01",
                customer_id="info-test",
                device_limit=5,
            )
            mgr.activate(key)
            info = mgr.get_license_info()

            assert info["edition"] == "pro"
            assert info["pro_available"] is True
            assert info["license_active"] is True
            assert info["expiry_date"] == "2030-01-01"
            assert info["customer_id"] == "info-test"
            assert info["device_limit"] == 5
            assert "trial_active" in info

    def test_device_id(self):
        """Verify device ID is a hex string."""
        device_id = LicenseManager._get_device_id()
        assert isinstance(device_id, str)
        assert len(device_id) == 16
        # Verify it is valid hex
        int(device_id, 16)


# ---------------------------------------------------------------------------
# TestRequirePro
# ---------------------------------------------------------------------------

class TestRequirePro:

    def test_require_pro_raises_without_license(self):
        """Decorated function raises PermissionError when no license."""
        with tempfile.TemporaryDirectory() as tmpdir:
            @require_pro
            def protected_feature():
                return "secret-result"

            # Patch LicenseManager.__init__ to use our temp dir (no license present)
            original_init = LicenseManager.__init__

            def patched_init(self, license_dir=None):
                original_init(self, license_dir=Path(tmpdir))

            with patch.object(LicenseManager, "__init__", patched_init):
                try:
                    protected_feature()
                    assert False, "Should have raised PermissionError"
                except PermissionError as e:
                    assert "requires Sentinel Pro" in str(e)
                    assert "protected_feature" in str(e)

    def test_require_pro_passes_with_license(self):
        """Decorated function works after activation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # First activate a license in the temp dir
            mgr = LicenseManager(license_dir=Path(tmpdir))
            key = LicenseManager.generate_license_key(
                edition=LicenseEdition.PRO,
                expiry_date="2030-01-01",
            )
            mgr.activate(key)

            @require_pro
            def protected_feature():
                return "secret-result"

            original_init = LicenseManager.__init__

            def patched_init(self, license_dir=None):
                original_init(self, license_dir=Path(tmpdir))

            with patch.object(LicenseManager, "__init__", patched_init):
                result = protected_feature()
                assert result == "secret-result"


if __name__ == "__main__":
    # TestLicenseToken
    t = TestLicenseToken()
    t.test_token_not_expired()
    t.test_token_expired()
    t.test_token_invalid_date()
    t.test_token_roundtrip()

    # TestLicenseManager
    m = TestLicenseManager()
    m.test_generate_and_activate()
    m.test_activate_invalid_key()
    m.test_activate_expired_key()
    m.test_activate_tampered_key()
    m.test_deactivate()
    m.test_get_current_edition_free()
    m.test_trial_start_and_check()
    m.test_trial_expired()
    m.test_trial_double_start()
    m.test_get_license_info()
    m.test_device_id()

    # TestRequirePro
    r = TestRequirePro()
    r.test_require_pro_raises_without_license()
    r.test_require_pro_passes_with_license()

    print("All license tests passed!")
