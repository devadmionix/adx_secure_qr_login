"""Security enhancement tests for QR Login.

Tests for:
- Per-user QR login control
- Replay protection
- Failed attempt lockout
- Device management
- Concurrent session control

Run with:

    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_security_enhancements
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	EVENT_INVALID_CREDENTIAL,
	EVENT_LOGIN_SUCCESS,
	REASON_INACTIVE_USER,
	REASON_INVALID_CREDENTIAL,
	REASON_LOCKED,
	REASON_OK,
	REASON_REPLAY_DETECTED,
)
from adx_secure_qr_login.tests import cleanup_test_users

# Settings these suites deliberately change. Every one is restored in tearDown:
# a test run must never leave the site in a different security posture than the
# one an administrator configured (a suite that quietly disables replay
# protection or raises the lockout threshold would be a real vulnerability).
_TOUCHED_SETTINGS = (
	"max_failed_attempts_per_credential",
	"lockout_minutes",
	"replay_policy",
	"replay_window_seconds",
	"max_concurrent_sessions",
	"ip_rate_limit_per_hour",
	"device_tracking",
)


class QRSecurityTestCase(FrappeTestCase):
	"""Base class that restores QR Security Settings around each test."""

	def snapshot_settings(self):
		self._settings_before = frappe.db.get_singles_dict(
			"QR Security Settings", cast=True
		)

	def restore_settings(self):
		if not getattr(self, "_settings_before", None):
			return
		current = frappe.db.get_singles_dict("QR Security Settings", cast=True)
		for field in _TOUCHED_SETTINGS:
			if current.get(field) != self._settings_before.get(field):
				frappe.db.set_single_value("QR Security Settings", field, self._settings_before.get(field))
		frappe.db.commit()


def _make_user(email, roles=("Stock User",)):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "QRSecurity",
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.flags.ignore_permissions = True
	doc.set("roles", [{"role": r} for r in roles])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	return doc.name


class TestPerUserQRControl(QRSecurityTestCase):
	"""Per-user QR login control tests."""

	def setUp(self):
		frappe.set_user("Administrator")
		self.snapshot_settings()
		cleanup_test_users(["qrtest.peruser@test.local"])
		self.user = _make_user("qrtest.peruser@test.local")
		# Set company
		company = (frappe.get_all("Company", pluck="name", limit=1) or [None])[0]
		if company:
			frappe.db.set_value("User", self.user, "company", company)

	def tearDown(self):
		self.restore_settings()
		frappe.db.rollback()
		cleanup_test_users(["qrtest.peruser@test.local"])

	def _mint(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		frappe.set_user("Administrator")
		for name in frappe.get_all(
			"QR Login Credential",
			filters={"user": self.user, "status": "Active"},
			pluck="name",
		):
			frappe.db.set_value(
				"QR Login Credential", name, "status", "Revoked", update_modified=False
			)
		frappe.db.commit()
		return generate_credential(self.user)

	def test_user_with_qr_enabled_resolves(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		# Default is enabled
		self.assertTrue(validation._is_user_qr_enabled(self.user))
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

	def test_user_with_qr_disabled_rejected(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		# Disable QR for this user
		frappe.db.set_value("User", self.user, "qr_login_enabled", 0)
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_INACTIVE_USER)

	def test_user_with_qr_reenabled_resolves(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		# Disable then re-enable
		frappe.db.set_value("User", self.user, "qr_login_enabled", 0)
		frappe.db.set_value("User", self.user, "qr_login_enabled", 1)
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)


class TestReplayProtection(QRSecurityTestCase):
	"""Replay protection tests."""

	def setUp(self):
		frappe.set_user("Administrator")
		self.snapshot_settings()
		cleanup_test_users(["qrtest.replay@test.local"])
		self.user = _make_user("qrtest.replay@test.local")
		company = (frappe.get_all("Company", pluck="name", limit=1) or [None])[0]
		if company:
			frappe.db.set_value("User", self.user, "company", company)

	def tearDown(self):
		self.restore_settings()
		frappe.db.rollback()
		cleanup_test_users(["qrtest.replay@test.local"])

	def _mint(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		frappe.set_user("Administrator")
		for name in frappe.get_all(
			"QR Login Credential",
			filters={"user": self.user, "status": "Active"},
			pluck="name",
		):
			frappe.db.set_value(
				"QR Login Credential", name, "status", "Revoked", update_modified=False
			)
		frappe.db.commit()
		return generate_credential(self.user)

	def test_single_use_replay_rejected(self):
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value("QR Security Settings", "replay_policy", "single_use")
		gen = self._mint()

		# First use succeeds
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

		# Simulate time passing (beyond grace period)
		frappe.db.set_value(
			"QR Login Credential",
			gen["credential"],
			"last_used",
			frappe.utils.add_to_date(frappe.utils.now(), minutes=-5),
		)

		# Second use rejected
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_REPLAY_DETECTED)

	def test_window_policy_allows_reuse(self):
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value("QR Security Settings", "replay_policy", "window")
		frappe.db.set_single_value("QR Security Settings", "replay_window_seconds", 300)
		gen = self._mint()

		# First use succeeds
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

		# Within window, second use also succeeds
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

	def test_disabled_policy_allows_reuse(self):
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value("QR Security Settings", "replay_policy", "disabled")
		gen = self._mint()

		# First use succeeds
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

		# Second use also succeeds
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)


class TestLockout(QRSecurityTestCase):
	"""Failed attempt lockout tests."""

	def setUp(self):
		frappe.set_user("Administrator")
		self.snapshot_settings()
		cleanup_test_users(["qrtest.lockout@test.local"])
		self.user = _make_user("qrtest.lockout@test.local")
		company = (frappe.get_all("Company", pluck="name", limit=1) or [None])[0]
		if company:
			frappe.db.set_value("User", self.user, "company", company)

	def tearDown(self):
		self.restore_settings()
		frappe.db.rollback()
		cleanup_test_users(["qrtest.lockout@test.local"])

	def _mint(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential

		frappe.set_user("Administrator")
		for name in frappe.get_all(
			"QR Login Credential",
			filters={"user": self.user, "status": "Active"},
			pluck="name",
		):
			frappe.db.set_value(
				"QR Login Credential", name, "status", "Revoked", update_modified=False
			)
		frappe.db.commit()
		return generate_credential(self.user)

	def test_lockout_after_max_failures(self):
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value(
			"QR Security Settings", "max_failed_attempts_per_credential", 3
		)
		frappe.db.set_single_value("QR Security Settings", "lockout_minutes", 15)

		gen = self._mint()
		name = gen["credential"]

		# Drive the real public entry point the auth path uses.
		for _ in range(3):
			validation.register_credential_failure(name)

		locked = frappe.db.get_value(
			"QR Login Credential", name, ["failed_attempts", "locked_until"],
			as_dict=True,
		)
		self.assertEqual(locked["failed_attempts"], 3)
		self.assertTrue(locked["locked_until"])

		# Even the correct token is refused while the lockout stands.
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_LOCKED)

	def test_lockout_expires_and_credential_recovers(self):
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value(
			"QR Security Settings", "max_failed_attempts_per_credential", 2
		)
		frappe.db.set_single_value("QR Security Settings", "lockout_minutes", 15)

		gen = self._mint()
		name = gen["credential"]

		for _ in range(2):
			validation.register_credential_failure(name)

		self.assertTrue(
			frappe.db.get_value("QR Login Credential", name, "locked_until")
		)

		# Lockout window elapses.
		frappe.db.set_value(
			"QR Login Credential",
			name,
			"locked_until",
			frappe.utils.add_to_date(frappe.utils.now(), minutes=-1),
			update_modified=False,
		)

		# The credential is usable again -- recovery is automatic, no admin action.
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), name
		)

	def test_successful_login_resets_lockout_counter(self):
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value(
			"QR Security Settings", "max_failed_attempts_per_credential", 3
		)

		gen = self._mint()
		name = gen["credential"]

		validation.register_credential_failure(name)
		validation.register_credential_failure(name)
		self.assertEqual(
			frappe.db.get_value("QR Login Credential", name, "failed_attempts"), 2
		)

		# A correct login proves the holder is not guessing.
		validation.record_success(name)
		self.assertEqual(
			frappe.db.get_value("QR Login Credential", name, "failed_attempts"), 0
		)

	def test_repeated_hits_on_locked_credential_do_not_extend_lockout(self):
		"""A locked credential must not be pushable further into the future.

		Otherwise an attacker who triggered a lockout keeps it locked by
		continuing to present the code -- a denial of service against one user.
		"""
		from adx_secure_qr_login.security import validation

		frappe.db.set_single_value(
			"QR Security Settings", "max_failed_attempts_per_credential", 2
		)

		gen = self._mint()
		name = gen["credential"]

		for _ in range(2):
			validation.register_credential_failure(name)

		first = frappe.db.get_value("QR Login Credential", name, "locked_until")

		for _ in range(10):
			validation.register_credential_failure(name)

		self.assertEqual(
			frappe.db.get_value("QR Login Credential", name, "locked_until"), first
		)


class TestDeviceManagement(QRSecurityTestCase):
	"""Device management tests."""

	def setUp(self):
		frappe.set_user("Administrator")
		self.snapshot_settings()
		self.users = [
			"qrtest.device@test.local",
			"qrtest.device.plain@test.local",
		]
		cleanup_test_users(self.users)
		self.user = _make_user(self.users[0])
		company = (frappe.get_all("Company", pluck="name", limit=1) or [None])[0]
		if company:
			frappe.db.set_value("User", self.user, "company", company)

	def tearDown(self):
		self.restore_settings()
		frappe.db.rollback()
		cleanup_test_users(self.users)

	def test_device_crud(self):
		from adx_secure_qr_login.api import qr_device

		# Create a device
		doc = frappe.get_doc({
			"doctype": "QR Login Device",
			"device_id": "test-device-001",
			"device_name": "Test Device",
			"user": self.user,
			"browser": "Chrome",
			"operating_system": "Windows",
			"ip_address": "127.0.0.1",
		})
		doc.insert(ignore_permissions=True)
		frappe.db.commit()

		# List devices
		devices = qr_device.list_devices(self.user)
		self.assertTrue(any(d["device_id"] == "test-device-001" for d in devices))

		# Get device
		device = qr_device.get_device(doc.name)
		self.assertEqual(device["device_id"], "test-device-001")

		# Trust device
		result = qr_device.trust_device(doc.name)
		self.assertTrue(result["trusted"])

		# Untrust device
		result = qr_device.untrust_device(doc.name)
		self.assertFalse(result["trusted"])

		# Revoke device
		result = qr_device.revoke_device(doc.name)
		self.assertEqual(result["status"], "revoked")

	def test_device_permissions(self):
		from adx_secure_qr_login.api import qr_device

		plain = _make_user("qrtest.device.plain@test.local", roles=("Sales User",))

		# Create a device
		doc = frappe.get_doc({
			"doctype": "QR Login Device",
			"device_id": "test-device-002",
			"device_name": "Test Device 2",
			"user": self.user,
			"browser": "Firefox",
			"operating_system": "Linux",
			"ip_address": "127.0.0.1",
		})
		doc.insert(ignore_permissions=True)
		frappe.db.commit()

		# Plain user cannot manage devices
		frappe.set_user(plain)
		with self.assertRaises(frappe.PermissionError):
			qr_device.revoke_device(doc.name)

		# Owner can view own devices
		frappe.set_user(self.user)
		devices = qr_device.list_devices(self.user)
		self.assertTrue(any(d["device_id"] == "test-device-002" for d in devices))


class TestConcurrentSessions(QRSecurityTestCase):
	"""Concurrent QR session control."""

	def setUp(self):
		frappe.set_user("Administrator")
		self.snapshot_settings()
		cleanup_test_users(["qrtest.concurrent@test.local"])
		self.user = _make_user("qrtest.concurrent@test.local")
		company = (frappe.get_all("Company", pluck="name", limit=1) or [None])[0]
		if company:
			frappe.db.set_value("User", self.user, "company", company)
		self._clear_registry()

	def tearDown(self):
		self._clear_registry()
		self.restore_settings()
		frappe.db.rollback()
		cleanup_test_users(["qrtest.concurrent@test.local"])

	def _clear_registry(self):
		from adx_secure_qr_login.security import session_guard

		session_guard.release_qr_session(self.user)

	def test_unlimited_sessions_allowed(self):
		"""The default (0) must never constrain a shared terminal."""
		from adx_secure_qr_login.security import session_guard

		frappe.db.set_single_value("QR Security Settings", "max_concurrent_sessions", 0)
		for i in range(10):
			session_guard.register_qr_session(self.user, f"sid-{i}")
		self.assertTrue(session_guard.check_concurrent_sessions(self.user))

	def test_session_limit_enforced(self):
		from adx_secure_qr_login.security import session_guard

		frappe.db.set_single_value("QR Security Settings", "max_concurrent_sessions", 1)

		self.assertTrue(session_guard.check_concurrent_sessions(self.user))
		session_guard.register_qr_session(self.user, "sid-1")
		self.assertFalse(session_guard.check_concurrent_sessions(self.user))

	def test_terminating_sessions_frees_the_slot(self):
		"""Revoking a credential must return the concurrent slot."""
		from adx_secure_qr_login.security import session_guard

		frappe.db.set_single_value("QR Security Settings", "max_concurrent_sessions", 1)
		session_guard.register_qr_session(self.user, "sid-1")
		self.assertFalse(session_guard.check_concurrent_sessions(self.user))

		session_guard.release_qr_session(self.user)
		self.assertTrue(session_guard.check_concurrent_sessions(self.user))

	def test_expired_registry_entries_do_not_consume_slots(self):
		"""A stale sid must never hold a slot forever."""
		from adx_secure_qr_login.security import session_guard

		frappe.db.set_single_value("QR Security Settings", "max_concurrent_sessions", 1)
		session_guard.register_qr_session(self.user, "sid-live")
		self.assertFalse(session_guard.check_concurrent_sessions(self.user))

		# Rewrite the entry as if it were minted before the TTL window.
		key = session_guard.QR_SESSIONS_KEY.format(self.user)
		frappe.cache.delete_value(key)
		frappe.cache.hset(key, "sid-ancient", 0)
		frappe.cache.expire(key, session_guard.QR_SESSION_TTL)

		self.assertTrue(session_guard.check_concurrent_sessions(self.user))
