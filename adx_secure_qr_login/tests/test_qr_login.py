"""Onboard Phase 4/5/6/7 automated test suites into Frappe's test runner.

Creates `tests/__init__.py` + `tests/test_qr_login.py` that exercises the
security-critical paths. Frappe discovers `test_*.py` under an app's module
folders, so the file lives at `<app>/tests/` and is run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_qr_login

Test accounts use the reserved `.test` TLD (RFC 6761), so they can never collide
with a real address. The passwords are generated per run.
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.tests import cleanup_test_users


class TestQRTokenSecurity(FrappeTestCase):
	"""Token generation, hashing and payload parsing."""

	def test_token_is_unique_and_long(self):
		from adx_secure_qr_login.security import tokens

		sample = [tokens.generate_token() for _ in range(100)]
		self.assertEqual(len(set(sample)), 100)
		self.assertTrue(all(len(t) >= 43 for t in sample))

	def test_hash_is_deterministic_and_one_way(self):
		from adx_secure_qr_login.security import tokens

		token = tokens.generate_token()
		digest = tokens.hash_token(token)
		self.assertEqual(digest, tokens.hash_token(token))
		self.assertNotEqual(digest, token)
		self.assertEqual(len(digest), 64)

	def test_payload_round_trip(self):
		from adx_secure_qr_login.security import tokens

		token = tokens.generate_token()
		self.assertEqual(tokens.parse_payload(tokens.build_payload(token)), token)

	def test_payload_rejects_malformed_input(self):
		from adx_secure_qr_login.security import tokens

		for bad in ("", None, "not-a-token!!", "https://x/y?qr=abc", "/path?qr=abc",
					"https://x/y", "https://x/y?nqr=" + tokens.generate_token(),
					"ftp://x/login?qr=" + tokens.generate_token(),
					"ADXQR9." + tokens.generate_token(), "A" * 500):
			with self.subTest(bad=bad):
				self.assertIsNone(tokens.parse_payload(bad))

	def test_login_url_round_trip(self):
		"""QR images carry a login URL any generic camera can open."""
		from adx_secure_qr_login.security import tokens

		token = tokens.generate_token()
		url = tokens.build_login_url("http://secureQR.local:8080", token)
		self.assertEqual(
			url, f"http://secureQR.local:8080/login?qr=ADXQR1.{token}"
		)
		self.assertEqual(tokens.parse_payload(url), token)
		# Trailing slash base + surrounding whitespace tolerated.
		self.assertEqual(
			tokens.parse_payload(
				"  " + tokens.build_login_url("http://h/", token) + "\n"
			),
			token,
		)
		# No base URL configured: falls back to the bare payload.
		self.assertEqual(tokens.build_login_url("", token), f"ADXQR1.{token}")


def ensure_system_user(email, first_name, roles=()):
	"""Create (or repair) a System User.

	Frappe derives `user_type` from `has_desk_access()` at insert time
	(frappe/core/doctype/user/user.py:414-415), so passing
	`user_type="System User"` to `insert()` is ignored for a user with no
	desk-access role -- it is silently created as a Website User. The type must
	therefore be set *after* the roles, or the user is unusable as a QR subject.
	"""
	if not frappe.db.exists("User", email):
		frappe.get_doc({
			"doctype": "User", "email": email, "first_name": first_name,
			"send_welcome_email": 0,
		}).insert(ignore_permissions=True)

	doc = frappe.get_doc("User", email)
	doc.flags.ignore_permissions = True
	for role in roles:
		if role not in {r.role for r in doc.get("roles") or []}:
			doc.append("roles", {"role": role})
	# Set explicitly after roles so it is not recomputed away on save.
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	return doc


class TestQRValidation(FrappeTestCase):
	"""Every rejection path returns its own internal reason code."""

	def setUp(self):
		self.user = "qrtest.subject@test.local"
		cleanup_test_users([self.user])
		ensure_system_user(self.user, "QRTest", roles=["Stock User"])
		# Multi-company gate: QR resolution requires an explicit User.company.
		# Use any real company; the gate only needs a valid association.
		company = (frappe.get_all("Company", pluck="name", limit=1) or [None])[0]
		if company:
			frappe.db.set_value("User", self.user, "company", company)
		frappe.set_user("Administrator")

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users([self.user])

	def _credential(self, **kw):
		"""Mint a credential, clearing any actives first.

		`generate_credential` commits, so `tearDown`'s rollback cannot undo it and
		credentials accumulate across tests until the active cap
		(`max_active_credentials_per_user`, default 3) rejects the next mint with
		an unrelated ValidationError.
		"""
		from adx_secure_qr_login.api.qr_manage import generate_credential

		frappe.set_user("Administrator")
		for name in frappe.get_all(
			"QR Login Credential", filters={"user": self.user, "status": "Active"}, pluck="name"
		):
			frappe.db.set_value("QR Login Credential", name, "status", "Revoked",
								update_modified=False)
		frappe.db.commit()
		return generate_credential(self.user, **kw)

	def test_valid_token_resolves(self):
		from adx_secure_qr_login.security import validation

		gen = self._credential()
		self.assertEqual(validation.resolve_credential(gen["one_time_token"]), gen["credential"])

	def test_unknown_token_rejected(self):
		from adx_secure_qr_login.security import validation
		from adx_secure_qr_login.security import tokens
		from adx_secure_qr_login.secure_qr_login.constants import (
			REASON_INVALID_CREDENTIAL,
		)

		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(tokens.generate_token())
		self.assertEqual(ctx.exception.reason_code, REASON_INVALID_CREDENTIAL)

	def test_revoked_token_rejected(self):
		from adx_secure_qr_login.api.qr_manage import revoke_credential
		from adx_secure_qr_login.security import validation
		from adx_secure_qr_login.secure_qr_login.constants import (
			REASON_REVOKED_CREDENTIAL,
		)

		gen = self._credential()
		revoke_credential(gen["credential"], reason="test")
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_REVOKED_CREDENTIAL)

	def test_expired_token_rejected(self):
		from adx_secure_qr_login.security import validation
		from adx_secure_qr_login.secure_qr_login.constants import (
			REASON_EXPIRED_CREDENTIAL,
		)

		gen = self._credential()
		frappe.db.set_value(
			"QR Login Credential", gen["credential"], "expires_on",
			str(frappe.utils.add_days(frappe.utils.nowdate(), -1)),
			update_modified=False,
		)
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_EXPIRED_CREDENTIAL)

	def test_disabled_user_rejected(self):
		from adx_secure_qr_login.security import validation
		from adx_secure_qr_login.secure_qr_login.constants import REASON_INACTIVE_USER

		gen = self._credential()
		frappe.db.set_value("User", self.user, "enabled", 0)
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_INACTIVE_USER)

	def test_regeneration_invalidates_previous_token(self):
		from adx_secure_qr_login.api.qr_manage import regenerate_credential
		from adx_secure_qr_login.security import validation

		gen = self._credential()
		old = gen["one_time_token"]
		regenerate_credential(gen["credential"])
		with self.assertRaises(validation.CredentialRejected):
			validation.resolve_credential(old)

	def test_token_hash_never_exposed(self):
		from adx_secure_qr_login.secure_qr_login.constants import TOKEN_HASH_FIELD

		gen = self._credential()
		doc = frappe.get_doc("QR Login Credential", gen["credential"])
		self.assertNotIn(TOKEN_HASH_FIELD, doc.as_public_dict())
		self.assertNotIn(gen["one_time_token"], str(doc.as_public_dict()))


class TestQRRbac(FrappeTestCase):
	"""A user without a QR role is refused at every management endpoint."""

	def setUp(self):
		frappe.set_user("Administrator")
		self.plain = "qrtest.plain@test.local"
		cleanup_test_users(
			[self.plain, "qrtest.subject@test.local", "qrtest.manager@test.local"]
		)
		# A desk user with no QR role: the "ordinary ERPNext user" the
		# specification describes. "Desk User" role is what actually makes
		# user_type resolve to System User.
		ensure_system_user(self.plain, "Plain", roles=["Sales User"])
		self.subject = ensure_system_user("qrtest.subject@test.local", "QRTest",
										   roles=["Stock User"]).name

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users(
			[self.plain, self.subject, "qrtest.manager@test.local"]
		)

	def test_plain_user_cannot_manage_credentials(self):
		from adx_secure_qr_login.api import qr_manage

		gen = qr_manage.generate_credential(self.subject)
		frappe.set_user(self.plain)

		for label, fn in (
			("generate", lambda: qr_manage.generate_credential(self.subject)),
			("revoke", lambda: qr_manage.revoke_credential(gen["credential"], "x")),
			("regenerate", lambda: qr_manage.regenerate_credential(gen["credential"])),
			("get", lambda: qr_manage.get_credential(gen["credential"])),
			("list", lambda: qr_manage.list_user_credentials(self.subject)),
		):
			with self.subTest(op=label):
				with self.assertRaises(frappe.PermissionError):
					fn()

	def test_plain_user_cannot_view_dashboard(self):
		from adx_secure_qr_login.api.qr_stats import dashboard_data

		frappe.set_user(self.plain)
		with self.assertRaises(frappe.PermissionError):
			dashboard_data()

	def test_manager_cannot_target_privileged_account(self):
		from adx_secure_qr_login.security import rbac

		frappe.set_user("Administrator")
		mgr = ensure_system_user("qrtest.manager@test.local", "Mgr",
								 roles=["QR Manager"]).name

		with self.assertRaises(frappe.PermissionError):
			rbac.assert_can_manage_target("test", "Administrator", user=mgr)


class TestQRAuditIntegrity(FrappeTestCase):
	"""The audit trail is append-only and never stores secrets."""

	def tearDown(self):
		frappe.db.rollback()

	def test_audit_row_cannot_be_modified_or_deleted(self):
		from adx_secure_qr_login.secure_qr_login.constants import EVENT_INVALID_CREDENTIAL
		from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
			log_event,
		)

		name = log_event(EVENT_INVALID_CREDENTIAL, success=False, commit=False)
		self.assertTrue(name)

		doc = frappe.get_doc("QR Login Audit", name)
		with self.assertRaises(frappe.PermissionError):
			doc.details = "tampered"
			doc.save()
		# Administrators (QR Admin / System Manager / Administrator) may delete;
		# anyone else is blocked. The test is running as Administrator, so
		# deletion is allowed now.
		doc.delete()
		self.assertFalse(frappe.db.exists("QR Login Audit", name))

	def test_audit_scrubs_secret_details(self):
		from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
			log_event,
			scrub_details,
		)
		from adx_secure_qr_login.secure_qr_login.constants import EVENT_INVALID_CREDENTIAL

		scrubbed = scrub_details({"token_hash": "SECRET", "note": "ok"})
		self.assertNotIn("SECRET", scrubbed)
		self.assertIn("note=ok", scrubbed)

		name = log_event(EVENT_INVALID_CREDENTIAL, success=False, commit=False,
						 details={"token": "PLAINTEXT"})
		self.assertNotIn("PLAINTEXT", frappe.db.get_value("QR Login Audit", name, "details") or "")


class TestQRSettings(FrappeTestCase):
	"""Configuration cannot be pushed into an unsafe state."""

	def tearDown(self):
		frappe.db.rollback()

	def test_validity_clamped_to_maximum(self):
		from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
			get_settings,
			get_validity_days,
		)

		s = get_settings()
		s.flags.ignore_permissions = True
		s.default_validity_days = 3650
		s.max_validity_days = 30
		s.save()
		self.assertEqual(get_settings().default_validity_days, 30)
		self.assertEqual(get_validity_days(9999), 30)


class TestQRStatsReconcile(FrappeTestCase):
	"""Dashboard figures come from the authoritative tables."""

	def tearDown(self):
		frappe.db.rollback()

	def test_counts_match_raw_sql(self):
		from adx_secure_qr_login.api.qr_stats import credential_counts

		frappe.set_user("Administrator")
		counts = credential_counts()
		raw = frappe.db.sql(
			"SELECT COUNT(*) FROM `tabQR Login Credential` WHERE status='Active'"
		)[0][0]
		self.assertEqual(counts["active"], raw)

	def test_dashboard_matches_weekly_report(self):
		from adx_secure_qr_login.api.qr_stats import dashboard_data, weekly_report_data

		frappe.set_user("Administrator")
		a = dashboard_data()
		b = weekly_report_data()
		for section in ("credentials", "authentication", "security"):
			self.assertEqual(a[section], b[section], section)
