"""Multi-company QR login: User.company gate tests.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_user_company

Uses the site's real companies (no Company creation, no chart build).
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_SECURITY_VALIDATION_FAILED,
	REASON_COMPANY_NOT_ASSIGNED,
	REASON_EXPIRED_CREDENTIAL,
	REASON_INACTIVE_USER,
	REASON_REVOKED_CREDENTIAL,
)
from adx_secure_qr_login.tests import cleanup_test_users

COMPANY_A = "Admionix"
COMPANY_B = "Admionix-2"


def _make_user(email, roles=("Stock User",)):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "QRCompany",
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


class TestUserCompanyGate(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(
			[
				"qrtest.company@test.local",
				"qrtest.company.mgr@test.local",
				"qrtest.weekly.plain@test.local",
			]
		)
		self.user = _make_user("qrtest.company@test.local")
		self._set_company(COMPANY_A)

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users(
			[
				self.user,
				"qrtest.company.mgr@test.local",
				"qrtest.weekly.plain@test.local",
			]
		)
		# Same strand-risk as above for this module's 2030 fixture week.
		frappe.db.sql(
			"DELETE FROM `tabQR Login Audit` WHERE `user` IS NULL"
			" AND occurred_on >= %s AND occurred_on < %s",
			("2030-09-23 00:00:00", "2030-09-30 00:00:00"),
		)
		frappe.db.commit()

	# -- helpers ------------------------------------------------------

	def _set_company(self, company):
		frappe.db.set_value("User", self.user, "company", company)

	def _mint(self):
		"""Mint a credential, clearing actives first (cap-safe)."""
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

	# -- Test 1: valid user -------------------------------------------

	def test_valid_user_with_company_resolves(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)
		self.assertEqual(validation.get_user_company(self.user), COMPANY_A)

	# -- Test 2: no company --------------------------------------------

	def test_no_company_rejected(self):
		from adx_secure_qr_login.security import validation

		self._set_company(None)
		gen = self._mint()
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_COMPANY_NOT_ASSIGNED)
		self.assertEqual(ctx.exception.event, EVENT_SECURITY_VALIDATION_FAILED)

	def test_no_company_endpoint_fails_generic(self):
		"""Scanner sees only the generic message; no session is created."""
		from adx_secure_qr_login.api.qr_auth import qr_exchange
		from adx_secure_qr_login.secure_qr_login.constants import (
			GENERIC_LOGIN_FAILURE_MESSAGE,
		)

		self._set_company(None)
		gen = self._mint()
		result = qr_exchange(qr_token=gen["one_time_token"])
		self.assertEqual(result["status"], "failed")
		self.assertEqual(result["message"], GENERIC_LOGIN_FAILURE_MESSAGE)
		self.assertNotIn("company", result["message"].lower())

	# -- Test 3: disabled user ------------------------------------------

	def test_disabled_user_rejected_before_company_check(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		frappe.db.set_value("User", self.user, "enabled", 0)
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_INACTIVE_USER)

	# -- Tests 4/5: expired / revoked -----------------------------------

	def test_expired_credential_rejected(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		frappe.db.set_value(
			"QR Login Credential",
			gen["credential"],
			"expires_on",
			str(frappe.utils.add_days(frappe.utils.nowdate(), -1)),
			update_modified=False,
		)
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_EXPIRED_CREDENTIAL)

	def test_revoked_credential_rejected(self):
		from adx_secure_qr_login.api.qr_manage import revoke_credential
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		revoke_credential(gen["credential"], reason="test")
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_REVOKED_CREDENTIAL)

	# -- Test 6: company isolation via existing permissions --------------

	def test_company_a_user_denied_company_b_by_framework(self):
		"""Isolation comes from ERPNext User Permissions, not from our field."""
		frappe.get_doc(
			{
				"doctype": "User Permission",
				"user": self.user,
				"allow": "Company",
				"for_value": COMPANY_A,
				"apply_to_all_doctypes": 1,
			}
		).insert(ignore_permissions=True)

		doc_a = frappe.get_doc("Company", COMPANY_A)
		doc_b = frappe.get_doc("Company", COMPANY_B)
		self.assertTrue(
			frappe.has_permission("Company", "read", doc_a, user=self.user)
		)
		self.assertFalse(
			frappe.has_permission("Company", "read", doc_b, user=self.user)
		)

	# -- Test 7: role parity ----------------------------------------------

	def test_qr_layer_adds_no_roles(self):
		from adx_secure_qr_login.security import validation

		roles_before = set(frappe.get_roles(self.user))
		gen = self._mint()
		validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(set(frappe.get_roles(self.user)), roles_before)
		self.assertIn("Stock User", roles_before)

	# -- Test 8: admin / system manager not restricted ---------------------

	def test_manager_role_user_with_company_resolves(self):
		from adx_secure_qr_login.security import validation

		_make_user("qrtest.company.mgr@test.local", roles=("System Manager",))
		frappe.db.set_value(
			"User", "qrtest.company.mgr@test.local", "company", COMPANY_A
		)
		self.user = "qrtest.company.mgr@test.local"
		gen = self._mint()
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

	# -- Test 9: company change takes effect immediately --------------------

	def test_company_change_resolves_live(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		validation.resolve_credential(gen["one_time_token"])

		self._set_company(COMPANY_B)
		self.assertEqual(validation.get_user_company(self.user), COMPANY_B)
		# Same credential, no re-mint: the new company governs the next login.
		self.assertEqual(
			validation.resolve_credential(gen["one_time_token"]), gen["credential"]
		)

	# -- invalid company variants -------------------------------------------

	def test_deleted_company_rejected(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		# Bypass Link validation to simulate a deleted Company record.
		frappe.db.set_value("User", self.user, "company", "No Such Company")
		with self.assertRaises(validation.CredentialRejected) as ctx:
			validation.resolve_credential(gen["one_time_token"])
		self.assertEqual(ctx.exception.reason_code, REASON_COMPANY_NOT_ASSIGNED)

	def test_group_company_rejected(self):
		from adx_secure_qr_login.security import validation

		gen = self._mint()
		frappe.db.set_value("Company", COMPANY_A, "is_group", 1)
		try:
			with self.assertRaises(validation.CredentialRejected) as ctx:
				validation.resolve_credential(gen["one_time_token"])
			self.assertEqual(ctx.exception.reason_code, REASON_COMPANY_NOT_ASSIGNED)
		finally:
			frappe.db.set_value("Company", COMPANY_A, "is_group", 0)

	# -- audit ----------------------------------------------------------------

	def test_audit_log_stores_company(self):
		from adx_secure_qr_login.secure_qr_login.constants import (
			EVENT_LOGIN_SUCCESS,
			REASON_OK,
		)
		from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import (
			log_event,
		)

		name = log_event(
			EVENT_LOGIN_SUCCESS,
			user=self.user,
			success=True,
			reason_code=REASON_OK,
			company=COMPANY_A,
			commit=False,
		)
		self.assertEqual(
			frappe.db.get_value("QR Login Audit", name, "company"), COMPANY_A
		)


class TestAutoIssueOnUserCreate(FrappeTestCase):
	"""Admin creates a user -> credential minted + welcome QR email queued."""

	EMAIL = "qrtest.autoissue@test.local"

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users([self.EMAIL])

	def _create_user(self, **overrides):
		fields = {
			"doctype": "User",
			"email": self.EMAIL,
			"first_name": "QRAuto",
			"send_welcome_email": 0,
			"company": COMPANY_A,
			"roles": [{"role": "Stock User"}],
		}
		fields.update(overrides)
		frappe.flags.in_test = False
		try:
			doc = frappe.get_doc(fields)
			doc.insert(ignore_permissions=True)
		finally:
			frappe.flags.in_test = True
		return doc.name

	def test_new_user_gets_credential_and_email(self):
		cleanup_test_users([self.EMAIL])
		frappe.db.set_single_value(
			"QR Security Settings", "auto_issue_credential_on_user_create", 1
		)

		self._create_user()

		creds = frappe.get_all(
			"QR Login Credential", filters={"user": self.EMAIL}, pluck="name"
		)
		self.assertEqual(len(creds), 1)
		self.assertEqual(
			frappe.db.get_value("QR Login Credential", creds[0], "status"), "Active"
		)
		# Stored QR image exists, so the code is visible on the credential.
		from adx_secure_qr_login.security import qr_image

		self.assertTrue(qr_image.qr_file_exists(creds[0]))

	def test_new_user_queues_welcome_email(self):
		"""Welcome mail is composed with the printable QR attached.

		Captures `frappe.sendmail` because queueing requires a configured
		outgoing Email Account, which a test site may not have.
		"""
		import frappe as _frappe

		cleanup_test_users([self.EMAIL])
		sent = []
		original = _frappe.sendmail
		_frappe.sendmail = lambda **kw: sent.append(kw)
		try:
			self._create_user()
		finally:
			_frappe.sendmail = original

		self.assertEqual(len(sent), 1)
		self.assertEqual(sent[0]["recipients"], [self.EMAIL])
		self.assertTrue(sent[0].get("inline_images"))
		self.assertTrue(sent[0]["inline_images"][0]["filename"].endswith(".png"))

	def test_no_company_no_auto_issue(self):
		cleanup_test_users([self.EMAIL])
		frappe.db.set_single_value(
			"QR Security Settings", "auto_issue_credential_on_user_create", 1
		)

		# New docs inherit company defaults from User Permissions, user
		# defaults AND the global tabDefaultValue row (frappe/model/
		# create_new.py). Strip all three so the user is genuinely created
		# without one.
		prev_global_single = frappe.db.get_single_value(
			"Global Defaults", "default_company"
		)
		prev_global_default = frappe.db.get_value(
			"DefaultValue", {"defkey": "company", "parent": "__default"}, "defvalue"
		)
		frappe.db.set_single_value("Global Defaults", "default_company", None)
		# NB: use the API, not frappe.db.delete -- it busts the cached
		# defaults, otherwise earlier tests' cached "Admionix" leaks back in.
		frappe.defaults.clear_default("company", parent="__default")
		frappe.defaults.clear_default("company", parent="Administrator")
		try:
			self._create_user(company=None)
			self.assertEqual(
				frappe.db.count("QR Login Credential", {"user": self.EMAIL}), 0
			)
		finally:
			frappe.db.set_single_value(
				"Global Defaults", "default_company", prev_global_single
			)
			if prev_global_default:
				frappe.defaults.set_default(
					"company", prev_global_default, "__default"
				)

	def test_setting_off_no_auto_issue(self):
		cleanup_test_users([self.EMAIL])
		frappe.db.set_single_value(
			"QR Security Settings", "auto_issue_credential_on_user_create", 0
		)
		try:
			self._create_user()
			self.assertEqual(
				frappe.db.count("QR Login Credential", {"user": self.EMAIL}), 0
			)
		finally:
			frappe.db.set_single_value(
				"QR Security Settings", "auto_issue_credential_on_user_create", 1
			)
