"""User form QR actions: summary + "Generate QR".

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_user_qr_form
"""

import json

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.tests import cleanup_test_users, site_companies

COMPANY = (site_companies() or [None])[0]
TARGET = "qrtest.uform.target@test.local"
PLAIN = "qrtest.uform.plain@test.local"
ADMIN = "qrtest.uform.admin@test.local"
ALL = [TARGET, PLAIN, ADMIN]


def _make_user(email, roles=("Stock User",), company=COMPANY):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{"doctype": "User", "email": email, "first_name": "UForm", "send_welcome_email": 0}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.set("roles", [{"role": r} for r in roles])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	frappe.db.set_value("User", email, "company", company)
	return email


class TestUserQRForm(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(ALL)
		_make_user(TARGET)
		_make_user(PLAIN)
		_make_user(ADMIN, roles=("Stock User", "QR Login Admin"))

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		cleanup_test_users(ALL)

	def test_plain_user_cannot_generate_for_another_user(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr

		frappe.set_user(PLAIN)
		with self.assertRaises(frappe.PermissionError):
			generate_user_qr(TARGET)
		frappe.set_user("Administrator")
		self.assertEqual(frappe.db.count("QR Login Credential", {"user": TARGET}), 0)

	def test_plain_user_cannot_generate_for_self(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr

		frappe.set_user(PLAIN)
		with self.assertRaises(frappe.PermissionError):
			generate_user_qr(PLAIN)

	def test_admin_generates_and_response_has_no_token(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr

		frappe.set_user(ADMIN)
		res = generate_user_qr(TARGET)

		self.assertNotIn("one_time_token", res)
		self.assertNotIn("token_hash", json.dumps(res))
		self.assertTrue(res["qr_svg"].startswith("data:image"))
		doc = frappe.get_doc("QR Login Credential", res["credential"])
		self.assertEqual(doc.user, TARGET)
		self.assertEqual(doc.status, "Active")

		audit = frappe.get_all(
			"QR Login Audit", filters={"credential": res["credential"]}, pluck="name"
		)
		self.assertTrue(audit)

	def test_requires_company(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr

		frappe.db.set_value("User", TARGET, "company", None)
		frappe.set_user(ADMIN)
		with self.assertRaises(frappe.ValidationError):
			generate_user_qr(TARGET)

	def test_refuses_when_qr_login_disabled_for_user(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr

		frappe.db.set_value("User", TARGET, "qr_login_enabled", 0)
		frappe.set_user(ADMIN)
		with self.assertRaises(frappe.ValidationError):
			generate_user_qr(TARGET)

	def test_cannot_target_administrator(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr

		frappe.set_user(ADMIN)
		with self.assertRaises(frappe.PermissionError):
			generate_user_qr("Administrator")

	def test_summary_exposes_no_secrets(self):
		from adx_secure_qr_login.api.qr_manage import generate_user_qr, get_user_qr_summary

		frappe.set_user(ADMIN)
		before = get_user_qr_summary(TARGET)
		self.assertTrue(before["visible"])
		self.assertEqual(before["active_count"], 0)
		self.assertTrue(before["can_manage"])

		generate_user_qr(TARGET)
		after = get_user_qr_summary(TARGET)
		self.assertEqual(after["active_count"], 1)
		self.assertEqual(after["status"], "Active")
		self.assertTrue(after["expires_on"])
		blob = json.dumps(after).lower()
		for forbidden in ("token", "hash", "secret", "payload"):
			self.assertNotIn(forbidden, blob)

	def test_summary_hidden_from_unrelated_user(self):
		from adx_secure_qr_login.api.qr_manage import get_user_qr_summary

		frappe.set_user(PLAIN)
		self.assertEqual(get_user_qr_summary(TARGET), {"visible": False})
		own = get_user_qr_summary(PLAIN)
		self.assertTrue(own["visible"])
		self.assertFalse(own["can_manage"])
