"""Feature 7: Security Dashboard tests.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_security_dashboard
"""

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	EVENT_GENERATED,
	EVENT_INVALID_CREDENTIAL,
	EVENT_LOGIN_SUCCESS,
	REASON_OK,
)
from adx_secure_qr_login.tests import cleanup_test_users

COMPANY_A = "Admionix"
COMPANY_B = "Admionix-2"
PERIOD_START = "2031-01-06"
PERIOD_END = "2031-01-12"


def _make_user(email, roles=("Stock User",)):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "QRDash",
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


def _make_audit(event, occurred_on, success=True, user=None, company=None):
	doc = frappe.get_doc(
		{
			"doctype": "QR Login Audit",
			"event": event,
			"occurred_on": occurred_on,
			"success": 1 if success else 0,
			"reason_code": REASON_OK,
			"actor": "Administrator",
		}
	)
	if user:
		doc.user = user
	if company:
		doc.company = company
	doc.flags.ignore_permissions = True
	doc.insert(ignore_permissions=True)
	return doc.name


class TestSecurityDashboard(FrappeTestCase):
	USERS = (
		"qrtest.dash@test.local",
		"qrtest.dash.manager@test.local",
		"qrtest.dash.plain@test.local",
		"qrtest.dash.other@test.local",
	)

	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(self.USERS)
		self.user = _make_user("qrtest.dash@test.local")
		frappe.db.set_value("User", self.user, "company", COMPANY_A)

		# 2 successes + 1 genuine failure + 1 management event (must NOT
		# count as a failed login).
		_make_audit(EVENT_LOGIN_SUCCESS, "2031-01-06 09:00:00", True, self.user, COMPANY_A)
		_make_audit(EVENT_LOGIN_SUCCESS, "2031-01-08 18:30:00", True, self.user, COMPANY_A)
		_make_audit(EVENT_INVALID_CREDENTIAL, "2031-01-07 11:00:00", False, None, None)
		_make_audit(EVENT_GENERATED, "2031-01-09 08:00:00", True, self.user, COMPANY_A)

	def tearDown(self):
		frappe.db.rollback()
		cleanup_test_users(self.USERS)
		# Committed runs (generate_credential commits) can strand the
		# intentionally user-less fixture rows. Delete them, scoped tightly
		# to this module's far-future fixture week, which holds no real data.
		frappe.db.sql(
			"DELETE FROM `tabQR Login Audit` WHERE `user` IS NULL"
			" AND occurred_on >= %s AND occurred_on < %s",
			(PERIOD_START, "2031-01-13 00:00:00"),
		)
		frappe.db.commit()

	def _dashboard(self, **kw):
		from adx_secure_qr_login.api.qr_stats import dashboard_data

		params = {"frm": PERIOD_START, "to": PERIOD_END}
		params.update(kw)
		return dashboard_data(**params)

	# -- access ----------------------------------------------------------

	def test_admin_and_manager_allowed_plain_denied(self):
		frappe.set_user("Administrator")
		self.assertIn("credentials", self._dashboard())

		_make_user("qrtest.dash.manager@test.local", roles=("QR Manager",))
		frappe.set_user("qrtest.dash.manager@test.local")
		self.assertIn("credentials", self._dashboard())

		_make_user("qrtest.dash.plain@test.local", roles=("Sales User",))
		frappe.set_user("qrtest.dash.plain@test.local")
		from adx_secure_qr_login.api.qr_stats import dashboard_data

		with self.assertRaises(frappe.PermissionError):
			dashboard_data(PERIOD_START, PERIOD_END)

	# -- counts ------------------------------------------------------------

	def test_failed_excludes_management_events(self):
		auth = self._dashboard()["authentication"]
		self.assertEqual(auth["successful_logins"], 2)
		self.assertEqual(auth["failed_attempts"], 1)

	def test_daily_series_reconciles_with_totals(self):
		data = self._dashboard()
		daily = data["daily"]
		self.assertTrue(daily)
		self.assertEqual(
			sum(d["successful"] for d in daily),
			data["authentication"]["successful_logins"],
		)
		self.assertEqual(
			sum(d["failed"] for d in daily), data["authentication"]["failed_attempts"]
		)
		self.assertTrue(all(d["day"] >= PERIOD_START for d in daily))
		self.assertTrue(all(d["day"] <= PERIOD_END for d in daily))

	def test_user_filter_narrows(self):
		other = _make_user("qrtest.dash.other@test.local")
		_make_audit(EVENT_LOGIN_SUCCESS, "2031-01-07 10:00:00", True, other)
		all_auth = self._dashboard()["authentication"]
		one_auth = self._dashboard(user=self.user)["authentication"]
		self.assertEqual(all_auth["successful_logins"], 3)
		self.assertEqual(one_auth["successful_logins"], 2)

	def test_today_filter(self):
		from adx_secure_qr_login.api.qr_stats import authentication_counts

		today = frappe.utils.nowdate()
		_make_audit(EVENT_LOGIN_SUCCESS, frappe.utils.now(), True, self.user)
		counts = authentication_counts(today, today)
		self.assertGreaterEqual(counts["successful_logins"], 1)

	def test_credential_lifecycle_reflected(self):
		from adx_secure_qr_login.api.qr_manage import generate_credential, revoke_credential
		from adx_secure_qr_login.api.qr_stats import credential_counts

		before = credential_counts()
		gen = generate_credential(self.user)
		mid = credential_counts()
		self.assertEqual(mid["active"], before["active"] + 1)
		revoke_credential(gen["credential"], reason="dashboard test")
		after = credential_counts()
		self.assertEqual(after["active"], before["active"])
		self.assertEqual(after["revoked"], before["revoked"] + 1)

	# -- security ------------------------------------------------------------

	def test_no_secrets_in_payload(self):
		import json

		blob = json.dumps(self._dashboard(), default=str).lower()
		for secret in ("token_hash", "password", "secret", "session", "sid"):
			self.assertNotIn(secret, blob)

	def test_audit_rows_immutable(self):
		name = _make_audit(EVENT_LOGIN_SUCCESS, "2031-01-07 10:00:00", True)
		doc = frappe.get_doc("QR Login Audit", name)
		with self.assertRaises(frappe.PermissionError):
			doc.details = "tampered"
			doc.save()

	# -- wiring ----------------------------------------------------------------

	def test_page_exists_with_roles(self):
		doc = frappe.get_doc("Page", "qr-security-dashboard")
		self.assertEqual(doc.module, "Secure QR Login")
		roles = {r.role for r in doc.get("roles") or []}
		self.assertTrue({"QR Admin", "System Manager"} <= roles)

	def test_sidebar_links_dashboard(self):
		items = frappe.get_doc("Workspace Sidebar", "Secure QR Login").get("items")
		self.assertIn(
			("qr-security-dashboard", "Page"),
			[(i.link_to, i.link_type) for i in items],
		)
