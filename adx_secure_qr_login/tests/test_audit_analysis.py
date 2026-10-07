"""QR Login Audit Analysis report: filters, quick filters, grouping, charts, scoping.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_audit_analysis
"""

import json

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_GENERATED,
	EVENT_INVALID_CREDENTIAL,
	EVENT_LOGIN_SUCCESS,
	EVENT_RATE_LIMITED,
	REASON_OK,
)
from adx_secure_qr_login.secure_qr_login.report.qr_login_audit_analysis import (
	qr_login_audit_analysis as report,
)
from adx_secure_qr_login.tests import cleanup_test_users, require_companies, site_companies

COMPANY = (site_companies() or [None])[0]
START, END = "2032-03-01", "2032-03-07"
SUBJECT = "qrtest.aa.subject@test.local"
MANAGER = "qrtest.aa.mgr@test.local"
PLAIN = "qrtest.aa.plain@test.local"
OTHER = "qrtest.aa.other@test.local"
ALL = [SUBJECT, MANAGER, PLAIN, OTHER]


def _make_user(email, roles=("Stock User",), company=COMPANY):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{"doctype": "User", "email": email, "first_name": "AA", "send_welcome_email": 0}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.set("roles", [{"role": r} for r in roles])
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	frappe.db.set_value("User", email, "company", company)
	return email


def _audit(event, when, success, user=None, company=None, reason=REASON_OK):
	doc = frappe.get_doc(
		{
			"doctype": "QR Login Audit",
			"event": event,
			"occurred_on": when,
			"success": 1 if success else 0,
			"reason_code": reason,
			"actor": "Administrator",
			"ip_address": "10.0.0.1",
			"user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
			"details": "token=SHOULD-NEVER-APPEAR",
		}
	)
	if user:
		doc.user = user
	if company:
		doc.company = company
	doc.flags.ignore_permissions = True
	doc.insert(ignore_permissions=True)
	return doc.name


class TestAuditAnalysis(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		cleanup_test_users(ALL)
		_make_user(SUBJECT)
		self._wipe()
		_audit(EVENT_LOGIN_SUCCESS, "2032-03-01 09:00:00", True, SUBJECT, COMPANY)
		_audit(EVENT_LOGIN_SUCCESS, "2032-03-02 10:00:00", True, SUBJECT, COMPANY)
		_audit(EVENT_INVALID_CREDENTIAL, "2032-03-02 11:00:00", False, None, None, "INVALID_CREDENTIAL")
		_audit(EVENT_RATE_LIMITED, "2032-03-03 11:00:00", False, None, None, "RATE_LIMITED")
		_audit(EVENT_GENERATED, "2032-03-03 12:00:00", True, SUBJECT, COMPANY)
		frappe.db.commit()

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		cleanup_test_users(ALL)
		self._wipe()
		frappe.db.sql("delete from `tabUser Permission` where user in %s", (tuple(ALL),))
		frappe.db.commit()

	def _wipe(self):
		frappe.db.sql(
			"delete from `tabQR Login Audit` where occurred_on >= %s and occurred_on < %s",
			("2032-03-01", "2032-03-08"),
		)

	def _run(self, **filters):
		base = {"from_date": START, "to_date": END}
		base.update(filters)
		return report.execute(base)

	@staticmethod
	def _summary(res):
		return {s["label"]: s["value"] for s in res[4]}

	# -- quick filters ------------------------------------------------------

	def test_quick_filter_categories(self):
		cases = {
			"Successful Logins": 2,
			"Failed Logins": 2,
			"All Logins": 4,
			"Security Events": 3,
			"": 5,
		}
		for category, expected in cases.items():
			with self.subTest(category=category):
				columns, data, *_ = self._run(category=category)
				self.assertEqual(len(data), expected)

	def test_matches_dashboard_figures(self):
		from adx_secure_qr_login.api.qr_stats import authentication_counts

		auth = authentication_counts(START, END)
		s = self._summary(self._run())
		self.assertEqual(s["Successful Logins"], auth["successful_logins"])
		self.assertEqual(s["Failed Logins"], auth["failed_attempts"])

	def test_filters_narrow(self):
		self.assertEqual(len(self._run(result="Failed")[1]), 2)
		self.assertEqual(len(self._run(event=EVENT_GENERATED)[1]), 1)
		self.assertEqual(len(self._run(reason_code="RATE_LIMITED")[1]), 1)
		self.assertEqual(len(self._run(user=SUBJECT)[1]), 3)
		self.assertEqual(len(self._run(from_date="2032-03-03", to_date="2032-03-03")[1]), 2)

	# -- grouping / pivot -----------------------------------------------------

	def test_group_by_result(self):
		_, data, *_ = self._run(group_by="Result")
		by = {r["group"]: r["total"] for r in data}
		self.assertEqual(by, {"Success": 3, "Failed": 2})

	def test_group_by_each_dimension_totals_reconcile(self):
		for dim in ("Result", "User", "Day", "Event", "Company"):
			with self.subTest(dim=dim):
				_, data, *_ = self._run(group_by=dim)
				self.assertEqual(sum(r["total"] for r in data), 5)

	def test_group_by_day_is_chronological_and_pivots_by_result(self):
		columns, data, *_ = self._run(group_by="Day", pivot_by="Result")
		self.assertEqual([r["group"] for r in data], ["2032-03-01", "2032-03-02", "2032-03-03"])
		labels = [c["label"] for c in columns]
		self.assertIn("Success", labels)
		self.assertIn("Failed", labels)
		self.assertEqual(sum(r["total"] for r in data), 5)

	def test_pivot_same_as_group_is_ignored(self):
		columns, data, *_ = self._run(group_by="Event", pivot_by="Event")
		self.assertTrue(all("pv_0" not in r for r in data))

	# -- charts ---------------------------------------------------------------

	def test_charts(self):
		donut = self._run(chart="Successful vs Failed Logins")[3]
		self.assertEqual(donut["data"]["datasets"][0]["values"], [2, 2])

		by_day = self._run(chart="Logins by Day")[3]
		self.assertEqual(sum(by_day["data"]["datasets"][0]["values"]), 2)
		self.assertEqual(sum(by_day["data"]["datasets"][1]["values"]), 2)

		events = self._run(chart="Events by Type")[3]
		self.assertEqual(sum(events["data"]["datasets"][0]["values"]), 5)

	def test_chart_respects_filters(self):
		donut = self._run(user=SUBJECT)[3]
		self.assertEqual(donut["data"]["datasets"][0]["values"], [2, 0])

	# -- no secrets -----------------------------------------------------------

	def test_detail_rows_expose_no_secrets(self):
		columns, data, *_ = self._run()
		blob = json.dumps([columns, data], default=str).lower()
		for forbidden in ("should-never-appear", "token_hash", "mozilla/5.0", "user_agent"):
			self.assertNotIn(forbidden, blob)
		device = {r["device"] for r in data if r["device"]}
		self.assertIn("Chrome on Linux", device)

	# -- access ---------------------------------------------------------------

	def test_plain_user_denied(self):
		_make_user(PLAIN)
		frappe.set_user(PLAIN)
		with self.assertRaises(frappe.PermissionError):
			self._run()

	def test_manager_cannot_see_privileged_users_rows(self):
		_make_user(MANAGER, roles=("Stock User", "QR Manager"))
		privileged = _make_user(OTHER, roles=("Stock User", "QR Admin"))
		_audit(EVENT_GENERATED, "2032-03-04 09:00:00", True, privileged, COMPANY)
		frappe.db.commit()

		frappe.set_user("Administrator")
		self.assertEqual(len(self._run(user=privileged)[1]), 1)

		frappe.set_user(MANAGER)
		self.assertEqual(self._run(user=privileged)[1], [])

	def test_manager_does_not_see_other_company(self):
		company_a, company_b = require_companies(2)[:2]
		_make_user(MANAGER, roles=("Stock User", "QR Manager"), company=company_a)
		user_b = _make_user(OTHER, company=company_b)
		for who, company in ((MANAGER, company_a), (OTHER, company_b)):
			frappe.get_doc(
				{
					"doctype": "User Permission",
					"user": who,
					"allow": "Company",
					"for_value": company,
					"apply_to_all_doctypes": 1,
				}
			).insert(ignore_permissions=True)
		_audit(EVENT_GENERATED, "2032-03-04 09:00:00", True, user_b, company_b)
		frappe.db.commit()

		frappe.set_user(MANAGER)
		data = self._run()[1]
		self.assertTrue(data, "manager should still see rows they are allowed to see")
		self.assertFalse([r for r in data if r["user"] == user_b])
		self.assertFalse([r for r in data if r["company"] == company_b])
		donut = self._run(company=company_b)[1]
		self.assertEqual(donut, [])
