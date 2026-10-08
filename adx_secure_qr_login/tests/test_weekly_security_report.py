"""Feature 8: Weekly Security Report tests.

Run with:

    bench --site <site> set-config allow_tests true
    bench --site <site> run-tests --app adx_secure_qr_login \
          --module adx_secure_qr_login.tests.test_weekly_security_report
"""

import datetime

import frappe
from frappe.tests.utils import FrappeTestCase

from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_REVOKED,
	EVENT_EXPIRED_CREDENTIAL,
	EVENT_GENERATED,
	EVENT_INVALID_CREDENTIAL,
	EVENT_LOGIN_SUCCESS,
	REASON_OK,
)

# Fixed reporting week: Mon 23 Sep 2030 - Sun 29 Sep 2030. Deliberately far in
# the future so the dev site's own real audit/credential rows can never fall
# inside it and pollute the counts.
PERIOD_START = "2030-09-23"
PERIOD_END = "2030-09-29"
START_DT = "2030-09-23 00:00:00"
END_EXCLUSIVE = "2030-09-30 00:00:00"


def _make_user(email):
	if not frappe.db.exists("User", email):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": "WeeklyReport",
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)
	doc = frappe.get_doc("User", email)
	doc.flags.ignore_permissions = True
	if "Stock User" not in {r.role for r in doc.get("roles") or []}:
		doc.append("roles", {"role": "Stock User"})
	doc.user_type = "System User"
	doc.enabled = 1
	doc.save(ignore_permissions=True)
	return doc.name


def _make_credential(user, status, issued_on, expires_on, revoked_on=None):
	doc = frappe.get_doc(
		{
			"doctype": "QR Login Credential",
			"user": user,
			"token_hash": "0" * 64,
			"token_prefix": "deadbeef",
			"generation": 1,
			"status": CREDENTIAL_STATUS_ACTIVE,
			"issued_on": issued_on,
			"expires_on": expires_on,
			"issued_by": "Administrator",
		}
	)
	doc.flags.ignore_permissions = True
	doc.insert(ignore_permissions=True)
	# set_value bypasses controller hooks so fixtures keep exact values.
	for field, value in (("status", status), ("revoked_on", revoked_on)):
		frappe.db.set_value(
			"QR Login Credential", doc.name, field, value, update_modified=False
		)
	return doc.name


def _make_audit(event, occurred_on, success=True, user=None, credential=None):
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
	if credential:
		doc.credential = credential
	doc.flags.ignore_permissions = True
	doc.insert(ignore_permissions=True)
	return doc.name


class TestWeeklySecurityReport(FrappeTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.user = _make_user("qrtest.weekly@test.local")
		self._credential_names = []
		self._report_names = []

		# ---- credentials -------------------------------------------------
		# Active at period end: issued before, expiring after, never revoked.
		self._credential_names.append(
			_make_credential(
				self.user,
				CREDENTIAL_STATUS_ACTIVE,
				"2030-09-10 10:00:00",
				"2031-01-01",
			)
		)
		# Became expired during the week (expires_on inside the week).
		self._credential_names.append(
			_make_credential(
				self.user, "Expired", "2030-06-01 10:00:00", "2030-09-25"
			)
		)
		# Revoked during the week.
		self._credential_names.append(
			_make_credential(
				self.user,
				CREDENTIAL_STATUS_REVOKED,
				"2030-08-01 10:00:00",
				"2031-01-01",
				revoked_on="2030-09-26 12:00:00",
			)
		)

		# ---- audit -------------------------------------------------------
		# 3 successful logins inside the week.
		for day in ("2030-09-23 09:00:00", "2030-09-25 18:30:00", "2030-09-29 23:59:58"):
			_make_audit(EVENT_LOGIN_SUCCESS, day, success=True, user=self.user)
		# 2 failed logins inside the week.
		_make_audit(
			EVENT_INVALID_CREDENTIAL, "2030-09-24 11:00:00", success=False
		)
		_make_audit(
			EVENT_EXPIRED_CREDENTIAL, "2030-09-27 22:00:00", success=False
		)
		# Management noise inside the week: must NOT count as failed logins.
		_make_audit(EVENT_GENERATED, "2030-09-26 08:00:00", success=True)
		# Outside the week: must NOT count.
		_make_audit(
			EVENT_LOGIN_SUCCESS, "2030-09-22 23:59:59", success=True, user=self.user
		)
		_make_audit(
			EVENT_LOGIN_SUCCESS, "2030-09-30 00:00:00", success=True, user=self.user
		)
		_make_audit(
			EVENT_INVALID_CREDENTIAL, "2030-09-30 00:00:01", success=False
		)

	def tearDown(self):
		frappe.db.rollback()

	def _generate(self, start=PERIOD_START, end=PERIOD_END):
		from adx_secure_qr_login.security import weekly_report

		return weekly_report._generate(start, end)

	def test_successful_login_count(self):
		result = self._generate()
		self.assertEqual(result["status"], "created")
		self.assertEqual(result["successful_logins"], 3)

	def test_failed_login_count_excludes_management_events(self):
		result = self._generate()
		self.assertEqual(result["failed_attempts"], 2)

	def test_active_credential_count(self):
		result = self._generate()
		# Only the still-live credential: the expired and the revoked one are
		# excluded by date logic, not by current status alone.
		self.assertEqual(result["active_credentials"], 1)

	def test_expired_credential_count(self):
		result = self._generate()
		self.assertEqual(result["expired_credentials"], 1)

	def test_revoked_credential_count(self):
		result = self._generate()
		self.assertEqual(result["revoked_credentials"], 1)

	def test_outside_period_excluded(self):
		from adx_secure_qr_login.security import weekly_report

		# Half-open boundaries: the 22 Sep 23:59:59 row belongs to the prior
		# week, the 30 Sep 00:00:00 rows belong to the next week -- none of
		# them leak into 23 - 29 Sep (asserted by the count tests above).
		prev_week = weekly_report.compute_metrics("2030-09-16", "2030-09-22")
		self.assertEqual(prev_week["successful_logins"], 1)
		self.assertEqual(prev_week["failed_attempts"], 0)

		next_week = weekly_report.compute_metrics("2030-09-30", "2030-10-06")
		self.assertEqual(next_week["successful_logins"], 1)
		self.assertEqual(next_week["failed_attempts"], 1)

		empty = weekly_report.compute_metrics("2020-01-06", "2020-01-12")
		self.assertEqual(empty["successful_logins"], 0)
		self.assertEqual(empty["failed_attempts"], 0)

	def test_duplicate_prevention(self):
		first = self._generate()
		second = self._generate()
		self.assertEqual(first["status"], "created")
		self.assertEqual(second["status"], "exists")
		self.assertEqual(second["report"], first["report"])
		count = frappe.db.count(
			"Weekly Security Report",
			{"period_start": PERIOD_START, "period_end": PERIOD_END},
		)
		self.assertEqual(count, 1)

	def test_previous_week_window(self):
		from adx_secure_qr_login.security import weekly_report

		# Monday 30 Sep 2030 -> reports Mon 23 Sep - Sun 29 Sep.
		self.assertEqual(
			weekly_report.previous_week("2030-09-30"), (PERIOD_START, PERIOD_END)
		)
		# Mid-week reference still yields the last *completed* week.
		self.assertEqual(
			weekly_report.previous_week("2030-10-02"), (PERIOD_START, PERIOD_END)
		)

	def test_week_bounds_are_half_open(self):
		from adx_secure_qr_login.security import weekly_report

		self.assertEqual(
			weekly_report.week_bounds(PERIOD_START, PERIOD_END),
			(START_DT, END_EXCLUSIVE),
		)

	def test_scheduler_entry_point(self):
		import adx_secure_qr_login.hooks as hooks

		jobs = hooks.scheduler_events.get("cron", {})
		self.assertIn("5 0 * * 1", jobs)
		self.assertIn(
			"adx_secure_qr_login.security.weekly_report.generate_for_previous_week",
			jobs["5 0 * * 1"],
		)

	def test_report_record_fields(self):
		result = self._generate()
		doc = frappe.get_doc("Weekly Security Report", result["report"])
		for field in (
			"period_start",
			"period_end",
			"generated_on",
			"successful_logins",
			"failed_attempts",
			"active_credentials",
			"expired_credentials",
			"revoked_credentials",
		):
			self.assertTrue(doc.get(field), field)

	def test_report_is_immutable(self):
		result = self._generate()
		doc = frappe.get_doc("Weekly Security Report", result["report"])
		doc.successful_logins = 9999
		with self.assertRaises(frappe.PermissionError):
			doc.save()
		with self.assertRaises(frappe.PermissionError):
			doc.delete()

	def test_no_secrets_in_report(self):
		result = self._generate()
		doc = frappe.get_doc("Weekly Security Report", result["report"])
		blob = str(doc.as_dict())
		for secret in ("token_hash", "password", "secret", "session"):
			self.assertNotIn(secret, blob.lower())

	def test_permissions_unauthorized_user_blocked(self):
		from adx_secure_qr_login.security import weekly_report

		plain = _make_user("qrtest.weekly.plain@test.local")
		plain_doc = frappe.get_doc("User", plain)
		plain_doc.flags.ignore_permissions = True
		plain_doc.set("roles", [{"role": "Sales User"}])
		plain_doc.save(ignore_permissions=True)

		frappe.set_user(plain)
		with self.assertRaises(frappe.PermissionError):
			weekly_report.generate_weekly_security_report(PERIOD_START, PERIOD_END)
		with self.assertRaises(frappe.PermissionError):
			weekly_report.get_latest_report()

	def test_timezone_uses_site_setting(self):
		from adx_secure_qr_login.security import weekly_report

		tz = weekly_report.get_report_timezone()
		self.assertTrue(tz)
		site_tz = frappe.db.get_single_value("System Settings", "time_zone")
		self.assertEqual(tz, site_tz or "UTC")

	def test_empty_week_returns_zeros_not_error(self):
		from adx_secure_qr_login.security import weekly_report

		metrics = weekly_report.compute_metrics("2020-01-06", "2020-01-12")
		self.assertEqual(
			{metrics[k] for k in (
				"successful_logins",
				"failed_attempts",
				"expired_credentials",
				"revoked_credentials",
			)},
			{0},
		)

	def test_graphical_report_returns_table_chart_and_summary(self):
		from adx_secure_qr_login.secure_qr_login.report.weekly_security_report.weekly_security_report import (
			execute as run_report,
		)

		self._generate()
		columns, data, message, chart, summary = run_report(
			{"from_date": PERIOD_START, "period_end": PERIOD_END, "to_date": PERIOD_END}
		)
		self.assertEqual(len(data), 1)
		self.assertEqual(data[0]["successful_logins"], 3)
		self.assertEqual(data[0]["failed_attempts"], 2)
		self.assertEqual(chart["type"], "bar")
		self.assertEqual(
			[d["name"] for d in chart["data"]["datasets"]],
			["Successful Logins", "Failed Attempts"],
		)
		self.assertEqual(len(summary), 5)

	def test_graphical_report_empty_period(self):
		from adx_secure_qr_login.secure_qr_login.report.weekly_security_report.weekly_security_report import (
			execute as run_report,
		)

		columns, data, message, chart, summary = run_report(
			{"from_date": "2020-01-06", "to_date": "2020-01-12"}
		)
		self.assertEqual(data, [])
		self.assertIsNone(chart)
		self.assertTrue(message)

	def test_graphical_report_unauthorized_blocked(self):
		from adx_secure_qr_login.secure_qr_login.report.weekly_security_report.weekly_security_report import (
			execute as run_report,
		)

		plain = _make_user("qrtest.weekly.plain@test.local")
		plain_doc = frappe.get_doc("User", plain)
		plain_doc.flags.ignore_permissions = True
		plain_doc.set("roles", [{"role": "Sales User"}])
		plain_doc.save(ignore_permissions=True)

		frappe.set_user(plain)
		with self.assertRaises(frappe.PermissionError):
			run_report({"from_date": PERIOD_START, "to_date": PERIOD_END})
