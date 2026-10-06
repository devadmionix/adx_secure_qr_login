# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Persistent weekly security report (Feature 8).

Single source of truth for the five weekly figures. Both the scheduler
(`generate_for_previous_week`, Monday 00:05) and the manual desk action call
`generate_weekly_security_report`, so the two paths can never drift apart.

Metric definitions (all windows are `[start, end)` -- inclusive start,
exclusive end -- so millisecond precision can never double-count or drop a
row):

* successful_logins: `QR Login Audit` rows with event "QR Login Success" and
  success=1 inside the week. Page visits, QR generation/downloads and
  password logins are never counted: they are different events.
* failed_attempts: `QR Login Audit` rows with success=0 and a *login-failure*
  event (invalid / expired / revoked credential, inactive user, rate
  limited, security validation failed) inside the week. Credential
  management events (generated, downloaded, regenerated, revoked,
  expired-sweep, setting changes) are excluded.
* active_credentials: credentials live *at the end* of the week, derived
  from dates rather than the current status field: issued before the
  exclusive end, expiring after the period end date, and not revoked before
  the exclusive end.
* expired_credentials: credentials whose `expires_on` date falls inside the
  reported week (i.e. that *became* expired during the week), excluding
  ones revoked before their expiry date (those are revocations, not lapses).
* revoked_credentials: credentials with status "Revoked" whose `revoked_on`
  falls inside the week. Superseded (rotated) credentials are excluded:
  they are routine rotation, not revocation.

Only aggregated counts are stored. No tokens, hashes, passwords or session
material ever reaches this module.
"""

import datetime

import frappe

from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_REVOKED,
	EVENT_LOGIN_SUCCESS,
	FAILED_LOGIN_EVENTS,
)

REPORT_DOCTYPE = "Weekly Security Report"


# ------------------------------------------------------------ access control

def _can_access_report(user: str | None = None) -> bool:
	"""QR Admin, System Manager or Administrator only."""
	user = user or frappe.session.user
	if user == "Administrator":
		return True
	try:
		roles = set(frappe.get_roles(user))
	except Exception:
		return False
	return bool(roles & {"QR Admin", "System Manager"})


def assert_can_access_report(action: str, user: str | None = None) -> None:
	if _can_access_report(user):
		return
	frappe.throw(
		frappe._("You are not permitted to perform this action."),
		frappe.PermissionError,
	)


# ----------------------------------------------------------------- timezone

def get_report_timezone() -> str:
	"""Site timezone for period boundaries.

	Primary source is System Settings `time_zone` (the site's configured
	timezone). Falls back to the app's `weekly_report_timezone` setting and
	finally UTC, so a missing configuration can never break the schedule.
	"""
	try:
		tz = frappe.db.get_single_value("System Settings", "time_zone")
		if tz:
			return tz
	except Exception:
		pass
	try:
		from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
			get_settings,
		)

		if get_settings().weekly_report_timezone:
			return get_settings().weekly_report_timezone
	except Exception:
		pass
	return "UTC"


def _today_in_tz(timezone: str | None = None) -> datetime.date:
	tzname = timezone or get_report_timezone()
	try:
		from zoneinfo import ZoneInfo

		return datetime.datetime.now(ZoneInfo(tzname)).date()
	except Exception:
		return frappe.utils.getdate(frappe.utils.nowdate())


# ------------------------------------------------------------------ windows

def previous_week(reference: str | datetime.date | None = None) -> tuple[str, str]:
	"""Monday..Sunday of the most recently completed week, as ISO date strings.

	Always the week *before* the one containing `reference` (default: today in
	the site timezone), so a Monday run reports exactly the week that has just
	finished and the current incomplete week is never included.
	"""
	if reference:
		ref = frappe.utils.getdate(reference)
	else:
		ref = _today_in_tz()
	monday_this_week = ref - datetime.timedelta(days=ref.weekday())
	monday = monday_this_week - datetime.timedelta(days=7)
	sunday = monday + datetime.timedelta(days=6)
	return monday.isoformat(), sunday.isoformat()


def week_bounds(period_start: str, period_end: str) -> tuple[str, str]:
	"""Half-open `[start, end)` datetime strings for SQL comparisons.

	`start` is Monday 00:00:00 and `end` is the Monday *after* `period_end` at
	00:00:00, so callers use `>= start AND < end` and never `<= 23:59:59`.
	"""
	start_date = frappe.utils.getdate(period_start)
	end_date = frappe.utils.getdate(period_end)
	start_dt = datetime.datetime.combine(start_date, datetime.time.min)
	end_exclusive = datetime.datetime.combine(
		end_date + datetime.timedelta(days=1), datetime.time.min
	)
	return (
		start_dt.strftime("%Y-%m-%d %H:%M:%S"),
		end_exclusive.strftime("%Y-%m-%d %H:%M:%S"),
	)


# ------------------------------------------------------------------- counts

def _count(sql: str, args: tuple) -> int:
	rows = frappe.db.sql(sql, args)
	return int(rows[0][0]) if rows else 0


def compute_metrics(period_start: str, period_end: str) -> dict:
	"""Aggregate the five figures with database-side COUNT(*).

	No document is loaded into Python; every figure is a single
	parameterized COUNT query.
	"""
	start_dt, end_exclusive = week_bounds(period_start, period_end)
	start_date = frappe.utils.getdate(period_start).isoformat()
	end_date = frappe.utils.getdate(period_end).isoformat()

	placeholders = ", ".join(["%s"] * len(FAILED_LOGIN_EVENTS))

	successful = _count(
		"""
		SELECT COUNT(*)
		FROM `tabQR Login Audit`
		WHERE event = %s
		  AND success = 1
		  AND occurred_on >= %s
		  AND occurred_on < %s
		""",
		(EVENT_LOGIN_SUCCESS, start_dt, end_exclusive),
	)

	failed = _count(
		f"""
		SELECT COUNT(*)
		FROM `tabQR Login Audit`
		WHERE success = 0
		  AND event IN ({placeholders})
		  AND occurred_on >= %s
		  AND occurred_on < %s
		""",
		(*FAILED_LOGIN_EVENTS, start_dt, end_exclusive),
	)

	active = _count(
		"""
		SELECT COUNT(*)
		FROM `tabQR Login Credential`
		WHERE issued_on < %s
		  AND expires_on > %s
		  AND (revoked_on IS NULL OR revoked_on >= %s)
		""",
		(end_exclusive, end_date, end_exclusive),
	)

	expired = _count(
		"""
		SELECT COUNT(*)
		FROM `tabQR Login Credential`
		WHERE expires_on >= %s
		  AND expires_on <= %s
		  AND (revoked_on IS NULL OR DATE(revoked_on) >= expires_on)
		""",
		(start_date, end_date),
	)

	revoked = _count(
		"""
		SELECT COUNT(*)
		FROM `tabQR Login Credential`
		WHERE status = %s
		  AND revoked_on >= %s
		  AND revoked_on < %s
		""",
		(CREDENTIAL_STATUS_REVOKED, start_dt, end_exclusive),
	)

	return {
		"period_start": start_date,
		"period_end": end_date,
		"successful_logins": successful,
		"failed_attempts": failed,
		"active_credentials": active,
		"expired_credentials": expired,
		"revoked_credentials": revoked,
	}


# --------------------------------------------------------------- generation

def _insert_report(metrics: dict, commit: bool) -> str:
	doc = frappe.get_doc(
		{
			"doctype": REPORT_DOCTYPE,
			"period_start": metrics["period_start"],
			"period_end": metrics["period_end"],
			"generated_on": frappe.utils.now(),
			"successful_logins": metrics["successful_logins"],
			"failed_attempts": metrics["failed_attempts"],
			"active_credentials": metrics["active_credentials"],
			"expired_credentials": metrics["expired_credentials"],
			"revoked_credentials": metrics["revoked_credentials"],
		}
	)
	doc.flags.ignore_permissions = True
	doc.insert(ignore_permissions=True)
	if commit:
		frappe.db.commit()
	return doc.name


def _generate(
	period_start: str, period_end: str, commit: bool = True
) -> dict:
	"""Shared implementation: compute everything first, then insert once.

	Duplicate-safe: an existing report for the same period is returned
	unchanged. Never creates a partially populated report: the insert happens
	only after all five counts succeed.
	"""
	start = frappe.utils.getdate(period_start).isoformat()
	end = frappe.utils.getdate(period_end).isoformat()
	if start > end:
		frappe.throw(frappe._("Report period start must not be after period end."))

	existing = frappe.db.get_value(
		REPORT_DOCTYPE, {"period_start": start, "period_end": end}, "name"
	)
	if existing:
		return {"status": "exists", "report": existing, "period": [start, end]}

	try:
		metrics = compute_metrics(start, end)
	except Exception:
		frappe.log_error(
			title="Weekly security report data collection failed",
			message=frappe.get_traceback(),
		)
		return {"status": "error", "reason": "data_collection"}

	try:
		name = _insert_report(metrics, commit=commit)
	except Exception:
		frappe.log_error(
			title="Weekly security report creation failed",
			message=frappe.get_traceback(),
		)
		return {"status": "error", "reason": "insert_failed"}

	return {"status": "created", "report": name, **metrics}


@frappe.whitelist(methods=["POST"])
def generate_weekly_security_report(
	period_start: str | None = None, period_end: str | None = None
) -> dict:
	"""Manual generation for an Administrator (desk action / API).

	With no arguments, reports the previous completed week -- the same window
	the scheduler uses. With explicit dates, reports that week instead (e.g.
	regenerating a missed week). Uses the identical calculation as the
	scheduled job. QR Admin / System Manager / Administrator only; the check
	is server-side.
	"""
	assert_can_access_report("generate_weekly_security_report")

	if period_start and period_end:
		frappe.utils.validate_date(period_start)
		frappe.utils.validate_date(period_end)
		start, end = period_start, period_end
	elif period_start or period_end:
		frappe.throw(frappe._("Provide both period start and period end, or neither."))
	else:
		start, end = previous_week()

	return _generate(start, end)


def generate_for_previous_week() -> dict:
	"""Scheduler entry point (Monday 00:05): persist last week's report.

	Runs as the scheduler (Administrator); no session permission check, so a
	missing role assignment can never silently stop reporting. Safe to execute
	multiple times: a second run for the same week returns the existing
	report instead of duplicating it.
	"""
	try:
		start, end = previous_week()
		return _generate(start, end)
	except Exception:
		frappe.log_error(
			title="Weekly security report scheduled run failed",
			message=frappe.get_traceback(),
		)
		return {"status": "error", "reason": "unhandled"}


# ------------------------------------------------------------------ reading

@frappe.whitelist(methods=["GET"])
def get_report_summary(report_name: str) -> dict:
	"""Desk-friendly summary of one stored report (cards + period header)."""
	assert_can_access_report("get_report_summary")

	if not frappe.db.exists(REPORT_DOCTYPE, report_name):
		frappe.throw(frappe._("Report not found."), frappe.DoesNotExistError)

	row = frappe.db.get_value(
		REPORT_DOCTYPE,
		report_name,
		[
			"name",
			"period_start",
			"period_end",
			"generated_on",
			"successful_logins",
			"failed_attempts",
			"active_credentials",
			"expired_credentials",
			"revoked_credentials",
		],
		as_dict=True,
	)
	period = (
		f"{frappe.utils.formatdate(row.period_start, 'dd MMM yyyy')} - "
		f"{frappe.utils.formatdate(row.period_end, 'dd MMM yyyy')}"
	)
	return {
		"name": row.name,
		"period": period,
		"period_start": str(row.period_start),
		"period_end": str(row.period_end),
		"generated_on": str(row.generated_on),
		"cards": [
			{"label": "Successful Logins", "value": row.successful_logins},
			{"label": "Failed Attempts", "value": row.failed_attempts},
			{"label": "Active Credentials", "value": row.active_credentials},
			{"label": "Expired Credentials", "value": row.expired_credentials},
			{"label": "Revoked Credentials", "value": row.revoked_credentials},
		],
		**{k: row[k] for k in (
			"successful_logins",
			"failed_attempts",
			"active_credentials",
			"expired_credentials",
			"revoked_credentials",
		)},
	}


@frappe.whitelist(methods=["GET"])
def get_latest_report() -> dict | None:
	"""Most recent stored report, for dashboard summary cards."""
	assert_can_access_report("get_latest_report")

	name = frappe.db.get_value(
		REPORT_DOCTYPE, {}, "name", order_by="period_start desc"
	)
	if not name:
		return None
	return get_report_summary(name)
