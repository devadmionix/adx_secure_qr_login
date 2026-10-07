# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Live statistics for the security dashboard and the weekly report.

Every figure is derived from the authoritative tables on each call. No counters
are maintained in parallel, so the dashboard and the emailed report cannot drift
from reality -- and a reconciliation test is trivially satisfiable because both
read the same functions.

Query-level scoping is enforced in permissions/audit_conditions.py, which limits
QR Managers to audit rows for users they may see. Administrator and QR Admin see
everything.
"""

import frappe

from adx_secure_qr_login.security import rbac
from adx_secure_qr_login.security.rbac import assert_is_qr_admin, is_qr_admin
from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_EXPIRED,
	CREDENTIAL_STATUS_REVOKED,
	EVENT_LOGIN_SUCCESS,
	EVENT_RATE_LIMITED,
	FAILED_LOGIN_EVENTS,
)


def _window(frm: str | None = None, to: str | None = None) -> tuple[str, str]:
	"""Resolve a reporting window, defaulting to the last 7 days.

	Returns dates as given; use `_bounds` for the SQL comparison.
	"""
	to = to or frappe.utils.nowdate()
	frm = frm or frappe.utils.add_days(to, -6)
	return frm, to


def _bounds(frm: str | None = None, to: str | None = None) -> tuple[str, str]:
	"""A reporting window as full timestamps.

	`occurred_on` is a Datetime, so comparing it against a bare date makes the
	upper bound `<to> 00:00:00` and silently drops everything recorded on the
	final day -- which for a report run on the morning it closes is exactly the
	data you most want. Expand to the whole day on both ends.

	Without this the two counting paths disagreed: frappe's own `between` operator
	expands the end date, raw SQL does not.
	"""
	from frappe.utils import get_datetime

	start, end = _window(frm, to)
	return str(get_datetime(f"{start} 00:00:00")), str(get_datetime(f"{end} 23:59:59.999999"))


def _visible_user_clause(column: str) -> tuple[str, list]:
	"""A SQL predicate restricting `column` to the users the caller may see.

	Returns (sql_fragment, args), where the fragment includes its own leading
	"AND" so callers can append it to an existing WHERE. Empty means
	unrestricted.
	"""
	visible = rbac.visible_users_for_manager()

	if visible is None:
		return "", []

	if not visible:
		# No visible users: an impossible predicate rather than `IN ()`.
		return f" AND 1 = 0", []

	names = ", ".join(frappe.db.escape(v) for v in visible)
	return f" AND `{column}` IN ({names})", []


def credential_counts() -> dict:
	"""Credential totals by status.

	An unrestricted caller sees the whole estate. A QR Manager sees only the
	credentials belonging to users inside their company scope (spec 17:
	"Permission-aware visibility"), which is why this is not a bare GROUP BY.
	"""
	where, args = _visible_user_clause("user")

	rows = frappe.db.sql(
		f"""
		SELECT status, COUNT(*) AS count
		FROM `tabQR Login Credential`
		WHERE 1 = 1{where}
		GROUP BY status
		""",
		tuple(args),
		as_dict=True,
	)
	# as_dict keys off the result-column label, so COUNT(*) must be aliased
	# explicitly or the row has no "count" key.
	counts = {r["status"]: r["count"] for r in rows}
	return {
		"active": counts.get(CREDENTIAL_STATUS_ACTIVE, 0),
		"expired": counts.get(CREDENTIAL_STATUS_EXPIRED, 0),
		"revoked": counts.get(CREDENTIAL_STATUS_REVOKED, 0),
		"superseded": counts.get("Superseded", 0),
		"total": sum(counts.values()),
	}


def authentication_counts(
	frm: str | None = None,
	to: str | None = None,
	user: str | None = None,
	company: str | None = None,
) -> dict:
	"""Successful and failed QR authentication attempts in a window.

	`user` and `company` are optional display filters (spec 17). They can only
	narrow: what the caller may read at all is decided by the row-level scoping in
	permissions/audit_conditions.py, which every count here is routed through.
	"""
	fr_fr, to_fr = _bounds(frm, to)

	scoped = not is_qr_admin()
	by_event, _ = _permission_scoped_tally(fr_fr, to_fr, user, company, scoped=scoped)

	success = 0
	failed = 0
	if scoped:
		# Only genuine login outcomes count. Management events (generated,
		# downloaded, revoked, ...) are activity, not authentication, and
		# must not inflate the failure figure.
		success = sum(
			count for event, count in by_event.items() if event == EVENT_LOGIN_SUCCESS
		)
		failed = sum(
			count
			for event, count in by_event.items()
			if event in FAILED_LOGIN_EVENTS and event != EVENT_LOGIN_SUCCESS
		)
	else:
		conditions = ["occurred_on BETWEEN %s AND %s"]
		args: list = [fr_fr, to_fr]
		if user:
			conditions.append("`user` = %s")
			args.append(user)
		if company:
			conditions.append("`company` = %s")
			args.append(company)
		rows = frappe.db.sql(
			f"""
			SELECT event, success, COUNT(*) AS count
			FROM `tabQR Login Audit`
			WHERE {" AND ".join(conditions)}
			GROUP BY event, success
			""",
			tuple(args),
			as_dict=True,
		)
		for r in rows:
			if r["event"] == EVENT_LOGIN_SUCCESS:
				if r["success"]:
					success += r["count"]
				else:
					failed += r["count"]
			elif r["event"] in FAILED_LOGIN_EVENTS and not r["success"]:
				failed += r["count"]

	rate_limited = by_event.get(EVENT_RATE_LIMITED, 0)

	return {
		"successful_logins": success,
		"failed_attempts": failed,
		# Spec 17 wants this as its own figure rather than only a line in the
		# reason breakdown: a spike here is the clearest brute-force signal there is.
		"rate_limited_attempts": rate_limited,
		"window": list(_window(frm, to)),
		"filters": {"user": user, "company": company},
	}


def _permission_scoped_tally(
	fr_fr: str,
	to_fr: str,
	user: str | None,
	company: str | None,
	scoped: bool,
) -> tuple[dict[str, int], dict[str, int]]:
	"""(by_event, by_reason) for the window, through the caller's own visibility.

	A QR Manager must only ever see figures for users inside their company
	scope, so their tally is gathered through `frappe.get_list`, which applies
	permission_query_conditions. Administrator and QR Admin are unrestricted, so
	they get the cheaper single grouped query.

	Returns both tallies; the caller picks nothing else.
	"""
	filters = {"occurred_on": ("between", (fr_fr, to_fr))}
	if user:
		filters["user"] = user
	if company:
		filters["company"] = company

	if not scoped:
		where = ["occurred_on BETWEEN %s AND %s"]
		args = [fr_fr, to_fr]
		for key, column in (("user", "user"), ("company", "company")):
			if filters.get(key):
				where.append(f"{column} = %s")
				args.append(filters[key])

		rows = frappe.db.sql(
			f"""
			SELECT event, reason_code, COUNT(*) AS count
			FROM `tabQR Login Audit`
			WHERE {" AND ".join(where)}
			GROUP BY event, reason_code
			""",
			tuple(args),
			as_dict=True,
		)

		by_event: dict[str, int] = {}
		by_reason: dict[str, int] = {}
		for r in rows:
			by_event[r["event"]] = by_event.get(r["event"], 0) + r["count"]
			if r["reason_code"]:
				by_reason[r["reason_code"]] = by_reason.get(r["reason_code"], 0) + r["count"]
		return by_event, by_reason

	# `frappe.get_list`, NOT `frappe.get_all`: get_all's own docstring says it
	# "Will not check for permissions", so it ignores permission_query_conditions
	# entirely and would hand a QR Manager the whole estate's audit trail.
	rows = frappe.get_list(
		"QR Login Audit",
		filters=filters,
		fields=["event", "reason_code"],
		limit_page_length=0,
	)

	by_event = {}
	by_reason = {}
	for r in rows:
		by_event[r["event"]] = by_event.get(r["event"], 0) + 1
		if r["reason_code"]:
			by_reason[r["reason_code"]] = by_reason.get(r["reason_code"], 0) + 1
	return by_event, by_reason


def security_event_counts(
	frm: str | None = None,
	to: str | None = None,
	user: str | None = None,
	company: str | None = None,
) -> dict:
	"""Failure reasons and management events, for the dashboard breakdown."""
	fr_fr, to_fr = _bounds(frm, to)
	by_event, by_reason = _permission_scoped_tally(
		fr_fr, to_fr, user, company, scoped=not is_qr_admin()
	)

	return {
		"by_event": by_event,
		"by_reason": by_reason,
		"security_events": sum(
			count for event, count in by_event.items() if event != EVENT_LOGIN_SUCCESS
		),
		"window": list(_window(frm, to)),
	}


def recent_failures(limit: int = 10) -> list[dict]:
	"""Latest rejected attempts, for the dashboard table."""
	# get_list, not get_all: these rows carry IP addresses, so a Manager must only
	# ever receive the ones inside their own scope.
	return frappe.get_list(
		"QR Login Audit",
		filters={"success": 0},
		fields=["name", "event", "reason_code", "user", "ip_address", "occurred_on"],
		order_by="occurred_on desc",
		limit_page_length=limit,
	)


def recent_credential_changes(limit: int = 10) -> list[dict]:
	"""Latest generate / regenerate / revoke activity."""
	return frappe.get_list(
		"QR Login Audit",
		filters={"event": ["in", ["QR Generated", "QR Regenerated", "QR Revoked"]]},
		fields=["name", "event", "user", "credential", "actor", "occurred_on"],
		order_by="occurred_on desc",
		limit_page_length=limit,
	)


def daily_login_series(
	frm: str | None = None,
	to: str | None = None,
	user: str | None = None,
	company: str | None = None,
) -> list[dict]:
	"""Successful vs failed QR logins per day, for the activity chart.

	One aggregated GROUP BY query -- never loads rows. A QR Manager sees only
	their scoped users (same `_visible_user_clause` as credential counts), so
	the chart can never leak another company's activity.
	"""
	fr_fr, to_fr = _bounds(frm, to)
	where, scope_args = _visible_user_clause("user")

	args: list = [EVENT_LOGIN_SUCCESS]
	placeholders = ", ".join(["%s"] * len(FAILED_LOGIN_EVENTS))
	args.extend(FAILED_LOGIN_EVENTS)
	args.extend([fr_fr, to_fr])

	if user:
		where += " AND `user` = %s"
		args.append(user)
	if company:
		where += " AND `company` = %s"
		args.append(company)

	rows = frappe.db.sql(
		f"""
		SELECT DATE(occurred_on) AS day,
			SUM(CASE WHEN event = %s AND success = 1 THEN 1 ELSE 0 END) AS successful,
			SUM(CASE WHEN success = 0 AND event IN ({placeholders}) THEN 1 ELSE 0 END) AS failed
		FROM `tabQR Login Audit`
		WHERE occurred_on BETWEEN %s AND %s{where}
		GROUP BY DATE(occurred_on)
		ORDER BY day
		""",
		tuple(args),
		as_dict=True,
	)
	return [
		{
			"day": str(r["day"]),
			"successful": int(r["successful"] or 0),
			"failed": int(r["failed"] or 0),
		}
		for r in rows
	]


@frappe.whitelist()
def dashboard_data(
	frm: str | None = None,
	to: str | None = None,
	user: str | None = None,
	company: str | None = None,
) -> dict:
	"""Everything the dashboard renders, in one call.

	Read-only and role-gated. Requires QR Admin or QR Manager; a plain desk user
	receives a PermissionError rather than an empty object, so the endpoint cannot
	be used to infer whether any credential data exists.

	`user` and `company` are the display filters of spec 17. They narrow the
	counts only -- visibility is decided by the DocType's own permission query
	conditions, never by a parameter here.
	"""
	from adx_secure_qr_login.security.rbac import can_manage_credentials

	if not can_manage_credentials():
		frappe.throw(frappe._("Not permitted"), frappe.PermissionError)

	return {
		"credentials": credential_counts(),
		"authentication": authentication_counts(frm, to, user, company),
		"security": security_event_counts(frm, to, user, company),
		"daily": daily_login_series(frm, to, user, company),
		"recent_failures": recent_failures(),
		"recent_changes": recent_credential_changes(),
		"generated_on": frappe.utils.now(),
	}


def weekly_report_data(frm: str | None = None, to: str | None = None) -> dict:
	"""Same figures as the dashboard, for the scheduled report.

	Kept as a separate function so the emailed report and the dashboard can be
	diffed directly in a test -- that equality is the reconciliation proof.
	No display filters: the report is always the whole period.
	"""
	assert_is_qr_admin("weekly_report_data")
	return dashboard_data(frm, to)
