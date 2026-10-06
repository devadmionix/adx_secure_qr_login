# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Scheduled weekly QR security report.

Registered under `scheduler_events["cron"]` in hooks.py. Reads authoritative
tables on every run; no independent counters exist, so the totals cannot drift
from the dashboard (both call api/qr_stats.py).

Email is queued, never sent inline, and a mail failure never marks the run as
failed -- otherwise one bad SMTP host would silently stop all future reporting.
"""

import datetime

import frappe

from frappe import _

from adx_secure_qr_login.api.qr_stats import dashboard_data
from adx_secure_qr_login.security.rbac import assert_is_qr_admin
from adx_secure_qr_login.secure_qr_login.constants import EVENT_SETTING_CHANGED, REASON_OK
from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import log_event
from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
	get_settings,
	report_recipients,
)


def previous_week(reference: str | None = None) -> tuple[str, str]:
	"""Monday..Sunday of the most recently completed week, as ISO dates.

	Always the week *before* the one containing `reference`. Because the cron entry
	fires on Monday, that is exactly the week that has just finished; for any other
	day it is the last complete week.
	"""
	today = frappe.utils.getdate(reference or frappe.utils.nowdate())
	monday_this_week = today - datetime.timedelta(days=today.weekday())
	monday = monday_this_week - datetime.timedelta(days=7)
	sunday = monday + datetime.timedelta(days=6)
	return str(monday), str(sunday)


def build_rows(data: dict) -> list[list[str]]:
	"""Flat label/value table for the email body and the PDF."""
	auth = data["authentication"]
	creds = data["credentials"]
	sec = data["security"]
	frm, to = auth["window"]

	return [
		[_("Period"), f"{frm} to {to}"],
		[_("Successful QR logins"), str(auth["successful_logins"])],
		[_("Failed QR attempts"), str(auth["failed_attempts"])],
		[_("Active credentials"), str(creds["active"])],
		[_("Expired credentials"), str(creds["expired"])],
		[_("Revoked credentials"), str(creds["revoked"])],
		[_("Superseded credentials"), str(creds["superseded"])],
		[_("Security events"), str(sec["security_events"])],
	]


def build_html(data: dict) -> str:
	rows = build_rows(data)
	head = "".join(f"<th style='text-align:left;padding:4px 12px 4px 0'>{c}</th>" for c in
				   (_("Metric"), _("Value")))
	body = "".join(
		f"<tr><td style='padding:4px 12px 4px 0;color:#7c7c7c'>{label}</td>"
		f"<td style='padding:4px 12px 4px 0;font-weight:600'>{value}</td></tr>"
		for label, value in rows
	)

	by_reason = data["security"]["by_reason"]
	detail = ""
	if by_reason:
		items = "".join(
			f"<li style='margin:2px 0'>{reason.replace('_', ' ').title()}: {count}</li>"
			for reason, count in sorted(by_reason.items(), key=lambda kv: -kv[1])[:10]
		)
		detail = (
			f"<h4 style='margin:18px 0 6px;font-size:13px'>{_('Failure reasons')}</h4>"
			f"<ul style='margin:0;padding-left:18px;font-size:12px;color:#525252'>{items}</ul>"
		)

	return (
		f"<p>{_('Automated weekly summary of QR credential activity.')}</p>"
		f"<table style='border-collapse:collapse;font-size:13px'>{head}{body}</table>"
		f"{detail}"
		f"<p style='margin-top:18px;font-size:11px;color:#8a8a8a'>"
		f"{_('Generated automatically from live credential and audit data.')}</p>"
	)


def send_weekly_report(reference: str | None = None) -> dict:
	"""Entry point called by the scheduler.

	Shares `_send` with the manual path so the emailed body can never drift
	between the two.
	"""
	settings = get_settings()

	if not settings.weekly_report_enabled:
		return {"status": "skipped", "reason": "disabled"}

	frm, to = previous_week(reference)

	return _send(settings, frm, to)


@frappe.whitelist(methods=["POST"])
def send_report_now(reference: str | None = None) -> dict:
	"""Send the report on demand -- spec 16 "Manual run: Send Now".

	Deliberately *not* gated on `weekly_report_enabled`: an administrator who
	has switched the schedule off still needs to produce a report for an audit or
	an investigation, and a disabled schedule means "don't do this every Monday",
	not "you may never do this".

	`reference` is any date inside the week to report on, so a missed week can be
	reproduced. Default: last week, same as the schedule.

	QR Admin only -- the report exposes estate-wide security figures.
	"""
	assert_is_qr_admin("send_report_now")

	if reference:
		frappe.utils.validate_date(reference)

	settings = get_settings()
	frm, to = previous_week(reference)

	# The schedule toggle is bypassed deliberately, but the recipient list is
	# still the configured one: a manual run must not be able to mail the
	# security summary somewhere the configuration does not sanction.
	result = _send(settings, frm, to)

	log_event(
		EVENT_SETTING_CHANGED,
		success=result.get("status") == "sent",
		reason_code=REASON_OK,
		actor=frappe.session.user,
		details={
			"trigger": "manual_report",
			"outcome": result.get("status"),
			"window": f"{frm} to {to}",
		},
		commit=True,
	)

	return result


def _send(settings, frm: str, to: str) -> dict:
	"""Collect, address and queue the report for an explicit window."""
	try:
		data = dashboard_data(frm, to)
	except Exception:
		frappe.log_error(
			title="Weekly QR report data collection failed",
			message=frappe.get_traceback(),
		)
		return {"status": "error", "reason": "data_collection"}

	recipients = report_recipients()
	if not recipients:
		frappe.log_error(
			title="Weekly QR security report skipped: no recipients",
			message=(
				"No QR Admin holds a usable email address and no additional "
				"recipients are configured in QR Security Settings."
			),
		)
		return {"status": "skipped", "reason": "no_recipients"}

	subject = f"{_('Weekly QR Security Report')} — {frm} to {to}"

	try:
		frappe.sendmail(
			recipients=recipients,
			subject=subject,
			message=build_html(data),
			now=False,
		)
	except Exception:
		frappe.log_error(
			title="Weekly QR security report email failed",
			message=frappe.get_traceback(),
		)
		return {"status": "error", "reason": "email"}

	return {
		"status": "sent",
		"window": [frm, to],
		"recipients": len(recipients),
		"successful_logins": data["authentication"]["successful_logins"],
		"failed_attempts": data["authentication"]["failed_attempts"],
		"security_events": data["security"]["security_events"],
	}
