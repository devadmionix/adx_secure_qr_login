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
from adx_secure_qr_login.security.mailer import send_immediately
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
		[_("Active QRs"), str(creds["active"])],
		[_("Expired QRs"), str(creds["expired"])],
		[_("Revoked QRs"), str(creds["revoked"])],
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


PDF_MAX_ROWS = 5000

_REASON_TEXT = {
	"INVALID_CREDENTIAL": "Invalid credential.",
	"EXPIRED_CREDENTIAL": "Credential expired.",
	"REVOKED_CREDENTIAL": "Credential revoked.",
	"SUPERSEDED_CREDENTIAL": "Credential replaced.",
	"INACTIVE_USER": "Inactive account.",
	"COMPANY_NOT_ASSIGNED": "No company assigned.",
	"RATE_LIMITED": "Rate limited.",
	"REPLAY_DETECTED": "Token already used.",
	"LOCKED": "Credential locked.",
	"CONCURRENT_SESSION": "Concurrent session limit.",
	"SECURITY_VALIDATION_FAILED": "Security validation failed.",
	"UNAUTHORIZED": "Not permitted.",
}

_EVENT_TEXT = {
	"QR Login Success": "QR login success.",
	"QR Generated": "Credential generated",
	"QR Regenerated": "Credential regenerated",
	"QR Revoked": "Credential revoked",
	"QR Downloaded": "QR downloaded",
	"QR Expired": "Credential expired",
	"Session Revoked": "Session revoked",
	"User Disabled": "User disabled",
	"Device Registered": "Device registered",
	"Device Revoked": "Device revoked",
	"Device Trusted": "Device trusted",
	"Device Untrusted": "Device untrusted",
	"Security Setting Changed": "Security setting changed",
	"Unauthorized QR Management": "Unauthorized management attempt",
}


def _result_text(row) -> str:
	if row["success"]:
		return _("Success")
	return {
		"LOCKED": _("Locked"),
		"REPLAY_DETECTED": _("Replay"),
		"RATE_LIMITED": _("Rate limited"),
	}.get(row.get("reason_code"), _("Failed"))


def _reason_text(row, names: dict) -> str:
	"""One human sentence per row. Built from fixed text and ids -- never from the
	free-text `details` column, which is not guaranteed to be safe to print."""
	event = row["event"]
	if not row["success"]:
		return _(_REASON_TEXT.get(row.get("reason_code"), "Refused."))
	text = _(_EVENT_TEXT.get(event, event))
	if event in ("QR Generated", "QR Regenerated", "QR Revoked") and row.get("actor"):
		text = f"{text} {_('by')} {names.get(row['actor'], row['actor'])}"
	return text


def build_audit_rows(frm: str, to: str) -> tuple[list[dict], bool]:
	"""Audit rows for the window, newest first.

	Estate-wide on purpose: the weekly report is a QR Admin / scheduler
	artefact (see `send_report_now`), the same scope as `dashboard_data` for an
	admin. `get_all` is used because the scheduler has no session to scope by.
	"""
	from frappe.utils import get_datetime

	rows = frappe.get_all(
		"QR Login Audit",
		filters={
			"occurred_on": (
				"between",
				[
					str(get_datetime(f"{frm} 00:00:00")),
					str(get_datetime(f"{to} 23:59:59.999999")),
				],
			)
		},
		fields=[
			"occurred_on",
			"user",
			"actor",
			"event",
			"success",
			"reason_code",
			"credential",
			"ip_address",
		],
		order_by="occurred_on desc",
		limit_page_length=PDF_MAX_ROWS + 1,
	)
	return rows[:PDF_MAX_ROWS], len(rows) > PDF_MAX_ROWS


def build_pdf_html(frm: str, to: str) -> str:
	"""The "Login Audit Log" PDF: summary boxes plus one row per audit event."""
	from adx_secure_qr_login.security import audit_analysis as aa

	esc = frappe.utils.escape_html
	rows, truncated = build_audit_rows(frm, to)

	people = {r["user"] for r in rows if r.get("user")} | {r["actor"] for r in rows if r.get("actor")}
	names = {
		u.name: (u.first_name or u.full_name or u.name)
		for u in frappe.get_all(
			"User",
			filters={"name": ("in", list(people) or [""])},
			fields=["name", "first_name", "full_name"],
		)
	}

	total = len(rows)
	successful = sum(1 for r in rows if r["success"])
	failed = total - successful
	replays = sum(1 for r in rows if r.get("reason_code") == "REPLAY_DETECTED")
	logins = sum(1 for r in rows if r["event"] in aa.LOGIN_EVENTS)
	admin_events = total - logins

	def box(value, label, extra=""):
		return (
			f"<td class='box'><div class='n'>{value}</div><div class='l'>{esc(label)}</div>{extra}</td>"
		)

	boxes = "".join(
		[
			box(total, _("Total events")),
			box(successful, _("Successful")),
			box(failed, _("Failed / refused")),
			box(replays, _("Blocked replays")),
			box(
				logins,
				_("Login attempts"),
				f"<div class='l'>{esc(_('Admin events'))}: {admin_events}</div>",
			),
		]
	)

	body = []
	for r in rows:
		is_login = r["event"] in aa.LOGIN_EVENTS
		# A login row with no user is an unidentified attempt; the `actor` on it is
		# only whoever the audit writer ran as, so it must not be shown as the user.
		who = r.get("user") or (None if is_login else r.get("actor"))
		body.append(
			"<tr>"
			f"<td class='nw'>{esc(str(frappe.utils.get_datetime(r['occurred_on']).replace(microsecond=0)))}</td>"
			f"<td>{esc(names.get(who, who) if who else _('Unknown'))}</td>"
			f"<td>{esc(_('Login') if is_login else _('Security Event'))}</td>"
			f"<td>{esc(_result_text(r))}</td>"
			f"<td class='nw'>{esc(r.get('credential') or '-')}</td>"
			f"<td class='nw'>{esc(r.get('ip_address') or '-')}</td>"
			f"<td>{esc(_reason_text(r, names))}</td>"
			"</tr>"
		)

	note = (
		f"<p class='note'>{esc(_('Only the newest {0} events are shown.').format(PDF_MAX_ROWS))}</p>"
		if truncated
		else ""
	)

	return f"""<html><head><meta charset="utf-8"><style>
		body {{ font-family: Helvetica, Arial, sans-serif; font-size: 11px; color: #171717; }}
		h1 {{ font-size: 22px; margin: 0 0 2px; }}
		.sub {{ color: #666; margin-bottom: 14px; }}
		table.boxes {{ width: 100%; border-collapse: separate; border-spacing: 6px 0; margin: 0 -6px 16px; }}
		td.box {{ border: 1px solid #ddd; border-radius: 4px; padding: 8px 10px; width: 20%; vertical-align: top; }}
		.n {{ font-size: 20px; font-weight: bold; }}
		.l {{ color: #666; font-size: 10px; }}
		table.log {{ width: 100%; border-collapse: collapse; }}
		table.log th {{ background: #f3f3f3; text-align: left; padding: 5px 6px; font-size: 10px;
			text-transform: uppercase; border-bottom: 1px solid #ccc; }}
		table.log td {{ padding: 5px 6px; border-bottom: 1px solid #eee; vertical-align: top; }}
		table.log thead {{ display: table-header-group; }}
		table.log tr {{ page-break-inside: avoid; }}
		.nw {{ white-space: nowrap; }}
		.note {{ color: #a05a00; }}
		.foot {{ margin-top: 12px; color: #888; font-size: 9px; }}
	</style></head><body>
	<h1>{esc(_("Login Audit Log"))}</h1>
	<div class="sub">{esc(_("{0} event(s) from {1} to {2}").format(total, frm, to))}</div>
	<table class="boxes"><tr>{boxes}</tr></table>
	{note}
	<table class="log">
		<thead><tr>
			<th>{esc(_("Time"))}</th><th>{esc(_("User"))}</th><th>{esc(_("Type"))}</th>
			<th>{esc(_("Result"))}</th><th>{esc(_("Credential"))}</th>
			<th>{esc(_("IP Address"))}</th><th>{esc(_("Reason"))}</th>
		</tr></thead>
		<tbody>{"".join(body) or f"<tr><td colspan='7'>{esc(_('No audit events in this period.'))}</td></tr>"}</tbody>
	</table>
	<div class="foot">{esc(_("Contains no QR tokens or secrets."))}</div>
	</body></html>"""


def _company_label() -> str:
	return (
		frappe.defaults.get_global_default("company")
		or frappe.db.get_single_value("Global Defaults", "default_company")
		or frappe.local.site
	)


def _stamp_header_footer(pdf: bytes, company: str) -> bytes:
	"""Overlay "<company>" (top right) and "Page i / n" (bottom right) on every page.

	The installed wkhtmltopdf is not the patched-Qt build, so its own
	header/footer options are silently ignored. Stamping afterwards works with any
	build. Falls back to the unstamped PDF if anything goes wrong.
	"""
	try:
		import io

		from pypdf import PdfReader, PdfWriter
		from reportlab.pdfgen import canvas

		reader = PdfReader(io.BytesIO(pdf))
		writer = PdfWriter()
		total = len(reader.pages)

		for number, page in enumerate(reader.pages, start=1):
			width = float(page.mediabox.width)
			height = float(page.mediabox.height)
			buf = io.BytesIO()
			c = canvas.Canvas(buf, pagesize=(width, height))
			c.setFont("Helvetica", 8)
			c.setFillGray(0.35)
			c.drawRightString(width - 42, height - 30, company)
			c.drawRightString(width - 42, 24, f"Page {number} / {total}")
			c.save()
			buf.seek(0)
			page.merge_page(PdfReader(buf).pages[0])
			writer.add_page(page)

		out = io.BytesIO()
		writer.write(out)
		return out.getvalue()
	except Exception:
		frappe.log_error(
			title="Weekly QR report PDF header/footer failed",
			message=frappe.get_traceback(),
		)
		return pdf


def build_pdf(frm: str, to: str) -> bytes | None:
	"""Render the audit-log PDF for the window. Returns None (and logs) on failure.

	A broken PDF toolchain must not stop the summary email itself from going
	out, so callers treat None as "send without attachment".
	"""
	try:
		from frappe.utils.pdf import get_pdf

		pdf = get_pdf(
			build_pdf_html(frm, to),
			options={"margin-top": "16mm", "margin-bottom": "16mm"},
		)
		return _stamp_header_footer(pdf, _company_label())
	except Exception:
		frappe.log_error(
			title="Weekly QR security report PDF failed",
			message=frappe.get_traceback(),
		)
		return None


def send_scheduled_weekly_report() -> dict:
	"""Hourly scheduler tick: send only when the configured day/hour is due."""
	settings = get_settings()

	if not settings.weekly_report_enabled:
		return {"status": "skipped", "reason": "disabled"}

	try:
		from zoneinfo import ZoneInfo

		now = datetime.datetime.now(ZoneInfo(settings.weekly_report_timezone or "UTC"))
	except Exception:
		now = datetime.datetime.utcnow()

	day = settings.weekly_report_day or "Monday"
	hour = 8 if settings.weekly_report_hour is None else int(settings.weekly_report_hour)

	if now.strftime("%A") != day or now.hour != hour:
		return {"status": "skipped", "reason": "not_due"}

	return send_weekly_report()


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
		frappe.utils.getdate(reference)  # raises on an invalid date

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

	pdf = build_pdf(frm, to)
	attachments = (
		[{"fname": f"QR-Audit-Log-{frm}-to-{to}.pdf", "fcontent": pdf}] if pdf else None
	)

	try:
		send_immediately(
			recipients=recipients,
			subject=subject,
			message=build_html(data),
			attachments=attachments,
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
		"pdf_attached": bool(pdf),
	}
