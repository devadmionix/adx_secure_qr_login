# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe
from frappe.model.document import Document

from adx_secure_qr_login.secure_qr_login.constants import (
	EVENT_SETTING_CHANGED,
	REASON_OK,
	ROLE_ADMIN,
)

DEFAULT_VALIDITY_DAYS = 30
MAX_VALIDITY_DAYS = 90


class QRSecuritySettings(Document):
	# doctype: qr.security.settings.single

	def validate(self):
		self.record_security_changes()
		self.clamp_validity()
		self.normalise_recipients()

	def send_report_now(self):
		"""Spec 16 "Manual run: Send Now".

		Bound to the Button of the same name. Reports the *previous* week, the
		same window the scheduled job uses, so a manual run and an automated one
		are never comparable across different periods by accident.
		"""
		from adx_secure_qr_login.reports.weekly_security_report import send_report_now

		result = send_report_now()

		if result.get("status") == "sent":
			frm, to = result["window"]
			frappe.msgprint(
				frappe._(
					"Weekly QR Security Report queued for {0} recipient(s) covering {1} to {2}."
				).format(result["recipients"], frm, to),
				indicator="green",
			)
		else:
			# Reasons are safe to show: "disabled", "no_recipients", "email",
			# "data_collection" are configuration states, not credential facts.
			frappe.msgprint(
				frappe._("Report not sent ({0}).").format(result.get("reason", "unknown")),
				indicator="orange",
			)

		return result

	def generate_weekly_report(self):
		"""Feature 8 manual run: persist a report for the previous week.

		Bound to the Button of the same name. Calls the same
		`security.weekly_report` service as the Monday 00:05 scheduler job, so
		manual and automatic figures can never diverge. Unlike `send_report_now`
		(email), this stores a `Weekly Security Report` record for history.
		"""
		from adx_secure_qr_login.security.weekly_report import (
			generate_weekly_security_report,
			previous_week,
		)

		frm, to = previous_week()
		result = generate_weekly_security_report(frm, to)

		if result.get("status") == "created":
			frappe.msgprint(
				frappe._(
					"Weekly Security Report {0} created for {1} to {2}: "
					"{3} successful logins, {4} failed attempts, "
					"{5} active / {6} expired / {7} revoked credentials."
				).format(
					result["report"],
					frm,
					to,
					result["successful_logins"],
					result["failed_attempts"],
					result["active_credentials"],
					result["expired_credentials"],
					result["revoked_credentials"],
				),
				indicator="green",
			)
		elif result.get("status") == "exists":
			frappe.msgprint(
				frappe._("Report for {0} to {1} already exists ({2}).").format(
					frm, to, result["report"]
				),
				indicator="blue",
			)
		else:
			frappe.msgprint(
				frappe._("Report not created ({0}).").format(
					result.get("reason", "unknown")
				),
				indicator="orange",
			)

		return result

	def on_update(self):
		self.clamp_validity()

	def record_security_changes(self):
		"""Audit every setting change (spec 14 SECURITY_SETTING_CHANGED).

		Security-relevant fields only: operational cosmetics are not worth an audit
		row, but anything that changes how strictly the system polices access must
		be attributable -- including the attempt to switch audit logging off.
		"""
		if self.is_new():
			return

		WATCHED = (
			"qr_login_enabled",
			"show_login_option",
			"allow_self_service_qr",
			"auto_issue_credential_on_user_create",
			"default_validity_days",
			"max_validity_days",
			"max_active_credentials_per_user",
			"revoke_prior_on_regenerate",
			"destroy_prior_session",
			"rate_limit_attempts",
			"rate_limit_window_seconds",
			"max_failed_attempts_per_credential",
			"require_2fa_on_qr_login",
			"audit_logging_enabled",
			"manager_company_scope_enabled",
			"allow_self_download",
			"require_https",
			"weekly_report_enabled",
			"weekly_report_recipient_role",
			"audit_retention_days",
		)

		# QR Security Settings is a Single: its values live in `tabSingles`, not
		# in a table, so `frappe.db.get_value` raises on it. Use the Singles API.
		previous = frappe.db.get_singles_dict("QR Security Settings", cast=True)
		if not previous:
			return

		changes = {
			field: {"from": previous.get(field), "to": self.get(field)}
			for field in WATCHED
			if previous.get(field) != self.get(field)
		}
		if not changes:
			return

		from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import log_event

		log_event(
			EVENT_SETTING_CHANGED,
			success=True,
			reason_code=REASON_OK,
			actor=frappe.session.user,
			details={"changed": ", ".join(sorted(changes))},
			commit=False,
		)

	def clamp_validity(self):
		"""Keep the configured window internally consistent.

		An explicit `default_validity_days` larger than `max_validity_days` would
		otherwise silently mint credentials that outlive the administrator's
		intended ceiling.
		"""
		maximum = self.get("max_validity_days") or MAX_VALIDITY_DAYS
		if maximum < 1:
			self.max_validity_days = MAX_VALIDITY_DAYS
			maximum = MAX_VALIDITY_DAYS

		default = self.get("default_validity_days") or DEFAULT_VALIDITY_DAYS
		self.default_validity_days = min(max(default, 1), maximum)

	def normalise_recipients(self):
		if not self.weekly_report_recipients:
			return
		parts = [p.strip() for p in self.weekly_report_recipients.split(",")]
		self.weekly_report_recipients = ", ".join(p for p in parts if p)


def get_settings() -> "QRSecuritySettings":
	settings = frappe.get_single("QR Security Settings")
	if not settings.name:
		settings.flags.ignore_permissions = True
	return settings


def get_validity_days(requested: int | None = None) -> int:
	"""Resolve how many days a new credential should be valid for.

	:param requested: explicitly requested days, already checked against the
	    maximum by the caller that will write the document.
	"""
	settings = get_settings()
	maximum = settings.max_validity_days or MAX_VALIDITY_DAYS
	if requested:
		return max(1, min(int(requested), maximum))
	return min(settings.default_validity_days or DEFAULT_VALIDITY_DAYS, maximum)


def is_qr_login_enabled() -> bool:
	return bool(get_settings().qr_login_enabled)


def report_recipients() -> list[str]:
	"""Email addresses for the weekly report, derived from the configured role."""
	settings = get_settings()
	recipients: list[str] = []

	if settings.weekly_report_recipient_role:
		recipients.extend(
			frappe.get_all(
				"Has Role",
				filters={"role": settings.weekly_report_recipient_role, "parenttype": "User"},
				pluck="parent",
			)
		)

	if not recipients and settings.weekly_report_recipient_role == ROLE_ADMIN:
		recipients = frappe.get_all("User", filters={"enabled": 1, "user_type": "System User"}, pluck="name")

	emails = [
		frappe.db.get_value("User", user, "email")
		for user in dict.fromkeys(recipients)
	]
	emails = [e for e in emails if e]

	for extra in (settings.weekly_report_recipients or "").split(","):
		extra = extra.strip()
		if extra and extra not in emails:
			emails.append(extra)

	return emails
