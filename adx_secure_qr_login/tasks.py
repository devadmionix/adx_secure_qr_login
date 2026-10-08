# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Scheduled maintenance.

None of these are security controls. Authentication correctness depends only on
`security/validation.py`, which recomputes status and expiry on every attempt.
These jobs exist so that list views, dashboard counts and the audit trail do not
drift from reality between requests.
"""

import frappe

from adx_secure_qr_login.secure_qr_login.constants import (
	CREDENTIAL_STATUS_ACTIVE,
	CREDENTIAL_STATUS_EXPIRED,
)


def refresh_expiry_status():
	"""Flip Active credentials to Expired once their expiry date has passed.

	Batched to avoid a long-running UPDATE on a large table, and limited to rows
	actually needing a change so the common case (nothing expired) is a cheap
	SELECT. Each transition is audited (spec 14 QR_EXPIRED) so a lapse is
	attributable rather than inferred from a status field.
	"""
	from adx_secure_qr_login.secure_qr_login.constants import EVENT_EXPIRED, REASON_OK
	from adx_secure_qr_login.secure_qr_login.doctype.qr_login_audit.qr_login_audit import log_event

	stale = frappe.get_all(
		"QR Login Credential",
		filters={
			"status": CREDENTIAL_STATUS_ACTIVE,
			"expires_on": ("<", frappe.utils.nowdate()),
		},
		fields=["name", "user", "expires_on"],
		limit=500,
	)

	if not stale:
		return {"updated": 0}

	for row in stale:
		frappe.db.set_value(
			"QR Login Credential",
			row["name"],
			"status",
			CREDENTIAL_STATUS_EXPIRED,
			update_modified=False,
		)
		log_event(
			EVENT_EXPIRED,
			user=row["user"],
			credential=row["name"],
			success=True,
			reason_code=REASON_OK,
			details={"expires_on": str(row["expires_on"]), "trigger": "scheduled_sweep"},
			commit=False,
		)

	# No explicit commit: `execute_job` commits when the job returns
	# (frappe/utils/background_jobs.py:303), so the status flips and their audit
	# rows land in one transaction. A mid-loop commit here would leave expired
	# statuses behind whenever a later row failed.
	return {"updated": len(stale)}


def purge_expired_audit():
	"""Delete audit rows beyond the configured retention window.

	Uses raw SQL because the audit DocType deliberately refuses deletion through
	the document layer (`on_trash` throws). Retention is security policy, so the
	only sanctioned removal path is this job, and it leaves a log line recording
	how many rows went and under whose authority.
	"""
	from adx_secure_qr_login.secure_qr_login.doctype.qr_security_settings.qr_security_settings import (
		get_settings,
	)

	days = get_settings().audit_retention_days or 0
	if days <= 0:
		return {"deleted": 0, "reason": "retention_disabled"}

	cutoff = frappe.utils.add_days(frappe.utils.now(), -days)

	# frappe.db.sql returns the raw driver result for DELETE, which for MySQLdb
	# is a tuple (affected_rows,) rather than an int. Normalise it so callers can
	# compare the count directly.
	# `frappe.db.sql()` returns () for a DELETE: it has no result set, so
	# frappe/database/database.py:324-325 bails out before returning anything.
	# The affected-row count has to come from the driver's rowcount.
	frappe.db.sql(
		"""
		DELETE FROM `tabQR Login Audit`
		WHERE occurred_on < %s
		""",
		(cutoff,),
	)
	deleted = frappe.db._cursor.rowcount if frappe.db._cursor else 0

	# No explicit commit: the scheduler commits the job's transaction on return,
	# so the DELETE and the log line below are recorded together.

	frappe.log_error(
		title="QR audit retention purge",
		message=(
			f"Deleted {deleted} audit rows older than {days} days "
			f"(before {cutoff}). Executed by scheduled job."
		),
	)
	return {"deleted": deleted, "cutoff": str(cutoff)}
