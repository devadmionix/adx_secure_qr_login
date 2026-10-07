# Copyright (c) 2026, ADmionix Solutions
# License: MIT

import frappe
from frappe.model.document import Document


class WeeklySecurityReport(Document):
	"""One immutable row per reported Monday-Sunday week.

	Rows are written only by `security.weekly_report` with
	`ignore_permissions=True`. No role holds create/write/delete, so history
	cannot be edited or pruned from the desk; the controller rejects any
	mutation after insert as a second line of defence.
	"""

	def validate(self):
		if self.is_new():
			return
		frappe.throw(
			frappe._("Weekly security reports cannot be modified after creation."),
			frappe.PermissionError,
		)

	def on_trash(self):
		frappe.throw(
			frappe._("Weekly security reports cannot be deleted."),
			frappe.PermissionError,
		)
