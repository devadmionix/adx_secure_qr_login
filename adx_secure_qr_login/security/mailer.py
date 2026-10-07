# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Immediate email delivery.

`frappe.sendmail(now=True)` registers the send as an `after_commit` callback
so a half-saved document never mails anyone. If that callback does not run or
fails, the message stays "Not Sent" in the Email Queue until the scheduler's
next tick (minutes later) -- which looks like "the email is stuck in the queue".

`send_immediately` keeps the after-commit send and adds a short worker job as a
safety net, so delivery never depends on the scheduler interval. Both paths skip
anything already marked Sent, so the recipient is never mailed twice.
"""

import frappe


def send_immediately(**kwargs):
	"""Send an email as soon as the surrounding transaction commits."""
	kwargs.pop("now", None)
	queue = frappe.sendmail(now=True, **kwargs)

	name = getattr(queue, "name", None)
	if name:
		try:
			frappe.enqueue(
				"frappe.email.doctype.email_queue.email_queue.send_now",
				name=name,
				queue="short",
				enqueue_after_commit=True,
			)
		except Exception:
			# The after-commit send above already covers delivery; the
			# scheduler flush is the last resort. Never fail the caller.
			frappe.log_error(
				title="QR email fallback enqueue failed",
				message=frappe.get_traceback(),
			)

	return queue
