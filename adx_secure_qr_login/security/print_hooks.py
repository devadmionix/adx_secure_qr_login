# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Print support for the QR credential card.

Wired in via the `doc_events` hook in hooks.py.

Note the naming: the handler is a *plain function* rather than a call to
`doc.run_method("before_print")`. A controller method of the same name would be
re-entered by `run_method`, which composes doc_events into every lifecycle call,
giving unbounded recursion.
"""

from base64 import b64encode

import frappe


def before_print_card(doc, method=None, *args, **kwargs) -> None:
	"""Attach the rendered QR to `doc` as a transient attribute.

	Sets `doc.qr_image_data` to a base64 PNG data URI, which the card print
	format embeds. This is deliberately a transient attribute and not a DocType
	field, so the base64 blob can never appear in a form response, a REST list
	payload or a `frappe.client.get_value` result.

	The image is read back from the private File attachment rather than
	re-rendered from the token, so printing works without the plaintext token
	existing in memory.

	`*args, **kwargs` absorbs `print_settings`, which frappe's print pipeline
	passes positionally (`doc.run_method("before_print", print_settings)`).
	"""
	doc.qr_image_data = None

	if doc.get("status") != "Active":
		# Only live credentials get an image on paper. The print format also
		# branches on status, so a revoked card prints as a notice rather than a
		# scannable-but-dead code.
		return

	from adx_secure_qr_login.security import qr_image

	file_name = qr_image.find_qr_file(doc.name)

	if not file_name:
		return

	try:
		content = frappe.get_doc("File", file_name).get_content()
		doc.qr_image_data = f"data:image/png;base64,{b64encode(content).decode('ascii')}"
	except Exception:
		frappe.log_error(title="QR print image load failed", message=frappe.get_traceback())
