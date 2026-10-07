# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""QR rendering.

Uses `pyqrcode`, which is a declared Frappe dependency (`PyQRCode~=1.2.1` in
frappe/pyproject.toml) and is already exercised by core's two-factor flow via
`frappe.twofactor.get_qr_svg_code`. Deliberately not using `segno` or `qrcode`:
both happen to be present in this virtualenv but neither is declared by Frappe or
ERPNext, so depending on them would break on a clean install.

Error correction is `H` (30% recovery). These codes get printed on cards, stuck
on terminals and photographed off badges, so redundancy is worth the extra
modules: a higher error-correction level does not lengthen the payload.
"""

import base64
from io import BytesIO

import frappe

# pyqrcode accepts "L", "M", "Q", "H".
ERROR_CORRECTION = "H"

_SVG_SCALE = 8
_PNG_SCALE = 10


def render_svg(payload: str, scale: int = _SVG_SCALE) -> str:
	"""Render `payload` as a standalone SVG document."""
	from pyqrcode import create as qrcreate

	stream = BytesIO()
	qrcreate(payload, error=ERROR_CORRECTION).svg(
		stream,
		scale=scale,
		module_color="#000000",
		background="#ffffff",
	)
	return stream.getvalue().decode("utf-8").replace("\n", "")


def render_png(payload: str, scale: int = _PNG_SCALE) -> bytes:
	"""Render `payload` as PNG bytes."""
	from pyqrcode import create as qrcreate

	stream = BytesIO()
	qrcreate(payload, error=ERROR_CORRECTION).png(stream, scale=scale)
	return stream.getvalue()


def svg_data_uri(payload: str, scale: int = _SVG_SCALE) -> str:
	"""Base64 data URI, for inline embedding in HTML and print formats."""
	encoded = base64.b64encode(render_svg(payload, scale).encode("utf-8")).decode("ascii")
	return f"data:image/svg+xml;base64,{encoded}"


# How a stored QR image is located.
#
# Deliberately keyed on `attached_to_field` rather than `file_type`: frappe
# normalises `File.file_type` from "image/png" to the bare extension "PNG" during
# save, so a mime-type filter silently matches nothing. `attached_to_field` is
# the value we set ourselves and is immune to that normalisation.
ATTACHED_FIELD = "qr_image"


def attachment_filters(credential: str) -> dict:
	return {
		"attached_to_doctype": "QR Login Credential",
		"attached_to_name": credential,
		"attached_to_field": ATTACHED_FIELD,
	}


def find_qr_file(credential: str) -> str | None:
	"""Return the File docname holding this credential's QR image.

	PNG only. Both the .png and .svg artifacts share the attachment-field
	key, so an extension filter is applied to keep PNG-only callers safe.
	"""
	f = attachment_filters(credential)
	f["file_name"] = ("like", "%.png")
	return frappe.db.get_value("File", f, "name")


def find_qr_svg_file(credential: str) -> str | None:
	"""The stored SVG rendering of this credential's QR, if any."""
	f = attachment_filters(credential)
	f["file_name"] = ("like", "%.svg")
	return frappe.db.get_value("File", f, "name")


def qr_file_exists(credential: str) -> bool:
	return bool(find_qr_file(credential))


def save_qr_file(payload: str, credential: str, filename_stem: str) -> str | None:
	"""Persist the rendered QR as a private File attached to the credential.

	Why a stored image at all: the plaintext token is never persisted, so without
	this a user could only ever download their QR in the same response that
	minted it -- which makes re-printing a lost card impossible. The stored image
	is the *only* re-printable artifact.

	This is a deliberate trade-off and it must be understood as such: the PNG is
	a faithful rendering of the token, so anyone who can read the file can OCR the
	token back out. Confidentiality of the QR is therefore equivalent to
	confidentiality of the token. It is stored as a private File (not under
	`public/`), and access is gated on credential read permission.

	:returns: the File docname, or None if the write failed.
	"""
	try:
		png = render_png(payload)
	except Exception:
		# A rendering failure must not abort credential creation; the token is
		# still returned to the caller in the API response.
		frappe.log_error(title="QR image render failed", message=frappe.get_traceback())
		return None

	filename = f"{filename_stem}-qr.png"

	file_doc = frappe.get_doc(
		{
			"doctype": "File",
			"file_name": filename,
			"content": png,
			# file_type is intentionally omitted: frappe derives it from the
			# content/extension and stores the short form ("PNG").
			"attached_to_doctype": "QR Login Credential",
			"attached_to_name": credential,
			"attached_to_field": ATTACHED_FIELD,
			"is_private": 1,
		}
	)
	file_doc.flags.ignore_permissions = True
	file_doc.save(ignore_permissions=True)

	# Also store the SVG twin so admins can download a crisp version from
	# the credential card. It carries the same QR content as the PNG --
	# never more, never less sensitive.
	try:
		svg_bytes = render_svg(payload).encode("utf-8")
		svg_file = frappe.get_doc(
			{
				"doctype": "File",
				"file_name": f"{filename_stem}-qr.svg",
				"content": svg_bytes,
				"attached_to_doctype": "QR Login Credential",
				"attached_to_name": credential,
				"attached_to_field": ATTACHED_FIELD,
				"is_private": 1,
			}
		)
		svg_file.flags.ignore_permissions = True
		svg_file.save(ignore_permissions=True)
	except Exception:
		frappe.log_error(title="QR SVG render failed", message=frappe.get_traceback())

	return file_doc.name


def delete_qr_files(credential: str) -> None:
	"""Remove stored QR images for a credential.

	Called on revoke so a withdrawn credential leaves no printable artifact
	behind on disk.

	Deletes the File *document*, not `frappe.delete_file(path)`: that helper takes
	a file path and silently does nothing when handed a docname, which would leave
	both the row and the bytes on disk.
	"""
	for name in frappe.get_all("File", attachment_filters(credential), pluck="name"):
		try:
			# File.on_trash removes the physical content as well as the row.
			frappe.delete_doc("File", name, force=True, ignore_permissions=True)
		except Exception:
			frappe.log_error(title="QR image cleanup failed", message=frappe.get_traceback())
