# Copyright (c) 2026, ADmionix Solutions
# License: MIT

"""Grant the QR roles to users who should already hold them.

Roles themselves are created automatically by frappe's DocType permission sync
(frappe/core/doctype/doctype/doctype.py:1989-1997), so this patch only has to
handle the role *assignment*, which that sync never touches.

Runs on existing installs. `after_install` covers fresh installs.
"""

import frappe

from adx_secure_qr_login.install import add_roles_to_administrator, create_roles, seed_settings


def execute():
	create_roles()
	seed_settings()
	add_roles_to_administrator()
	frappe.db.commit()
