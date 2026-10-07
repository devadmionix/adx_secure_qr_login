// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// QR Login Device form: Mark Trusted / Unmark Trusted / Revoke Session.
//
// Every button calls an existing endpoint in `api.qr_device`. Those re-check the
// caller's role and company scope on the server, so hiding a button here is a
// convenience, never the control.

frappe.ui.form.on("QR Login Device", {
	refresh(frm) {
		if (frm.is_new()) return;
		if (!frappe.user.has_role(["QR Login Admin", "QR Login Manager"])) return;

		const api = "adx_secure_qr_login.api.qr_device";
		const revoked = !!frm.doc.revoked;
		const trusted = !!frm.doc.trusted;

		const confirm_then = (opts, method) => {
			const dialog = new frappe.ui.Dialog({
				title: opts.title,
				fields: [
					{
						fieldtype: "HTML",
						fieldname: "message",
						options: `<p>${opts.message}</p>`,
					},
				],
				primary_action_label: opts.action,
				primary_action: () => {
					dialog.hide();
					frappe
						.call({
							method: `${api}.${method}`,
							args: { device: frm.doc.name },
							freeze: true,
						})
						.then((r) => {
							if (r && r.message && opts.done) {
								frappe.show_alert({
									message: opts.done(r.message),
									indicator: "green",
								});
							}
							frm.reload_doc();
						});
				},
				secondary_action_label: __("Cancel"),
				secondary_action: () => dialog.hide(),
			});
			dialog.show();
		};

		if (!revoked) {
			if (!trusted) {
				frm.add_custom_button(__("Mark Trusted"), () =>
					confirm_then(
						{
							title: __("Mark this device as trusted?"),
							message: __(
								"This device will be recorded as trusted for {0}.",
								[frappe.utils.escape_html(frm.doc.user)]
							),
							action: __("Mark Trusted"),
							done: () => __("Device marked as trusted"),
						},
						"trust_device"
					)
				);
			} else {
				frm.add_custom_button(__("Unmark Trusted"), () =>
					confirm_then(
						{
							title: __("Remove trusted status?"),
							message: __(
								"This device will no longer be recorded as trusted for {0}.",
								[frappe.utils.escape_html(frm.doc.user)]
							),
							action: __("Unmark Trusted"),
							done: () => __("Device is no longer trusted"),
						},
						"untrust_device"
					)
				);
			}

			frm.add_custom_button(__("Revoke Session"), () =>
				confirm_then(
					{
						title: __("Revoke this device session?"),
						message: __(
							"The associated session will be terminated and the device " +
								"will no longer be allowed to authenticate according to " +
								"the configured device security policy."
						),
						action: __("Revoke"),
						done: (m) =>
							__("Device revoked. Sessions terminated: {0}", [
								m.sessions_terminated || 0,
							]),
					},
					"revoke_device"
				)
			);
		} else {
			frm.dashboard.set_headline(
				`<span class="indicator-pill red">${__("Revoked")}</span>`
			);
		}
	},
});
