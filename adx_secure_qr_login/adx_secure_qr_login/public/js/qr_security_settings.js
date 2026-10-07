// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// QR Security Settings form: the two reporting buttons.
//
// "Send Weekly Report Now" opens the Weekly Report Setup dialog --
// the same wizard the Odoo reference ships as a target="new" popup:
// configure the report, then Save or send it immediately.
//
// "Generate Weekly Security Report" persists a report record for the
// previous week without mailing anyone, so figures can be reviewed
// before the scheduled send.
//
// Both paths call the whitelisted controller methods of the same
// name; this script only decides when each one runs and collects the
// settings. Authorization stays server-side (QR Admin only).

frappe.ui.form.on("QR Security Settings", {
	send_report_now(frm) {
		adx_qr_weekly_report_setup(frm);
	},

	generate_weekly_report(frm) {
		frm.call({
			doc: frm.doc,
			method: "generate_weekly_report",
		});
	},
});

function adx_qr_weekly_report_setup(frm) {
	const doc = frm.doc;
	const saved_recipients = (doc.weekly_report_recipients || "")
		.split(",")
		.map((e) => e.trim())
		.filter(Boolean);

	const dialog = new frappe.ui.Dialog({
		title: __("Weekly Report Setup"),
		fields: [
			{
				fieldtype: "Check",
				fieldname: "enabled",
				label: __("Send a weekly security summary"),
				default: doc.weekly_report_enabled ? 1 : 0,
			},
			{
				fieldtype: "Select",
				fieldname: "weekday",
				label: __("Send on"),
				options: [
					"Monday",
					"Tuesday",
					"Wednesday",
					"Thursday",
					"Friday",
					"Saturday",
					"Sunday",
				].join("\n"),
				default: doc.weekly_report_day || "Monday",
			},
			{
				fieldtype: "Int",
				fieldname: "hour",
				label: __("Hour (0-23)"),
				default: doc.weekly_report_hour == null ? 8 : doc.weekly_report_hour,
			},
			{
				fieldtype: "MultiSelectList",
				fieldname: "recipients",
				label: __("Recipients"),
				description: __(
					"Pick users to receive the report, in addition to the recipient role."
				),
				get_data: (txt) => get_recipient_options(txt),
			},
			{
				fieldtype: "HTML",
				fieldname: "help",
				options: `<p class="text-muted">${__(
					"The report counts logins, failures, credentials and " +
					"sessions for the past 7 days - the same totals the " +
					"dashboard shows. Leave recipients empty to mail the " +
					"configured recipient role."
				)}</p>`,
			},
		],
		primary_action_label: __("Save"),
		primary_action(values) {
			save_settings(values).then(() => dialog.hide());
		},
		secondary_action_label: __("Send Report Now"),
		secondary_action() {
			const values = dialog.get_values();
			if (!values) return;
			// Save first so the send uses exactly what the dialog shows.
			save_settings(values).then(() => {
				frm.call({ doc: frm.doc, method: "send_report_now" });
				dialog.hide();
			});
		},
	});

	// Users whose email can receive the report. Addresses already saved
	// in the settings stay selectable even if they are not a user.
	function get_recipient_options(txt) {
		txt = (txt || "").trim();
		return frappe.db
			.get_list("User", {
				filters: { enabled: 1, user_type: "System User" },
				or_filters: txt
					? [
							["full_name", "like", `%${txt}%`],
							["email", "like", `%${txt}%`],
					  ]
					: undefined,
				fields: ["email", "full_name"],
				limit: 50,
			})
			.then((users) => {
				const options = (users || [])
					.filter((u) => u.email)
					.map((u) => ({
						value: u.email,
						label: u.full_name || u.email,
						description: u.email,
					}));
				saved_recipients.forEach((email) => {
					if (!options.find((o) => o.value === email)) {
						options.push({ value: email, label: email, description: "" });
					}
				});
				return options;
			})
			.catch(() => saved_recipients.map((email) => ({ value: email, label: email })));
	}

	function save_settings(values) {
		const hour = Math.min(Math.max(cint(values.hour), 0), 23);
		// Reuse the form's own save path so the change is audited
		// and clamped exactly like a manual edit.
		return frm
			.set_value({
				weekly_report_enabled: values.enabled ? 1 : 0,
				weekly_report_day: values.weekday,
				weekly_report_hour: hour,
				weekly_report_recipients: (values.recipients || []).join(", "),
			})
			.then(() => frm.save());
	}

	dialog.show();
	if (saved_recipients.length) {
		dialog.fields_dict.recipients.set_value(saved_recipients);
	}
}
