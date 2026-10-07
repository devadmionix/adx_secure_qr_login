// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// QR Login Audit list: quick filters over the existing rows.
//
// The filter definitions come from the server
// (security.audit_analysis.quick_filter_definitions), the same constants the
// dashboard and the analysis report use, so "Failed Logins" means the same
// thing everywhere. Filters only narrow the list; what a user may see at all is
// still decided by the audit DocType's permission rules.

frappe.listview_settings["QR Login Audit"] = {
	onload(listview) {
		const group = __("Quick Filters");
		const apply = (filters) => {
			listview.filter_area.clear().then(() => {
				listview.filter_area.add(filters);
			});
		};

		listview.page.add_inner_button(
			__("Today"),
			() => {
				const today = frappe.datetime.get_today();
				apply([
					[
						"QR Login Audit",
						"occurred_on",
						"between",
						[today, today],
					],
				]);
			},
			group
		);

		const by_server = (label) => () =>
			frappe
				.call({
					method: "adx_secure_qr_login.security.audit_analysis.quick_filter_definitions",
				})
				.then((r) => {
					const defs = r.message || {};
					if (defs[label]) apply(defs[label]);
				});

		["Successful Logins", "Failed Logins", "Security Events", "All Logins"].forEach((label) =>
			listview.page.add_inner_button(__(label), by_server(label), group)
		);

		listview.page.add_inner_button(__("Analysis"), () =>
			frappe.set_route("query-report", "QR Login Audit Analysis")
		);
	},
};
