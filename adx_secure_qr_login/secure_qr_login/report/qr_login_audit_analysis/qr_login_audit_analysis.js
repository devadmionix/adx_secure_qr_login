// Copyright (c) 2026, ADmionix Solutions
// License: MIT

// QR Login Audit Analysis: filters, quick filters, Print / PDF.
//
// All figures come from the server report, which applies the caller's role,
// manager scope and Company User Permissions. Nothing here widens access.

frappe.query_reports["QR Login Audit Analysis"] = {
	filters: [
		{
			fieldname: "from_date",
			label: __("From Date"),
			fieldtype: "Date",
			default: frappe.datetime.add_days(frappe.datetime.get_today(), -6),
		},
		{
			fieldname: "to_date",
			label: __("To Date"),
			fieldtype: "Date",
			default: frappe.datetime.get_today(),
		},
		{ fieldname: "user", label: __("User"), fieldtype: "Link", options: "User" },
		{ fieldname: "company", label: __("Company"), fieldtype: "Link", options: "Company" },
		{
			fieldname: "event",
			label: __("Event"),
			fieldtype: "Select",
			options: [""].concat(
				frappe.meta.get_docfield("QR Login Audit", "event")
					? (frappe.meta.get_docfield("QR Login Audit", "event").options || "").split("\n")
					: []
			),
		},
		{
			fieldname: "result",
			label: __("Result"),
			fieldtype: "Select",
			options: ["", "Success", "Failed"],
		},
		{ fieldname: "reason_code", label: __("Reason Code"), fieldtype: "Data" },
		{
			fieldname: "category",
			label: __("Quick Filter"),
			fieldtype: "Select",
			options: ["", "All Logins", "Successful Logins", "Failed Logins", "Security Events"],
		},
		{
			fieldname: "group_by",
			label: __("Group By"),
			fieldtype: "Select",
			options: ["", "Result", "User", "Day", "Event", "Company"],
		},
		{
			fieldname: "pivot_by",
			label: __("Pivot By"),
			fieldtype: "Select",
			options: ["", "Result", "User", "Day", "Event", "Company"],
		},
		{
			fieldname: "chart",
			label: __("Chart"),
			fieldtype: "Select",
			options: ["Successful vs Failed Logins", "Logins by Day", "Events by Type"],
			default: "Successful vs Failed Logins",
		},
	],

	onload(report) {
		const set = (values) => {
			Object.entries(values).forEach(([k, v]) => report.set_filter_value(k, v));
			report.refresh();
		};
		const today = frappe.datetime.get_today();

		const quick = __("Quick Filters");
		report.page.add_inner_button(__("Today"), () => set({ from_date: today, to_date: today }), quick);
		report.page.add_inner_button(__("Successful Logins"), () => set({ category: "Successful Logins" }), quick);
		report.page.add_inner_button(__("Failed Logins"), () => set({ category: "Failed Logins" }), quick);
		report.page.add_inner_button(__("Security Events"), () => set({ category: "Security Events" }), quick);
		report.page.add_inner_button(__("All Logins"), () => set({ category: "All Logins" }), quick);

		// Same dialog and renderer as the standard PDF menu entry, which uses
		// qr_login_audit_analysis.html with the rows already on screen.
		report.page.add_inner_button(__("Print / PDF"), () => {
			report.get_validated_visible_indexes();
			const dialog = frappe.ui.get_print_settings(
				false,
				(print_settings) => report.pdf_report(print_settings),
				report.report_doc.letter_head,
				report.get_visible_columns(),
				true,
				"PDF Settings",
				report.report_doc.default_print_format
			);
			report.add_portrait_warning(dialog);
		});
	},
};
