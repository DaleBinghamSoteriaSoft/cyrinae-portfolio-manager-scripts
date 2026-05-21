#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional Risk Profiler PDF
# Description: Creates a Risk Profiler PDF cover report for a system key.
# ============================================================

import html
import json
import re
import subprocess
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE = "OpenRMF Professional Risk Profiler"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
STATUS_COLUMNS = ["Open", "Not a Finding", "Not Applicable", "Not Reviewed"]


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 risk-profiler/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
	)


def safe_filename_value(value: str) -> str:
	safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
	return safe_value.strip(".-") or "unknown-system"


def call_system_package_json_script(arguments: list[str]) -> str:
	source_script = Path(__file__).resolve().parents[1] / "system-package" / SYSTEM_PACKAGE_SCRIPT_NAME
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print("ERROR: The system package JSON script failed.")
		if result.stdout.strip():
			print(result.stdout.strip())
		if result.stderr.strip():
			print(result.stderr.strip())
		sys.exit(result.returncode)
	return result.stdout


def parse_json_value_from_output(output: str):
	decoder = json.JSONDecoder()
	for index, character in enumerate(output):
		if character not in "[{":
			continue
		try:
			parsed, _ = decoder.raw_decode(output[index:])
			return parsed
		except json.JSONDecodeError:
			continue
	print("ERROR: Could not find JSON in the system package JSON script output.")
	print(output)
	sys.exit(1)


def parse_optional_arguments(arguments: list[str]) -> dict[str, str]:
	parsed = {}
	for argument in arguments:
		if "=" not in argument:
			print(f"ERROR: Optional arguments must use KEY=VALUE format. Invalid value: {argument}")
			sys.exit(1)
		key, value = argument.split("=", 1)
		parsed[key] = value
	return parsed


def optional_value(options: dict[str, str], *keys: str) -> str:
	for key in keys:
		value = options.get(key)
		if value not in (None, ""):
			return value
	return "Unknown"


def first_json_value(data, keys: set[str]) -> str:
	if isinstance(data, dict):
		for key, value in data.items():
			if key in keys and value not in (None, ""):
				return str(value).strip()
		for value in data.values():
			found_value = first_json_value(value, keys)
			if found_value:
				return found_value
	elif isinstance(data, list):
		for item in data:
			found_value = first_json_value(item, keys)
			if found_value:
				return found_value
	return ""


def framework_value(system_package, options: dict[str, str], json_keys: set[str], *option_keys: str) -> str:
	value = first_json_value(system_package, json_keys)
	if value:
		return value
	return optional_value(options, *option_keys)


def score_value(score: dict, key: str) -> str:
	return str(score.get(key, 0))


def numeric_count(value: str) -> int:
	try:
		return int(float(str(value).strip()))
	except ValueError:
		return 0


def build_cat_status_rows(system_package: dict) -> list[dict[str, str]]:
	score = system_package.get("score", {}) if isinstance(system_package, dict) else {}
	if not isinstance(score, dict):
		score = {}
	return [
		{
			"category": "CAT 1",
			"open": score_value(score, "totalCat1Open"),
			"not_reviewed": score_value(score, "totalCat1NotReviewed"),
			"not_a_finding": score_value(score, "totalCat1NotAFinding"),
			"not_applicable": score_value(score, "totalCat1NotApplicable"),
		},
		{
			"category": "CAT 2",
			"open": score_value(score, "totalCat2Open"),
			"not_reviewed": score_value(score, "totalCat2NotReviewed"),
			"not_a_finding": score_value(score, "totalCat2NotAFinding"),
			"not_applicable": score_value(score, "totalCat2NotApplicable"),
		},
		{
			"category": "CAT 3",
			"open": score_value(score, "totalCat3Open"),
			"not_reviewed": score_value(score, "totalCat3NotReviewed"),
			"not_a_finding": score_value(score, "totalCat3NotAFinding"),
			"not_applicable": score_value(score, "totalCat3NotApplicable"),
		},
		{
			"category": "Total",
			"open": "",
			"not_reviewed": score_value(score, "totalNotReviewed"),
			"not_a_finding": score_value(score, "totalNotAFinding"),
			"not_applicable": score_value(score, "totalNotApplicable"),
		},
	]


def build_patch_vulnerability_risk_rows(system_package: dict) -> list[dict[str, str]]:
	patch_score = system_package.get("patchScore", {}) if isinstance(system_package, dict) else {}
	if not isinstance(patch_score, dict):
		patch_score = {}
	return [
		{"risk": "Critical", "open": score_value(patch_score, "totalCriticalOpen")},
		{"risk": "High", "open": score_value(patch_score, "totalHighOpen")},
		{"risk": "Medium", "open": score_value(patch_score, "totalMediumOpen")},
		{"risk": "Low", "open": score_value(patch_score, "totalLowOpen")},
	]


def build_report_data(system_key: str, options: dict[str, str], system_package: dict) -> dict[str, str]:
	return {
		"system_key": system_key,
		"framework_title": framework_value(system_package, options, {"frameworkTitle", "frameworktitle", "framework_title"}, "frameworkTitle", "frameworktitle", "framework_title"),
		"framework_version": framework_value(system_package, options, {"frameworkVersion", "frameworkversion", "framework_version"}, "frameworkVersion", "frameworkversion", "framework_version"),
		"cat_status_rows": build_cat_status_rows(system_package),
		"patch_vulnerability_risk_rows": build_patch_vulnerability_risk_rows(system_package),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"source_script": Path(__file__).name,
	}


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, str]) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"
	cat_status_table = Table(
		[
			["CAT", *[Paragraph(status, table_header_style) for status in STATUS_COLUMNS]],
			*[
				[row["category"], row["open"], row["not_a_finding"], row["not_applicable"], row["not_reviewed"]]
				for row in report_data["cat_status_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[75, 80, 115, 115, 115],
	)
	cat_status_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 1), (1, 1), colors.lightcoral),
				("BACKGROUND", (1, 2), (1, 2), colors.orange),
				("BACKGROUND", (1, 3), (1, 3), colors.yellow),
				("BACKGROUND", (2, 1), (2, -1), colors.lightgreen),
				("BACKGROUND", (3, 1), (3, -1), colors.whitesmoke),
				("BACKGROUND", (4, 1), (4, -1), colors.lightgrey),
				("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (-1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	patch_vulnerability_risk_table = Table(
		[
			["Risk", "Open"],
			*[[row["risk"], row["open"]] for row in report_data["patch_vulnerability_risk_rows"]],
		],
		hAlign="LEFT",
		colWidths=[160, 100],
	)
	patch_vulnerability_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 1), (1, 1), colors.darkred),
				("BACKGROUND", (1, 2), (1, 2), colors.red),
				("BACKGROUND", (1, 3), (1, 3), colors.orange),
				("BACKGROUND", (1, 4), (1, 4), colors.yellow),
				("TEXTCOLOR", (1, 1), (1, 2), colors.white),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)

	def build_2d_histogram(rows: list[dict[str, str]], row_label_key: str, columns: list[tuple[str, str]], title: str, x_label: str) -> BytesIO | None:
		try:
			import matplotlib  # pyright: ignore[reportMissingModuleSource]

			matplotlib.use("Agg")
			import matplotlib.pyplot as plt  # pyright: ignore[reportMissingModuleSource]
		except ImportError:
			return None
		if not rows:
			return None

		row_labels = [row[row_label_key] for row in rows]
		column_labels = [label for label, _ in columns]
		matrix = [[numeric_count(row[column_key]) for _, column_key in columns] for row in rows]
		max_value = max([value for row_values in matrix for value in row_values] or [0])
		x_edges = list(range(len(column_labels) + 1))
		y_edges = list(range(len(row_labels) + 1))

		figure_height = max(3.0, 0.48 * len(row_labels) + 1.8)
		figure, axis = plt.subplots(figsize=(7.4, figure_height), dpi=150)
		histogram = axis.pcolormesh(
			x_edges,
			y_edges,
			matrix,
			cmap="YlOrRd",
			edgecolors="black",
			linewidth=0.75,
			vmin=0,
			vmax=max_value or 1,
			shading="flat",
		)
		axis.set_xticks([index + 0.5 for index in range(len(column_labels))], labels=column_labels, rotation=30, ha="right")
		axis.set_yticks([index + 0.5 for index in range(len(row_labels))], labels=row_labels)
		axis.set_xlabel(x_label)
		axis.set_ylabel(row_label_key.replace("_", " ").title())
		axis.set_title(title)
		axis.invert_yaxis()
		for row_index, row_values in enumerate(matrix):
			for column_index, value in enumerate(row_values):
				text_value = rows[row_index][columns[column_index][1]]
				text_color = "white" if max_value and value > (max_value / 2) else "black"
				axis.text(column_index + 0.5, row_index + 0.5, text_value, ha="center", va="center", color=text_color, fontsize=8)
		colorbar = figure.colorbar(histogram, ax=axis, pad=0.02)
		colorbar.set_label("Count")
		figure.tight_layout()

		image_buffer = BytesIO()
		figure.savefig(image_buffer, format="png", bbox_inches="tight")
		plt.close(figure)
		image_buffer.seek(0)
		return image_buffer

	cat_status_histogram_image = build_2d_histogram(
		report_data["cat_status_rows"],
		"category",
		[("Open", "open"), ("Not a Finding", "not_a_finding"), ("Not Applicable", "not_applicable"), ("Not Reviewed", "not_reviewed")],
		"Checklist Risk 2D Histogram",
		"Status",
	)
	patch_vulnerability_risk_histogram_image = build_2d_histogram(
		report_data["patch_vulnerability_risk_rows"],
		"risk",
		[("Open", "open")],
		"Patch Vulnerability Risk 2D Histogram",
		"Status",
	)

	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		title=REPORT_TITLE,
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(REPORT_TITLE, styles["Title"]),
		Spacer(1, 24),
		Paragraph("Risk Profiler", styles["Heading1"]),
		Spacer(1, 12),
		Paragraph(f"Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"Framework Title: {html.escape(report_data['framework_title'])}", styles["Normal"]),
		Paragraph(f"Framework Version: {html.escape(report_data['framework_version'])}", styles["Normal"]),
		Paragraph(f"Source Script: {html.escape(report_data['source_script'])}", styles["Normal"]),
		PageBreak(),
		Paragraph("Checklist Risk", styles["Heading1"]),
		Spacer(1, 12),
		cat_status_table,
		Spacer(1, 18),
		Paragraph("Checklist Risk 2D Histogram", styles["Heading2"]),
		Spacer(1, 8),
	]
	if cat_status_histogram_image:
		story.append(Image(cat_status_histogram_image, width=500, height=240))
	else:
		story.append(Paragraph("Checklist Risk 2D Histogram unavailable. Install matplotlib to render it.", styles["Normal"]))
	story.extend(
		[
		PageBreak(),
		Paragraph("Patch Vulnerability Risk", styles["Heading1"]),
		Spacer(1, 12),
		patch_vulnerability_risk_table,
		Spacer(1, 18),
		Paragraph("Patch Vulnerability Risk 2D Histogram", styles["Heading2"]),
		Spacer(1, 8),
		]
	)
	if patch_vulnerability_risk_histogram_image:
		story.append(Image(patch_vulnerability_risk_histogram_image, width=500, height=220))
	else:
		story.append(Paragraph("Patch Vulnerability Risk 2D Histogram unavailable. Install matplotlib to render it.", styles["Normal"]))
	document.build(story)
	return True


def escape_pdf_text(value: str) -> str:
	return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 12) -> str:
	y_position = 740
	content = ["BT", f"/F1 {font_size} Tf"]
	for line in lines:
		content.append(f"1 0 0 1 72 {y_position} Tm ({escape_pdf_text(line)}) Tj")
		y_position -= 18
	content.append("ET")
	return "\n".join(content)


def write_minimal_pdf(output_path: Path, report_data: dict[str, str]) -> None:
	cat_status_lines = [
		"Checklist Risk",
		"",
		"CAT    Open  Not a Finding  Not Applicable  Not Reviewed",
		"-----  ----  -------------  --------------  ------------",
	]
	for row in report_data["cat_status_rows"]:
		cat_status_lines.append(
			f"{row['category']:<5}  {row['open']:>4}  {row['not_a_finding']:>13}  {row['not_applicable']:>14}  {row['not_reviewed']:>12}"
		)
	cat_status_lines.extend(["", "Checklist Risk 2D Histogram unavailable in fallback PDF output."])
	patch_vulnerability_risk_lines = [
		"Patch Vulnerability Risk",
		"",
		"Risk      Open",
		"--------  ----",
	]
	for row in report_data["patch_vulnerability_risk_rows"]:
		patch_vulnerability_risk_lines.append(f"{row['risk']:<8}  {row['open']:>4}")
	patch_vulnerability_risk_lines.extend(["", "Patch Vulnerability Risk 2D Histogram unavailable in fallback PDF output."])
	page_streams = [
		make_text_page(
			[
			REPORT_TITLE,
			"",
			"Risk Profiler",
			"",
			f"Generated: {report_data['generated_at']}",
			f"System Key: {report_data['system_key']}",
			f"Framework Title: {report_data['framework_title']}",
			f"Framework Version: {report_data['framework_version']}",
			f"Source Script: {report_data['source_script']}",
			],
			font_size=14,
		),
		make_text_page(cat_status_lines),
		make_text_page(patch_vulnerability_risk_lines),
	]
	objects = [
		b"<< /Type /Catalog /Pages 2 0 R >>",
		b"",
		b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	]
	page_object_numbers = []
	for page_stream in page_streams:
		page_object_number = len(objects) + 1
		content_object_number = len(objects) + 2
		page_object_numbers.append(page_object_number)
		objects.append(
			f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>".encode("latin-1")
		)
		stream_bytes = page_stream.encode("latin-1", errors="replace")
		objects.append(b"<< /Length " + str(len(stream_bytes)).encode("ascii") + b" >>\nstream\n" + stream_bytes + b"\nendstream")
	kids = " ".join(f"{page_number} 0 R" for page_number in page_object_numbers)
	objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_numbers)} >>".encode("latin-1")

	pdf = bytearray(b"%PDF-1.4\n")
	offsets = [0]
	for object_number, object_bytes in enumerate(objects, start=1):
		offsets.append(len(pdf))
		pdf.extend(f"{object_number} 0 obj\n".encode("ascii"))
		pdf.extend(object_bytes)
		pdf.extend(b"\nendobj\n")

	xref_offset = len(pdf)
	pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
	pdf.extend(b"0000000000 65535 f \n")
	for offset in offsets[1:]:
		pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
	pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii"))
	output_path.write_bytes(pdf)


def write_pdf(output_path: Path, report_data: dict[str, str]) -> str:
	if output_path.exists():
		output_path.unlink()
	if write_pdf_with_reportlab(output_path, report_data):
		return "reportlab"
	write_minimal_pdf(output_path, report_data)
	return "fallback"


def main() -> None:
	if len(sys.argv) < REQUIRED_ARGUMENT_COUNT:
		print_usage()
		sys.exit(1)

	system_key = sys.argv[4]
	options = parse_optional_arguments(sys.argv[5:])
	system_package = parse_json_value_from_output(call_system_package_json_script(sys.argv[1:5]))
	report_data = build_report_data(system_key, options, system_package)
	output_filename = f"OpenRMFPro-Risk-Profiler-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
