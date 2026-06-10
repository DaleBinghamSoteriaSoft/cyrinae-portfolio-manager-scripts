#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional RoI Ranker PDF
# Description: Creates a cover-page-only POAM prioritization PDF report for a system key.
# ============================================================

import html
import importlib.util
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
POAM_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
POAM_SETTINGS_SCRIPT_NAME = "poam_settings.py"
MAX_SECURITY_CHECK_TEXT_LENGTH = 120


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 roi_ranker/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
	)


def safe_filename_value(value: str) -> str:
	safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
	return safe_value.strip(".-").lower() or "unknown-system"


def safe_text(value) -> str:
	if value is None:
		return ""
	return str(value)


def call_child_script(source_script: Path, arguments: list[str], label: str) -> str:
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print(f"ERROR: The {label} JSON script failed.")
		if result.stdout.strip():
			print(result.stdout.strip())
		if result.stderr.strip():
			print(result.stderr.strip())
		sys.exit(result.returncode)
	return result.stdout


def call_system_package_json_script(arguments: list[str]) -> str:
	source_script = Path(__file__).resolve().parents[1] / "system-package" / SYSTEM_PACKAGE_SCRIPT_NAME
	return call_child_script(source_script, arguments, "system package")


def call_poam_json_script(arguments: list[str]) -> str:
	source_script = Path(__file__).resolve().parents[1] / "poam" / POAM_SCRIPT_NAME
	return call_child_script(source_script, arguments, "POAM")


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
	print("ERROR: Could not find JSON in the child script output.")
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


def first_value(record: dict, keys: list[str]) -> str:
	for key in keys:
		value = record.get(key)
		if value not in (None, ""):
			return safe_text(value)
	return ""


def find_record_list(data, candidate_keys: list[str]) -> list[dict]:
	if isinstance(data, list):
		return [record for record in data if isinstance(record, dict)]
	if not isinstance(data, dict):
		return []
	for key in candidate_keys:
		value = data.get(key)
		if isinstance(value, list):
			return [record for record in value if isinstance(record, dict)]
	for value in data.values():
		if isinstance(value, list) and all(isinstance(record, dict) for record in value):
			return value
	return []


def poam_records(poam_data) -> list[dict]:
	return find_record_list(poam_data, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


def normalize_status(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"ongoing", "on going", "in progress", "active", "open", "new"}:
		return "Ongoing"
	if value_text in {"completed", "complete", "closed"}:
		return "Completed"
	if value_text in {"accepted", "risk accepted", "risk acceptance"}:
		return "Accepted"
	return safe_text(value).strip() or "Other"


def poam_status(record: dict) -> str:
	return normalize_status(first_value(record, ["status", "statusString", "poamStatus", "poamStatusString", "poamStatusName", "workflowStatus", "state"]))


def normalize_raw_severity(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"critical", "cat i", "cat 1", "i", "4"}:
		return "Critical"
	if value_text in {"high", "cat ii", "cat 2", "ii", "3"}:
		return "High"
	if value_text in {"medium", "moderate", "cat iii", "cat 3", "iii", "2"}:
		return "Medium"
	if value_text in {"low", "1"}:
		return "Low"
	return "Not Set"


def normalize_residual_risk(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"very high", "veryhigh", "5"}:
		return "Very High"
	if value_text in {"high", "4"}:
		return "High"
	if value_text in {"moderate", "medium", "3"}:
		return "Moderate"
	if value_text in {"low", "2"}:
		return "Low"
	if value_text in {"very low", "verylow", "1"}:
		return "Very Low"
	return ""


def raw_severity(record: dict) -> str:
	return normalize_raw_severity(first_value(record, ["rawSeverity", "rawSeverityString", "rawSeverityValue"]))


def residual_risk_level_mitigation(record: dict) -> str:
	return normalize_residual_risk(first_value(record, ["residualRiskLevelMitigations", "residualRiskLevelMitigation", "residualRisk", "residualRiskString", "resultingResidualRisk"]))


def security_check_value(record: dict) -> str:
	return first_value(record, ["securityChecks", "securityCheck", "securityControlNumber", "control", "controlNumber", "vulnerabilityId", "vulnId", "vulnIdString"]) or "Not Set"


def poam_source_detail_value(record: dict) -> str:
	return first_value(record, ["sourceIdControlVulnerability"]) or "Not Set"


def device_name_from_value(value) -> str:
	if isinstance(value, dict):
		return first_value(value, ["deviceName", "devicename", "hostName", "hostname", "assetName", "asset", "name", "id"])
	return safe_text(value).strip()


def affected_device_values(record: dict) -> list[str]:
	value = record.get("devicesAffected")
	if isinstance(value, (int, float)):
		return []
	if isinstance(value, list):
		return [device for device in (device_name_from_value(item) for item in value) if device]
	if isinstance(value, dict):
		device_name = device_name_from_value(value)
		return [device_name] if device_name else []
	value_text = safe_text(value).strip()
	if not value_text:
		return []
	if value_text.isdigit():
		return []
	if any(separator in value_text for separator in [",", ";", "|"]):
		return [item.strip() for item in re.split(r"[,;|]", value_text) if item.strip()]
	return [value_text]


def unnamed_device_count(record: dict) -> int:
	value = record.get("devicesAffected")
	if isinstance(value, (int, float)):
		return max(int(value), 0)
	value_text = safe_text(value).strip()
	if value_text.isdigit():
		return max(int(value_text), 0)
	return 0


def severity_weight(raw_value: str, residual_value: str, weights: dict) -> int:
	if residual_value:
		key = "residualRiskLevelMitigation" + residual_value.replace(" ", "")
		return int(weights.get(key, 0))
	key = "rawSeverity" + raw_value.replace(" ", "")
	return int(weights.get(key, 0))


def load_poam_weights() -> dict:
	settings_path = Path(__file__).resolve().parent / POAM_SETTINGS_SCRIPT_NAME
	spec = importlib.util.spec_from_file_location("poam_settings", settings_path)
	if spec is None or spec.loader is None:
		print(f"ERROR: Could not load POAM weights from {settings_path}.")
		sys.exit(1)
	module = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(module)
	weights = getattr(module, "POAMWEIGHTS", None)
	if not isinstance(weights, dict):
		print(f"ERROR: {POAM_SETTINGS_SCRIPT_NAME} must define a POAMWEIGHTS dictionary.")
		sys.exit(1)
	return weights


def truncate_cell_text(value: str, max_length: int) -> str:
	value_text = re.sub(r"\s+", " ", safe_text(value)).strip()
	if len(value_text) <= max_length:
		return value_text
	return value_text[: max_length - 1].rstrip() + "…"


def build_impact_rows(poam_data) -> list[dict[str, str]]:
	weights = load_poam_weights()
	grouped_rows: dict[tuple[str, str], dict] = {}
	for record in poam_records(poam_data):
		if poam_status(record) != "Ongoing":
			continue
		security_check = security_check_value(record)
		source_detail = poam_source_detail_value(record)
		raw_value = raw_severity(record)
		residual_value = residual_risk_level_mitigation(record)
		severity_value = residual_value or raw_value
		device_values = affected_device_values(record)
		unnamed_count = unnamed_device_count(record)
		weight = severity_weight(raw_value, residual_value, weights)
		key = (security_check, severity_value)
		if key not in grouped_rows:
			grouped_rows[key] = {
				"security_check": security_check,
				"source_details": set(),
				"devices": set(),
				"unnamed_device_count": 0,
				"severity": severity_value,
				"weight": weight,
				"impact_score": 0,
			}
		grouped_rows[key]["source_details"].add(source_detail)
		grouped_rows[key]["devices"].update(device_values)
		grouped_rows[key]["unnamed_device_count"] = int(grouped_rows[key]["unnamed_device_count"]) + unnamed_count

	for row in grouped_rows.values():
		device_count = len(row["devices"]) + int(row["unnamed_device_count"])
		row["device_count"] = device_count
		row["impact_score"] = int(row["weight"]) * device_count

	return [
		{
			"security_check": truncate_cell_text(row["security_check"], MAX_SECURITY_CHECK_TEXT_LENGTH),
			"source": truncate_cell_text(", ".join(sorted(row["source_details"])), MAX_SECURITY_CHECK_TEXT_LENGTH),
			"device_count": safe_text(row["device_count"]),
			"severity": safe_text(row["severity"]),
			"impact_score": safe_text(row["impact_score"]),
		}
		for row in sorted(grouped_rows.values(), key=lambda row: (-int(row["impact_score"]), -int(row["device_count"]), safe_text(row["security_check"]).lower()))
		if int(row["device_count"]) > 0
	]


def readable_weight_name(key: str) -> str:
	if key.startswith("rawSeverity"):
		return "Raw Severity: " + re.sub(r"(?<!^)(?=[A-Z])", " ", key.removeprefix("rawSeverity"))
	if key.startswith("residualRiskLevelMitigation"):
		return "Residual Risk Mitigation: " + re.sub(r"(?<!^)(?=[A-Z])", " ", key.removeprefix("residualRiskLevelMitigation"))
	return re.sub(r"(?<!^)(?=[A-Z])", " ", key)


def build_settings_rows() -> list[dict[str, str]]:
	weights = load_poam_weights()
	return [
		{"setting": readable_weight_name(key), "weight": safe_text(value)}
		for key, value in weights.items()
	]


def build_system_description(system_package: dict, options: dict[str, str]) -> str:
	value = first_json_value(system_package, {"description", "systemDescription", "system_description"})
	if value:
		return value
	return optional_value(options, "description", "systemDescription", "system_description")


def build_system_title(system_package: dict, options: dict[str, str]) -> str:
	value = first_json_value(system_package, {"title", "systemTitle", "systemName", "name"})
	if value:
		return value
	return optional_value(options, "systemTitle", "systemName", "title", "name")


def report_title_for_system(system_title: str, system_key: str) -> str:
	system_title_text = safe_text(system_title).strip()
	if system_title_text and system_title_text != "Unknown":
		return f"{system_title_text} POAM Prioritization"
	return f"{safe_text(system_key).strip() or 'Unknown System'} POAM Prioritization"


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, poam_data) -> dict:
	system_title = build_system_title(system_package, options)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title, system_key),
		"system_description": build_system_description(system_package, options),
		"impact_rows": build_impact_rows(poam_data),
		"settings_rows": build_settings_rows(),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"source_script": Path(__file__).name,
	}


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	table_header_style = styles["BodyText"].clone("ImpactTableHeader")
	table_header_style.fontName = "Helvetica-Bold"
	table_header_style.fontSize = 8
	table_header_style.leading = 9
	small_style = styles["BodyText"].clone("ImpactTableText")
	small_style.fontSize = 7
	small_style.leading = 8
	settings_header_style = styles["BodyText"].clone("SettingsTableHeader")
	settings_header_style.fontName = "Helvetica-Bold"
	settings_header_style.fontSize = 9
	settings_header_style.leading = 10
	settings_style = styles["BodyText"].clone("SettingsTableText")
	settings_style.fontSize = 9
	settings_style.leading = 10

	def paragraph_cell(value: str, style=None):
		return Paragraph("<br/>".join(html.escape(line) for line in safe_text(value).splitlines()), style or styles["BodyText"])

	impact_table_rows = [
		[
			Paragraph("Security Check", table_header_style),
			Paragraph("Source", table_header_style),
			Paragraph("# Devices", table_header_style),
			Paragraph("Severity", table_header_style),
			Paragraph("POAM Impact Score", table_header_style),
		]
	]
	for row in report_data["impact_rows"]:
		impact_table_rows.append(
			[
				paragraph_cell(row["security_check"], small_style),
				paragraph_cell(row["source"], small_style),
				row["device_count"],
				row["severity"],
				row["impact_score"],
			]
		)
	impact_table = Table(impact_table_rows, colWidths=[165, 170, 60, 70, 55], hAlign="LEFT", repeatRows=1)
	impact_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EEF7")),
				("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B7B7B7")),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("ALIGN", (1, 0), (-1, -1), "CENTER"),
				("VALIGN", (0, 0), (-1, -1), "TOP"),
			]
		)
	)
	settings_table_rows = [
		[
			Paragraph("POAM Setting", settings_header_style),
			Paragraph("Weight", settings_header_style),
		]
	]
	for row in report_data["settings_rows"]:
		settings_table_rows.append([paragraph_cell(row["setting"], settings_style), paragraph_cell(row["weight"], settings_style)])
	settings_table = Table(settings_table_rows, colWidths=[300, 65], hAlign="LEFT", repeatRows=1)
	settings_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EEF7")),
				("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B7B7B7")),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("ALIGN", (1, 0), (-1, -1), "CENTER"),
				("VALIGN", (0, 0), (-1, -1), "TOP"),
			]
		)
	)
	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		title=report_data["report_title"],
		author="OpenRMF Professional External API Scripts",
		leftMargin=36,
		rightMargin=36,
	)
	story = [
		Paragraph(html.escape(report_data["report_title"]), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		PageBreak(),
		Paragraph("Live POAM", styles["Heading1"]),
		Spacer(1, 8),
		impact_table if report_data["impact_rows"] else Paragraph("No ongoing POAM items were returned for impact scoring.", styles["Normal"]),
		PageBreak(),
		Paragraph("POAM Prioritization Settings", styles["Heading1"]),
		Spacer(1, 8),
		settings_table,
	]
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


def write_minimal_pdf(output_path: Path, report_data: dict) -> None:
	cover_page_stream = make_text_page(
		[
			report_data["report_title"],
			"",
			f"Date Generated: {report_data['generated_at']}",
			f"System Key: {report_data['system_key']}",
			f"System Title: {report_data['system_title']}",
			f"Description: {report_data['system_description']}",
		],
		font_size=14,
	)
	impact_lines = [
		"Live POAM",
		"",
		"Security Check | Source | # Devices | Severity | POAM Impact Score",
		"-------------- | ------ | --------- | -------- | -----------------",
	]
	for row in report_data["impact_rows"]:
		impact_lines.append(f"{row['security_check']} | {row['source']} | {row['device_count']} | {row['severity']} | {row['impact_score']}")
	settings_lines = [
		"POAM Prioritization Settings",
		"",
		"POAM Setting | Weight",
		"------------ | ------",
	]
	for row in report_data["settings_rows"]:
		settings_lines.append(f"{row['setting']} | {row['weight']}")
	page_streams = [
		cover_page_stream,
		*[make_text_page(impact_lines[index:index + 36]) for index in range(0, len(impact_lines), 36)],
		*[make_text_page(settings_lines[index:index + 36]) for index in range(0, len(settings_lines), 36)],
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


def write_pdf(output_path: Path, report_data: dict) -> str:
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
	poam_data = parse_json_value_from_output(call_poam_json_script([*sys.argv[1:5], "grouped=false", "status=Ongoing"]))
	report_data = build_report_data(system_key, options, system_package, poam_data)
	output_filename = f"OpenRMFPro-poam-prioritization-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
