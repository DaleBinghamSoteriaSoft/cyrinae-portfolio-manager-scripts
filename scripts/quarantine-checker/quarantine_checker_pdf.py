#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional Quarantine Checker PDF
# Description: Creates a hardware patch quarantine checker PDF for a system key.
# ============================================================

import html
import ipaddress
import json
import re
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
	sys.path.insert(0, str(SCRIPT_DIR))

from quarantine_settings import QUARANTINE_SETTINGS

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE_SUFFIX = "Quarantine Checker"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
HARDWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_hardware_json.py"
PATCH_SCORE_DEVICES_SCRIPT_NAME = "get_systempackage_by_systemkey_patchscore_devices_json.py"
CHECKLISTS_SCRIPT_NAME = "get_systempackage_by_systemkey_checklists_json.py"

HOSTNAME_KEYS = [
	"hostname",
	"hostName",
	"host_name",
	"deviceName",
	"devicename",
	"assetName",
	"computerName",
	"machineName",
	"dnsName",
	"netbiosName",
	"name",
]
IP_KEYS = [
	"ipAddress",
	"ipaddress",
	"ip_address",
	"ipAddressList",
	"ipAddresses",
	"ip_addresses",
	"ipv4Address",
	"ipv4",
	"address",
]
PATCH_SEVERITY_KEYS = {
	"Critical": [
		"totalCriticalOpen",
		"totalPatchCriticalOpen",
		"criticalOpen",
		"openCritical",
		"criticalVulnerabilities",
		"criticalVulnerabilityCount",
	],
	"High": [
		"totalHighOpen",
		"totalPatchHighOpen",
		"highOpen",
		"openHigh",
		"highVulnerabilities",
		"highVulnerabilityCount",
	],
	"Medium": [
		"totalMediumOpen",
		"totalPatchMediumOpen",
		"mediumOpen",
		"openMedium",
		"mediumVulnerabilities",
		"mediumVulnerabilityCount",
	],
	"Low": [
		"totalLowOpen",
		"totalPatchLowOpen",
		"lowOpen",
		"openLow",
		"lowVulnerabilities",
		"lowVulnerabilityCount",
	],
}
PATCH_SETTING_KEYS = {
	"Critical": "maxPatchOpenCriticalVuln",
	"High": "maxPatchOpenHighVuln",
	"Medium": "maxPatchOpenMediumVuln",
	"Low": "maxPatchOpenLowVuln",
}
CHECKLIST_SEVERITY_KEYS = {
	"High": [
		"totalHighOpen",
		"totalChecklistHighOpen",
		"checklistHighOpen",
		"highOpen",
		"openHigh",
		"openHighVuln",
		"highVulnerabilities",
		"highVulnerabilityCount",
		"cat1Open",
		"category1Open",
		"openCat1",
		"openCategory1",
		"totalCategory1Open",
	],
	"Medium": [
		"totalMediumOpen",
		"totalChecklistMediumOpen",
		"checklistMediumOpen",
		"mediumOpen",
		"openMedium",
		"openMediumVuln",
		"mediumVulnerabilities",
		"mediumVulnerabilityCount",
		"cat2Open",
		"category2Open",
		"openCat2",
		"openCategory2",
		"totalCategory2Open",
	],
	"Low": [
		"totalLowOpen",
		"totalChecklistLowOpen",
		"checklistLowOpen",
		"lowOpen",
		"openLow",
		"openLowVuln",
		"lowVulnerabilities",
		"lowVulnerabilityCount",
		"cat3Open",
		"category3Open",
		"openCat3",
		"openCategory3",
		"totalCategory3Open",
	],
}
CHECKLIST_SETTING_KEYS = {
	"High": "maxChecklistOpenHighVuln",
	"Medium": "maxChecklistOpenMediumVuln",
	"Low": "maxChecklistOpenLowVuln",
}
HARDWARE_RECORD_KEYS = ["records", "items", "data", "results", "hardware", "assets", "devices"]
PATCH_SCORE_DEVICE_RECORD_KEYS = ["records", "items", "data", "results", "patchScoreDevices", "patchscoreDevices", "patchScores", "devices", "assets"]
CHECKLIST_RECORD_KEYS = ["records", "items", "data", "results", "checklists", "checklist", "devices", "assets"]
PDF_LEFT_MARGIN = 36
PDF_RIGHT_MARGIN = 36
JSON_WRAP_WIDTH = 108


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 quarantine-checker/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
	)


def safe_filename_value(value: str) -> str:
	safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
	return safe_value.strip(".-") or "unknown-system"


def safe_text(value) -> str:
	if value is None:
		return ""
	return str(value)


def display_value(value) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip())


def normalized_value(value) -> str:
	return display_value(value).lower()


def call_json_script(script_folder: str, script_name: str, arguments: list[str], error_label: str) -> str:
	source_script = Path(__file__).resolve().parents[1] / script_folder / script_name
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print(f"ERROR: The {error_label} JSON script failed.")
		if result.stdout.strip():
			print(result.stdout.strip())
		if result.stderr.strip():
			print(result.stderr.strip())
		sys.exit(result.returncode)
	return result.stdout


def call_system_package_json_script(arguments: list[str]) -> str:
	return call_json_script("system-package", SYSTEM_PACKAGE_SCRIPT_NAME, arguments, "system package")


def call_hardware_json_script(arguments: list[str]) -> str:
	return call_json_script("hardware", HARDWARE_SCRIPT_NAME, arguments, "hardware")


def call_patch_score_devices_json_script(arguments: list[str]) -> str:
	return call_json_script("patch-vulnerability", PATCH_SCORE_DEVICES_SCRIPT_NAME, arguments, "patch score devices")


def call_checklists_json_script(arguments: list[str]) -> str:
	return call_json_script("checklist", CHECKLISTS_SCRIPT_NAME, [*arguments, "limit=10000"], "checklists")


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
				return display_value(value)
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


def first_record_value(record: dict, keys: list[str]) -> str:
	for key in keys:
		value = record.get(key)
		if value not in (None, ""):
			return display_value(value)
	return ""


def value_at_path(record: dict, path: list[str]):
	current_value = record
	for key in path:
		if not isinstance(current_value, dict) or key not in current_value:
			return None
		current_value = current_value[key]
	return current_value


def first_nested_record_value(record: dict, paths: list[list[str]]) -> str:
	for path in paths:
		value = value_at_path(record, path)
		if value not in (None, ""):
			return display_value(value)
	return ""


def numeric_value(value):
	if isinstance(value, bool):
		return None
	if isinstance(value, (int, float)):
		return int(value)
	text = display_value(value)
	if not text:
		return None
	match = re.search(r"-?\d+(?:\.\d+)?", text.replace(",", ""))
	if not match:
		return None
	try:
		return int(float(match.group(0)))
	except ValueError:
		return None


def first_numeric_json_value(data, keys: set[str]):
	if isinstance(data, dict):
		for key, value in data.items():
			if key in keys:
				number = numeric_value(value)
				if number is not None:
					return number
		for value in data.values():
			found_value = first_numeric_json_value(value, keys)
			if found_value is not None:
				return found_value
	elif isinstance(data, list):
		for item in data:
			found_value = first_numeric_json_value(item, keys)
			if found_value is not None:
				return found_value
	return None


def iter_scalar_values(value):
	if isinstance(value, dict):
		for nested_value in value.values():
			yield from iter_scalar_values(nested_value)
	elif isinstance(value, list):
		for nested_value in value:
			yield from iter_scalar_values(nested_value)
	elif value not in (None, ""):
		yield safe_text(value)


def valid_ip(value: str) -> str:
	try:
		return str(ipaddress.ip_address(value.strip()))
	except ValueError:
		return ""


def extract_ips_from_value(value) -> list[str]:
	ips = []
	for scalar_value in iter_scalar_values(value):
		for candidate in re.split(r"[,;\s]+", scalar_value):
			ip_value = valid_ip(candidate)
			if ip_value:
				ips.append(ip_value)
	return sorted(set(ips))


def extract_ips(record: dict) -> list[str]:
	ips = []
	for key in IP_KEYS:
		if key in record:
			ips.extend(extract_ips_from_value(record[key]))
	for path in [
		["asset", "ipAddress"],
		["asset", "ipAddresses"],
		["device", "ipAddress"],
		["device", "ipAddresses"],
		["host", "ipAddress"],
		["host", "ipAddresses"],
		["network", "ipAddress"],
	]:
		value = value_at_path(record, path)
		if value not in (None, ""):
			ips.extend(extract_ips_from_value(value))
	return sorted(set(ips))


def record_hostname(record: dict) -> str:
	direct_value = first_record_value(record, HOSTNAME_KEYS)
	if direct_value:
		return direct_value
	nested_value = first_nested_record_value(
		record,
		[
			["asset", "hostname"],
			["asset", "hostName"],
			["asset", "deviceName"],
			["device", "hostname"],
			["device", "hostName"],
			["device", "deviceName"],
			["host", "hostname"],
			["host", "hostName"],
			["system", "hostname"],
			["system", "hostName"],
		],
	)
	return nested_value if nested_value else "Unknown"


def looks_like_hardware_record(value: dict) -> bool:
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS).intersection(value.keys())
		or {"serialNumber", "assetTag", "macAddress", "operatingSystem"}.intersection(value.keys())
	)


def looks_like_patch_score_device_record(value: dict) -> bool:
	patch_count_keys = []
	for keys in PATCH_SEVERITY_KEYS.values():
		patch_count_keys.extend(keys)
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS + patch_count_keys).intersection(value.keys())
		or {"patchScore", "patchscore", "vulnerabilities", "device", "asset"}.intersection(value.keys())
	)


def looks_like_checklist_record(value: dict) -> bool:
	checklist_count_keys = []
	for keys in CHECKLIST_SEVERITY_KEYS.values():
		checklist_count_keys.extend(keys)
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS + checklist_count_keys).intersection(value.keys())
		or {"checklist", "checklists", "checklistScore", "checklistscore", "vulnerabilities", "device", "asset"}.intersection(value.keys())
	)


def find_record_list(data, candidate_keys: list[str], record_predicate) -> list[dict]:
	if isinstance(data, list):
		records = [record for record in data if isinstance(record, dict)]
		if records and any(record_predicate(record) for record in records):
			return records
		found_records = []
		for record in records:
			found_records.extend(find_record_list(record, candidate_keys, record_predicate))
		return found_records
	if not isinstance(data, dict):
		return []

	for key in candidate_keys:
		value = data.get(key)
		if isinstance(value, list):
			records = [record for record in value if isinstance(record, dict)]
			if records:
				return records

	if record_predicate(data):
		return [data]

	found_records = []
	for value in data.values():
		if isinstance(value, (dict, list)):
			found_records.extend(find_record_list(value, candidate_keys, record_predicate))
	return found_records


def hardware_records(hardware_data) -> list[dict]:
	return find_record_list(hardware_data, HARDWARE_RECORD_KEYS, looks_like_hardware_record)


def patch_score_device_records(patch_score_devices_data) -> list[dict]:
	return find_record_list(patch_score_devices_data, PATCH_SCORE_DEVICE_RECORD_KEYS, looks_like_patch_score_device_record)


def checklist_records(checklists_data) -> list[dict]:
	return find_record_list(checklists_data, CHECKLIST_RECORD_KEYS, looks_like_checklist_record)


def build_patch_reason(record: dict) -> str:
	reasons = []
	for severity, keys in PATCH_SEVERITY_KEYS.items():
		count = first_numeric_json_value(record, set(keys))
		if count is None:
			continue
		setting_key = PATCH_SETTING_KEYS[severity]
		threshold = numeric_value(QUARANTINE_SETTINGS.get(setting_key, 0)) or 0
		if count > threshold:
			reasons.append(f"{severity} open patch vulnerabilities: {count} exceeds maximum {threshold}")

	return "; ".join(reasons)


def build_checklist_reason(record: dict) -> str:
	reasons = []
	for severity, keys in CHECKLIST_SEVERITY_KEYS.items():
		count = first_numeric_json_value(record, set(keys))
		if count is None:
			continue
		setting_key = CHECKLIST_SETTING_KEYS[severity]
		threshold = numeric_value(QUARANTINE_SETTINGS.get(setting_key, 0)) or 0
		if count > threshold:
			reasons.append(f"{severity} open checklist vulnerabilities: {count} exceeds maximum {threshold}")

	return "; ".join(reasons)


def build_hardware_lookup(hardware_data) -> dict[str, dict[str, str]]:
	lookup = {}
	for record in hardware_records(hardware_data):
		hostname = record_hostname(record)
		if normalized_value(hostname) in ("", "unknown"):
			continue
		lookup[normalized_value(hostname)] = {
			"hostname": hostname,
			"IP address": ", ".join(extract_ips(record)),
		}
	return lookup


def build_hardware_patch_listing(hardware_data, patch_score_devices_data) -> list[dict[str, str]]:
	hardware_lookup = build_hardware_lookup(hardware_data)
	rows = []
	for record in patch_score_device_records(patch_score_devices_data):
		reason = build_patch_reason(record)
		if not reason:
			continue

		patch_hostname = record_hostname(record)
		hardware_record = hardware_lookup.get(normalized_value(patch_hostname), {})
		rows.append(
			{
				"hostname": hardware_record.get("hostname", patch_hostname),
				"IP address": hardware_record.get("IP address", ", ".join(extract_ips(record))),
				"reason": reason,
			}
		)
	return sorted(rows, key=lambda row: (row["hostname"].lower(), row["IP address"]))


def build_hardware_checklist_listing(hardware_data, checklists_data) -> list[dict[str, str]]:
	hardware_lookup = build_hardware_lookup(hardware_data)
	rows = []
	for record in checklist_records(checklists_data):
		reason = build_checklist_reason(record)
		if not reason:
			continue

		checklist_hostname = record_hostname(record)
		hardware_record = hardware_lookup.get(normalized_value(checklist_hostname), {})
		rows.append(
			{
				"hostname": hardware_record.get("hostname", checklist_hostname),
				"IP address": hardware_record.get("IP address", ", ".join(extract_ips(record))),
				"reason": reason,
			}
		)
	return sorted(rows, key=lambda row: (row["hostname"].lower(), row["IP address"]))


def build_system_description(system_package: dict, options: dict[str, str]) -> str:
	description = first_json_value(
		system_package,
		{"description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription"},
	)
	if description:
		return description
	return optional_value(options, "description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription")


def build_system_title(system_package: dict, options: dict[str, str]) -> str:
	title = first_json_value(system_package, {"title", "systemTitle", "system_title", "systemName", "name"})
	if title:
		return title
	return optional_value(options, "title", "systemTitle", "system_title", "systemName", "name")


def framework_value(system_package: dict, options: dict[str, str], json_keys: set[str], *option_keys: str) -> str:
	value = first_json_value(system_package, json_keys)
	if value:
		return value
	return optional_value(options, *option_keys)


def report_title_for_system(system_title: str) -> str:
	return f"{display_value(system_title) or 'Unknown'} {REPORT_TITLE_SUFFIX}"


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, hardware_data, patch_score_devices_data, checklists_data) -> dict:
	system_title = build_system_title(system_package, options)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"framework_title": framework_value(system_package, options, {"frameworkTitle", "frameworktitle", "framework_title"}, "frameworkTitle", "frameworktitle", "framework_title"),
		"framework_version": framework_value(system_package, options, {"frameworkVersion", "frameworkversion", "framework_version"}, "frameworkVersion", "frameworkversion", "framework_version"),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"hardware_patch_listing": build_hardware_patch_listing(hardware_data, patch_score_devices_data),
		"hardware_checklist_listing": build_hardware_checklist_listing(hardware_data, checklists_data),
	}


def json_listing_text(report_data: dict, listing_key: str) -> str:
	return json.dumps(report_data[listing_key], indent=2, sort_keys=False)


def wrapped_json_listing_text(report_data: dict, listing_key: str, width: int = JSON_WRAP_WIDTH) -> str:
	wrapped_lines = []
	for line in json_listing_text(report_data, listing_key).splitlines():
		if len(line) <= width:
			wrapped_lines.append(line)
			continue
		leading_spaces = line[:len(line) - len(line.lstrip(" "))]
		wrapped_lines.extend(
			textwrap.wrap(
				line,
				width=width,
				break_long_words=False,
				break_on_hyphens=False,
				subsequent_indent=f"{leading_spaces}  ",
			)
		)
	return "\n".join(wrapped_lines)


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	preformatted_style = styles["Code"].clone("HardwarePatchJson")
	preformatted_style.fontName = "Courier"
	preformatted_style.fontSize = 7
	preformatted_style.leading = 8.5
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"

	contents_table = Table(
		[
			[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)],
			["Hardware Patch Information", "2"],
			["Hardware Checklist Information", "3"],
		],
		hAlign="LEFT",
		colWidths=[380, 90],
	)
	contents_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)

	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		title=report_data["report_title"],
		author="OpenRMF Professional External API Scripts",
		leftMargin=PDF_LEFT_MARGIN,
		rightMargin=PDF_RIGHT_MARGIN,
	)
	story = [
		Paragraph(report_data["report_title"], styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		Spacer(1, 18),
		contents_table,
		PageBreak(),
		Paragraph("Hardware Patch Information", styles["Heading1"]),
		Spacer(1, 12),
		Preformatted(wrapped_json_listing_text(report_data, "hardware_patch_listing"), preformatted_style),
		PageBreak(),
		Paragraph("Hardware Checklist Information", styles["Heading1"]),
		Spacer(1, 12),
		Preformatted(wrapped_json_listing_text(report_data, "hardware_checklist_listing"), preformatted_style),
	]
	document.build(story)
	return True


def escape_pdf_text(value: str) -> str:
	return safe_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 11) -> str:
	y = 750
	leading = font_size + 4
	commands = ["BT", f"/F1 {font_size} Tf", f"{PDF_LEFT_MARGIN} {y} Td"]
	for index, line in enumerate(lines):
		if index:
			commands.append(f"0 -{leading} Td")
		commands.append(f"({escape_pdf_text(line)}) Tj")
	commands.append("ET")
	return "\n".join(commands)


def chunk_lines(lines: list[str], chunk_size: int) -> list[list[str]]:
	if not lines:
		return [[]]
	return [lines[index:index + chunk_size] for index in range(0, len(lines), chunk_size)]


def write_minimal_pdf(output_path: Path, report_data: dict) -> None:
	patch_json_lines = wrapped_json_listing_text(report_data, "hardware_patch_listing").splitlines()
	checklist_json_lines = wrapped_json_listing_text(report_data, "hardware_checklist_listing").splitlines()
	page_streams = [
		make_text_page(
			[
				report_data["report_title"],
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"System Key: {report_data['system_key']}",
				f"System Title: {report_data['system_title']}",
				f"Description: {report_data['system_description']}",
				"",
				"Page Title                                      Page Number",
				"--------------------------------------------  -----------",
				"Hardware Patch Information                              2",
				"Hardware Checklist Information                          3",
			],
			font_size=14,
		),
	]
	for index, lines in enumerate(chunk_lines(patch_json_lines, 56)):
		page_lines = ["Hardware Patch Information", ""] if index == 0 else ["Hardware Patch Information (continued)", ""]
		page_streams.append(make_text_page([*page_lines, *lines], font_size=9))
	for index, lines in enumerate(chunk_lines(checklist_json_lines, 56)):
		page_lines = ["Hardware Checklist Information", ""] if index == 0 else ["Hardware Checklist Information (continued)", ""]
		page_streams.append(make_text_page([*page_lines, *lines], font_size=9))

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
	arguments = sys.argv[1:5]
	system_package = parse_json_value_from_output(call_system_package_json_script(arguments))
	hardware_data = parse_json_value_from_output(call_hardware_json_script(arguments))
	patch_score_devices_data = parse_json_value_from_output(call_patch_score_devices_json_script(arguments))
	checklists_data = parse_json_value_from_output(call_checklists_json_script(arguments))
	report_data = build_report_data(system_key, options, system_package, hardware_data, patch_score_devices_data, checklists_data)
	output_filename = f"OpenRMFPro-Quarantine-Checker-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
