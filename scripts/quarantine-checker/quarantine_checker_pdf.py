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
CHECKLIST_HOSTNAME_KEYS = [key for key in HOSTNAME_KEYS if key != "name"]
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
		"totalCat1Open",
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
		"totalCat2Open",
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
		"totalCat3Open",
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
ARTIFACT_TITLE_KEYS = ["artifactTitle", "artifact_title", "title", "checklistTitle", "checklistName", "name"]
PDF_LEFT_MARGIN = 36
PDF_RIGHT_MARGIN = 36


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


def checklist_search_argument(hostname: str) -> str:
	return f"searchString={hostname}"


def call_checklists_json_script_for_hostname(arguments: list[str], hostname: str) -> str:
	return call_json_script("checklist", CHECKLISTS_SCRIPT_NAME, [*arguments, "limit=10000", checklist_search_argument(hostname)], "checklists")


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


def normalized_hostname(value: str) -> str:
	hostname = normalized_value(value)
	return hostname.split(".", 1)[0] if "." in hostname else hostname


def hostname_matches(candidate: str, expected: str) -> bool:
	candidate_hostname = normalized_hostname(candidate)
	expected_hostname = normalized_hostname(expected)
	if candidate_hostname in ("", "unknown") or expected_hostname in ("", "unknown"):
		return False
	return candidate_hostname == expected_hostname


def checklist_hostname_values(record: dict) -> list[str]:
	values = []
	for key in CHECKLIST_HOSTNAME_KEYS:
		if key in record:
			values.append(display_value(record[key]))
	for path in [
		["asset", "hostname"],
		["asset", "hostName"],
		["asset", "host_name"],
		["asset", "deviceName"],
		["asset", "assetName"],
		["device", "hostname"],
		["device", "hostName"],
		["device", "host_name"],
		["device", "deviceName"],
		["device", "name"],
		["host", "hostname"],
		["host", "hostName"],
		["host", "host_name"],
		["host", "name"],
		["hardware", "hostname"],
		["hardware", "hostName"],
		["hardware", "host_name"],
		["hardware", "deviceName"],
		["hardware", "name"],
		["system", "hostname"],
		["system", "hostName"],
		["system", "host_name"],
	]:
		value = value_at_path(record, path)
		if value not in (None, ""):
			values.append(display_value(value))
	return [value for value in values if value]


def checklist_record_matches_hardware(record: dict, hardware_record: dict[str, str]) -> bool:
	hostname = hardware_record.get("hostname", "")
	return any(hostname_matches(candidate, hostname) for candidate in checklist_hostname_values(record))


def artifact_title(record: dict) -> str:
	direct_value = first_record_value(record, ARTIFACT_TITLE_KEYS)
	if direct_value:
		return direct_value
	nested_value = first_nested_record_value(
		record,
		[
			["artifact", "artifactTitle"],
			["artifact", "title"],
			["checklist", "artifactTitle"],
			["checklist", "title"],
			["score", "artifactTitle"],
			["score", "title"],
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


def checklist_score_value(record: dict, score_key: str):
	for path in [["score", score_key], ["checklistScore", score_key], ["checklistscore", score_key]]:
		count = numeric_value(value_at_path(record, path))
		if count is not None:
			return count
	return first_numeric_json_value(record, {score_key})


def build_checklist_reason(record: dict) -> str:
	reasons = []
	for severity, score_key in {"High": "totalCat1Open", "Medium": "totalCat2Open", "Low": "totalCat3Open"}.items():
		count = checklist_score_value(record, score_key)
		if count is None:
			continue
		setting_key = CHECKLIST_SETTING_KEYS[severity]
		threshold = numeric_value(QUARANTINE_SETTINGS.get(setting_key, 0)) or 0
		if count > threshold:
			reasons.append(f"{severity} open checklist vulnerabilities ({score_key}): {count} exceeds maximum {threshold}")

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


def build_hardware_inventory(hardware_data) -> list[dict[str, str]]:
	devices = []
	seen_hostnames = set()
	for record in hardware_records(hardware_data):
		hostname = record_hostname(record)
		normalized_hostname = normalized_value(hostname)
		if normalized_hostname in ("", "unknown") or normalized_hostname in seen_hostnames:
			continue
		seen_hostnames.add(normalized_hostname)
		devices.append(
			{
				"hostname": hostname,
				"IP address": ", ".join(extract_ips(record)),
			}
		)
	return sorted(devices, key=lambda row: (row["hostname"].lower(), row["IP address"]))


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


def build_hardware_checklist_inventory(hardware_inventory: list[dict[str, str]], checklist_data_by_hostname: dict[str, object]) -> list[dict[str, str]]:
	rows = []
	for hardware_record in hardware_inventory:
		hostname = hardware_record["hostname"]
		for record in checklist_records(checklist_data_by_hostname.get(hostname, [])):
			if not checklist_record_matches_hardware(record, hardware_record):
				continue
			reason = build_checklist_reason(record)
			if not reason:
				continue

			rows.append(
				{
					"hostname": hostname,
					"IP address": hardware_record["IP address"],
					"artifactTitle": artifact_title(record),
					"reason": reason,
				}
			)
	return sorted(rows, key=lambda row: (safe_text(row["hostname"]).lower(), safe_text(row["IP address"]), safe_text(row["artifactTitle"]).lower()))


def checklist_record_count(checklist_data_by_hostname: dict[str, object]) -> int:
	return sum(len(checklist_records(checklist_data)) for checklist_data in checklist_data_by_hostname.values())


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


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, hardware_data, patch_score_devices_data, checklist_data_by_hostname: dict[str, object]) -> dict:
	system_title = build_system_title(system_package, options)
	hardware_inventory = build_hardware_inventory(hardware_data)
	hardware_patch_listing = build_hardware_patch_listing(hardware_data, patch_score_devices_data)
	hardware_checklist_inventory = build_hardware_checklist_inventory(hardware_inventory, checklist_data_by_hostname)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"framework_title": framework_value(system_package, options, {"frameworkTitle", "frameworktitle", "framework_title"}, "frameworkTitle", "frameworktitle", "framework_title"),
		"framework_version": framework_value(system_package, options, {"frameworkVersion", "frameworkversion", "framework_version"}, "frameworkVersion", "frameworkversion", "framework_version"),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"checklist_count": checklist_record_count(checklist_data_by_hostname),
		"hardware_count": len(hardware_inventory),
		"hardware_patch_listing": hardware_patch_listing,
		"hardware_checklist_inventory": hardware_checklist_inventory,
	}


def build_checklist_data_by_hostname(arguments: list[str], hardware_data) -> dict[str, object]:
	checklist_data_by_hostname = {}
	for hardware_record in build_hardware_inventory(hardware_data):
		hostname = hardware_record["hostname"]
		checklist_data = parse_json_value_from_output(call_checklists_json_script_for_hostname(arguments, hostname))
		checklist_data_by_hostname[hostname] = [
			record
			for record in checklist_records(checklist_data)
			if checklist_record_matches_hardware(record, hardware_record)
		]
	return checklist_data_by_hostname


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"
	table_body_style = styles["BodyText"].clone("QuarantineTableBody")
	table_body_style.fontSize = 8
	table_body_style.leading = 9.5
	link_style = styles["BodyText"].clone("ContentsLink")
	link_style.textColor = colors.blue

	def contents_link(title: str, anchor_name: str) -> Paragraph:
		return Paragraph(f'<link href="#{anchor_name}">{html.escape(title)}</link>', link_style)

	def listing_table(rows: list[dict[str, str]], include_artifact_title: bool = False) -> Table:
		headers = ["Hostname", "IP"]
		if include_artifact_title:
			headers.append("Artifact Title")
		headers.append("Reason")
		table_rows = [[Paragraph(header, table_header_style) for header in headers]]
		if rows:
			for row in rows:
				table_row = [
					Paragraph(html.escape(safe_text(row.get("hostname", "Unknown"))), table_body_style),
					Paragraph(html.escape(safe_text(row.get("IP address", ""))), table_body_style),
				]
				if include_artifact_title:
					table_row.append(Paragraph(html.escape(safe_text(row.get("artifactTitle", "Unknown"))), table_body_style))
				table_row.append(Paragraph(html.escape(safe_text(row.get("reason", ""))), table_body_style))
				table_rows.append(table_row)
		else:
			empty_row = [Paragraph("No quarantine records found.", table_body_style), Paragraph("", table_body_style)]
			if include_artifact_title:
				empty_row.append(Paragraph("", table_body_style))
			empty_row.append(Paragraph("", table_body_style))
			table_rows.append(empty_row)
		column_widths = [120, 85, 145, 190] if include_artifact_title else [145, 105, 290]
		table = Table(table_rows, hAlign="LEFT", colWidths=column_widths, repeatRows=1)
		table.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
					("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
					("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
					("VALIGN", (0, 0), (-1, -1), "TOP"),
					("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
				]
			)
		)
		return table

	contents_table = Table(
		[
			[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)],
			[contents_link("Hardware Patch Information", "hardware_patch_information"), "2"],
			[contents_link("Hardware Checklist Inventory", "hardware_checklist_inventory"), "3"],
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

	def draw_page_number(canvas, document) -> None:
		canvas.saveState()
		canvas.setFont("Helvetica", 9)
		canvas.drawRightString(document.pagesize[0] - document.rightMargin, 24, f"Page {document.page}")
		canvas.restoreState()

	story = [
		Paragraph(report_data["report_title"], styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		Paragraph(f"Number of Checklists: {html.escape(safe_text(report_data['checklist_count']))}", styles["Normal"]),
		Paragraph(f"Number of Hardware Devices: {html.escape(safe_text(report_data['hardware_count']))}", styles["Normal"]),
		Spacer(1, 18),
		contents_table,
		PageBreak(),
		Paragraph('<a name="hardware_patch_information"/>Hardware Patch Information', styles["Heading1"]),
		Spacer(1, 12),
		listing_table(report_data["hardware_patch_listing"]),
		PageBreak(),
		Paragraph('<a name="hardware_checklist_inventory"/>Hardware Checklist Inventory', styles["Heading1"]),
		Spacer(1, 12),
		listing_table(report_data["hardware_checklist_inventory"], include_artifact_title=True),
	]
	document.build(story, onFirstPage=draw_page_number, onLaterPages=draw_page_number)
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


def add_text_page_number(page_stream: str, page_number: int) -> str:
	return "\n".join(
		[
			page_stream,
			"BT",
			"/F1 9 Tf",
			f"1 0 0 1 530 24 Tm ({escape_pdf_text(f'Page {page_number}')}) Tj",
			"ET",
		]
	)


def chunk_lines(lines: list[str], chunk_size: int) -> list[list[str]]:
	if not lines:
		return [[]]
	return [lines[index:index + chunk_size] for index in range(0, len(lines), chunk_size)]


def fallback_link_annotation(rectangle: tuple[int, int, int, int], target_page_object_number: int) -> bytes:
	x1, y1, x2, y2 = rectangle
	return (
		f"<< /Type /Annot /Subtype /Link /Rect [{x1} {y1} {x2} {y2}] "
		f"/Border [0 0 0] /A << /S /GoTo /D [{target_page_object_number} 0 R /Fit] >> >>"
	).encode("ascii")


def fallback_table_lines(rows: list[dict[str, str]], include_artifact_title: bool = False) -> list[str]:
	if include_artifact_title:
		lines = [
			"Hostname                   IP                     Artifact Title              Reason",
			"------------------------   --------------------   -------------------------   -----------------------------------",
		]
	else:
		lines = [
			"Hostname                       IP                         Reason",
			"----------------------------   ------------------------   -----------------------------------------------",
		]
	if not rows:
		return [*lines, "No quarantine records found."]
	for row in rows:
		hostname = display_value(row.get("hostname", "Unknown")) or "Unknown"
		ip_address = display_value(row.get("IP address", ""))
		artifact_title_text = display_value(row.get("artifactTitle", "Unknown")) or "Unknown"
		reason_width = 35 if include_artifact_title else 47
		reason_lines = textwrap.wrap(
			display_value(row.get("reason", "")),
			width=reason_width,
			break_long_words=False,
			break_on_hyphens=False,
		) or [""]
		for index, reason_line in enumerate(reason_lines):
			if include_artifact_title:
				lines.append(
					f"{hostname[:24]:<24}   {ip_address[:20]:<20}   {artifact_title_text[:25]:<25}   {reason_line}"
					if index == 0 else f"{'':<24}   {'':<20}   {'':<25}   {reason_line}"
				)
			else:
				lines.append(f"{hostname[:28]:<28}   {ip_address[:24]:<24}   {reason_line}" if index == 0 else f"{'':<28}   {'':<24}   {reason_line}")
	return lines


def write_minimal_pdf(output_path: Path, report_data: dict) -> None:
	patch_chunks = chunk_lines(fallback_table_lines(report_data["hardware_patch_listing"]), 48)
	checklist_inventory_chunks = chunk_lines(fallback_table_lines(report_data["hardware_checklist_inventory"], include_artifact_title=True), 48)
	patch_start_page_index = 1
	checklist_inventory_start_page_index = patch_start_page_index + len(patch_chunks)
	page_streams = [
		make_text_page(
			[
				report_data["report_title"],
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"System Key: {report_data['system_key']}",
				f"System Title: {report_data['system_title']}",
				f"Description: {report_data['system_description']}",
				f"Number of Checklists: {report_data['checklist_count']}",
				f"Number of Hardware Devices: {report_data['hardware_count']}",
				"",
				"Page Title                                      Page Number",
				"--------------------------------------------  -----------",
				"Hardware Patch Information                              2",
				"Hardware Checklist Inventory                            3",
			],
			font_size=14,
		),
	]
	for index, lines in enumerate(patch_chunks):
		page_lines = ["Hardware Patch Information", ""] if index == 0 else ["Hardware Patch Information (continued)", ""]
		page_streams.append(make_text_page([*page_lines, *lines], font_size=9))
	for index, lines in enumerate(checklist_inventory_chunks):
		page_lines = ["Hardware Checklist Inventory", ""] if index == 0 else ["Hardware Checklist Inventory (continued)", ""]
		page_streams.append(make_text_page([*page_lines, *lines], font_size=9))
	page_streams = [add_text_page_number(page_stream, page_number) for page_number, page_stream in enumerate(page_streams, start=1)]

	total_pages = len(page_streams)
	page_object_number_for_index = lambda page_index: 4 + page_index * 2
	first_page_link_targets = [
		((PDF_LEFT_MARGIN, 582, 420, 604), page_object_number_for_index(patch_start_page_index)),
		((PDF_LEFT_MARGIN, 564, 420, 586), page_object_number_for_index(checklist_inventory_start_page_index)),
	]
	first_annotation_object_number = 4 + total_pages * 2
	first_page_annotation_references = [f"{first_annotation_object_number + index} 0 R" for index in range(len(first_page_link_targets))]

	objects = [
		b"<< /Type /Catalog /Pages 2 0 R >>",
		b"",
		b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	]
	page_object_numbers = []
	for page_stream in page_streams:
		page_index = len(page_object_numbers)
		page_object_number = len(objects) + 1
		content_object_number = len(objects) + 2
		page_object_numbers.append(page_object_number)
		annotations = ""
		if page_index == 0:
			annotations = " /Annots [" + " ".join(first_page_annotation_references) + "]"
		objects.append(
			f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R{annotations} >>".encode("latin-1")
		)
		stream_bytes = page_stream.encode("latin-1", errors="replace")
		objects.append(b"<< /Length " + str(len(stream_bytes)).encode("ascii") + b" >>\nstream\n" + stream_bytes + b"\nendstream")
	for rectangle, target_page_object_number in first_page_link_targets:
		objects.append(fallback_link_annotation(rectangle, target_page_object_number))
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
	checklist_data_by_hostname = build_checklist_data_by_hostname(arguments, hardware_data)
	report_data = build_report_data(system_key, options, system_package, hardware_data, patch_score_devices_data, checklist_data_by_hostname)
	output_filename = f"OpenRMFPro-Quarantine-Checker-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
