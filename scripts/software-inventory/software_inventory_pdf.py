#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional Software Inventory Lifecycle PDF
# API Path   : GET /systempackage/{systemKey} and GET /systempackage/{systemKey}/software
# Description: Creates a two-page software lifecycle report showing software age buckets by hostname.
# ============================================================

import html
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import requests

REQUIRED_ARGUMENT_COUNT = 5
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
SOFTWARE_SCRIPT_FOLDER = "software"
SOFTWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_software_json.py"
DEFAULT_GENERATED_AT = "2026-06-16 10:00:38 AM EDT"
DEFAULT_SYSTEM_TITLE = "Soteria Infrastructure"
DEFAULT_SYSTEM_KEY = "soteria-infra"
DEFAULT_DESCRIPTION = "Soteria Software desktops, servers, network, infrastructure and policies/procedures."
END_OF_LIFE_PRODUCTS_URL = "https://endoflife.date/api/all.json"
END_OF_LIFE_PRODUCT_URL_TEMPLATE = "https://endoflife.date/api/{product}.json"
EOL_TIMEOUT_SECONDS = 8

HOSTNAME_KEYS = ["hostname", "hostName", "deviceName", "devicename", "assetName", "computerName", "machineName", "name"]
HOSTNAME_LIST_KEYS = ["hostnames", "hostNames", "hostnameList", "hostNameList", "deviceNames", "devices", "assets"]
SOFTWARE_KEYS = ["softwareName", "software", "name", "applicationName", "productName", "title"]
VENDOR_KEYS = ["vendor", "vendorName", "manufacturer", "publisher", "companyName"]
VERSION_KEYS = ["version", "softwareVersion", "productVersion", "release"]
UPDATED_KEYS = ["updated", "updatedAt", "updatedDate", "lastUpdated", "lastUpdatedAt", "modified", "modifiedAt", "scanDate", "lastSeen"]


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 software-inventory/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
	)
	print("Optional: generatedAt=VALUE outputFile=VALUE skipEol=true")


def safe_text(value) -> str:
	if value is None:
		return ""
	return str(value)


def display_value(value) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip())


def safe_filename_value(value: str) -> str:
	safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
	return safe_value.strip(".-") or "unknown-system"


def parse_optional_arguments(arguments: list[str]) -> dict[str, str]:
	parsed = {}
	for argument in arguments:
		if "=" not in argument:
			print(f"ERROR: Optional arguments must use KEY=VALUE format. Invalid value: {argument}")
			sys.exit(1)
		key, value = argument.split("=", 1)
		parsed[key] = value
	return parsed


def truthy_option(options: dict[str, str], key: str) -> bool:
	return display_value(options.get(key)).lower() in {"1", "true", "yes", "y"}


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


def call_software_json_script(arguments: list[str]) -> str:
	software_arguments = list(arguments)
	if not any(argument.lower().startswith("groupby=") for argument in software_arguments[4:]):
		software_arguments.append("groupby=false")
	return call_json_script(SOFTWARE_SCRIPT_FOLDER, SOFTWARE_SCRIPT_NAME, software_arguments, "software inventory")


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
	print("ERROR: Could not find JSON in script output.")
	print(output)
	sys.exit(1)


def first_value(record: dict, keys: list[str]) -> str:
	for key in keys:
		value = record.get(key)
		if value not in (None, "") and not isinstance(value, (dict, list)):
			return display_value(value)
	return ""


def collect_text_values(value) -> list[str]:
	if value in (None, ""):
		return []
	if isinstance(value, str):
		parts = [part.strip() for part in re.split(r"[,;\n]+", value) if part.strip()]
		return parts or [display_value(value)]
	if isinstance(value, dict):
		for keys in (HOSTNAME_KEYS, ["hostname", "hostName", "name", "deviceName", "assetName"]):
			text = first_value(value, keys)
			if text:
				return [text]
		return []
	if isinstance(value, list):
		values = []
		for item in value:
			values.extend(collect_text_values(item))
		return values
	return [display_value(value)]


def hostnames_for_record(record: dict) -> list[str]:
	hostnames = []
	for key in HOSTNAME_LIST_KEYS:
		hostnames.extend(collect_text_values(record.get(key)))
	hostname = first_value(record, HOSTNAME_KEYS) or first_nested_value(record, [["asset", "hostname"], ["asset", "hostName"], ["device", "hostname"], ["device", "hostName"]])
	if hostname:
		hostnames.append(hostname)
	unique_hostnames = [hostname for hostname in dict.fromkeys(hostnames) if hostname]
	return unique_hostnames or ["Unknown"]


def first_nested_value(record: dict, paths: list[list[str]]) -> str:
	for path in paths:
		current_value = record
		for key in path:
			if not isinstance(current_value, dict) or key not in current_value:
				current_value = None
				break
			current_value = current_value[key]
		if current_value not in (None, ""):
			return display_value(current_value)
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


def parse_datetime_value(value):
	value_text = display_value(value)
	if not value_text:
		return None
	normalized_value = value_text.replace("Z", "+00:00")
	try:
		return datetime.fromisoformat(normalized_value).replace(tzinfo=None)
	except ValueError:
		pass
	for date_format in ("%Y-%m-%d %I:%M:%S %p %Z", "%Y-%m-%d %I:%M:%S %p", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %I:%M %p", "%m/%d/%Y"):
		try:
			return datetime.strptime(value_text, date_format)
		except ValueError:
			continue
	return None


def report_datetime(generated_at: str) -> datetime:
	parsed_value = parse_datetime_value(generated_at)
	return parsed_value or datetime.now()


def normalize_product_key(value: str) -> str:
	value_text = display_value(value).lower()
	value_text = re.sub(r"\b(microsoft|corporation|inc|llc|ltd|the|foundation|software)\b", " ", value_text)
	value_text = re.sub(r"[^a-z0-9]+", "-", value_text)
	return value_text.strip("-")


def fetch_json_url(url: str):
	response = requests.get(url, timeout=EOL_TIMEOUT_SECONDS)
	response.raise_for_status()
	return response.json()


def candidate_eol_product_names(software_name: str, vendor: str) -> list[str]:
	candidates = [normalize_product_key(software_name)]
	if vendor:
		candidates.append(normalize_product_key(f"{vendor} {software_name}"))
	words = [word for word in re.split(r"[^A-Za-z0-9]+", software_name.lower()) if word]
	if len(words) > 1:
		candidates.append("-".join(words[:2]))
		candidates.append(words[0])
	return [candidate for candidate in dict.fromkeys(candidates) if candidate]


def matching_eol_cycle(cycles: list[dict], version: str) -> dict:
	version_text = display_value(version).lower()
	if not version_text:
		return {}
	for cycle in cycles:
		cycle_value = display_value(cycle.get("cycle")).lower()
		if cycle_value and (version_text == cycle_value or version_text.startswith(cycle_value + ".")):
			return cycle
	version_major = version_text.split(".", 1)[0]
	for cycle in cycles:
		if display_value(cycle.get("cycle")).lower() == version_major:
			return cycle
	return {}


def eol_field_value(value) -> str:
	if value in (None, "", False):
		return ""
	return display_value(value)


def forecast_mark(days_to_eol) -> str:
	try:
		days = int(days_to_eol)
	except (TypeError, ValueError):
		return "No"
	if days < 0:
		return "Reached"
	return "Reached" if days <= 0 else "No"


def forecast_window_mark(days_to_eol, window_days: int) -> str:
	try:
		days = int(days_to_eol)
	except (TypeError, ValueError):
		return "No"
	if days < 0:
		return "Reached"
	return "Reached" if days <= window_days else "No"


def build_eol_dataframe(inventory_df, skip_eol: bool):
	try:
		import pandas as pd
	except ImportError:
		return None
	if skip_eol or inventory_df.empty:
		return pd.DataFrame(columns=["software_key", "version", "external_product", "eol_date", "support_date"])
	try:
		products = set(fetch_json_url(END_OF_LIFE_PRODUCTS_URL))
	except (requests.RequestException, TimeoutError, ValueError) as exc:
		print(f"WARNING: Could not reach endoflife.date API. Continuing without EOL enrichment. Details: {exc}")
		return pd.DataFrame(columns=["software_key", "version", "external_product", "eol_date", "support_date"])

	rows = []
	unique_software = inventory_df[["software_key", "software", "vendor", "version"]].drop_duplicates()
	product_cache = {}
	for record in unique_software.to_dict("records"):
		product_name = ""
		for candidate in candidate_eol_product_names(record["software"], record["vendor"]):
			if candidate in products:
				product_name = candidate
				break
		if not product_name:
			continue
		if product_name not in product_cache:
			try:
				product_cache[product_name] = fetch_json_url(END_OF_LIFE_PRODUCT_URL_TEMPLATE.format(product=product_name))
			except (requests.RequestException, TimeoutError, ValueError):
				product_cache[product_name] = []
		cycles = product_cache.get(product_name, [])
		if not isinstance(cycles, list):
			continue
		cycle = matching_eol_cycle([item for item in cycles if isinstance(item, dict)], record["version"])
		if not cycle:
			continue
		rows.append(
			{
				"software_key": record["software_key"],
				"version": record["version"],
				"external_product": product_name,
				"eol_date": eol_field_value(cycle.get("eol")),
				"support_date": eol_field_value(cycle.get("support")),
			}
		)
	return pd.DataFrame(rows, columns=["software_key", "version", "external_product", "eol_date", "support_date"])


def software_record_to_rows(record: dict) -> list[dict[str, str]]:
	software = first_value(record, SOFTWARE_KEYS) or first_nested_value(record, [["software", "name"], ["application", "name"], ["product", "name"]])
	vendor = first_value(record, VENDOR_KEYS) or first_nested_value(record, [["software", "vendor"], ["application", "vendor"], ["product", "vendor"]])
	version = first_value(record, VERSION_KEYS) or first_nested_value(record, [["software", "version"], ["application", "version"], ["product", "version"]])
	updated = first_value(record, UPDATED_KEYS) or first_nested_value(record, [["software", "updated"], ["asset", "updated"], ["device", "updated"], ["scan", "updated"]])
	return [
		{
			"hostname": hostname,
			"software": software or "Unknown",
			"vendor": vendor,
			"version": version or "Unknown",
			"updated": updated or "Unknown",
			"software_key": normalize_product_key(software or "Unknown"),
		}
		for hostname in hostnames_for_record(record)
	]


def build_lifecycle_rows(software_data, generated_at: str, skip_eol: bool) -> list[dict[str, str]]:
	try:
		import pandas as pd
	except ImportError:
		print("ERROR: pandas is required for this lifecycle workflow. Install it with: pip install pandas")
		sys.exit(1)

	records = find_record_list(software_data, ["records", "items", "data", "results", "software", "applications"])
	inventory_rows = []
	for record in records:
		inventory_rows.extend(software_record_to_rows(record))
	inventory_df = pd.DataFrame(inventory_rows)
	if inventory_df.empty:
		return []

	current_date = pd.Timestamp(report_datetime(generated_at))
	inventory_df["updated_date"] = pd.to_datetime(inventory_df["updated"], errors="coerce", utc=True).dt.tz_convert(None)
	inventory_df["days_since_updated"] = (current_date - inventory_df["updated_date"]).dt.days
	inventory_df["past_30_days"] = inventory_df["days_since_updated"].ge(30).fillna(False)
	inventory_df["past_60_days"] = inventory_df["days_since_updated"].ge(60).fillna(False)
	inventory_df["past_90_days"] = inventory_df["days_since_updated"].ge(90).fillna(False)

	eol_df = build_eol_dataframe(inventory_df, skip_eol)
	if eol_df is not None and not eol_df.empty:
		inventory_df = inventory_df.merge(eol_df, how="left", on=["software_key", "version"])
	for column_name in ("external_product", "eol_date", "support_date"):
		if column_name not in inventory_df.columns:
			inventory_df[column_name] = ""
	inventory_df["eol_datetime"] = pd.to_datetime(inventory_df["eol_date"], errors="coerce", utc=True).dt.tz_convert(None)
	inventory_df["time_to_deprecation_days"] = (inventory_df["eol_datetime"] - current_date).dt.days

	inventory_df = inventory_df.sort_values(
		by=["past_90_days", "past_60_days", "past_30_days", "hostname", "software"],
		ascending=[False, False, False, True, True],
	)
	rows = []
	for record in inventory_df.to_dict("records"):
		rows.append(
			{
				"hostname": display_value(record.get("hostname")) or "Unknown",
				"software": display_value(record.get("software")) or "Unknown",
				"version": display_value(record.get("version")) or "Unknown",
				"updated": display_value(record.get("updated")) or "Unknown",
				"past_30_days": "Reached" if bool(record.get("past_30_days")) else "No",
				"past_60_days": "Reached" if bool(record.get("past_60_days")) else "No",
				"past_90_days": "Reached" if bool(record.get("past_90_days")) else "No",
				"external_product": display_value(record.get("external_product")) or "Not Matched",
				"eol_date": display_value(record.get("eol_date")) or "Not Matched",
				"support_date": display_value(record.get("support_date")) or "Unknown",
				"time_to_deprecation_days": "" if pd.isna(record.get("time_to_deprecation_days")) else safe_text(int(record.get("time_to_deprecation_days"))),
				"eol_30_days": forecast_window_mark(record.get("time_to_deprecation_days"), 30),
				"eol_60_days": forecast_window_mark(record.get("time_to_deprecation_days"), 60),
				"eol_90_days": forecast_window_mark(record.get("time_to_deprecation_days"), 90),
			}
		)
	return rows


def build_report_data(system_package: dict, software_data, options: dict[str, str]) -> dict:
	system_key = display_value(system_package.get("systemKey")) or display_value(options.get("systemKey")) or DEFAULT_SYSTEM_KEY
	generated_at = display_value(options.get("generatedAt")) or DEFAULT_GENERATED_AT
	system_title = display_value(system_package.get("title")) or DEFAULT_SYSTEM_TITLE
	description = display_value(system_package.get("description")) or DEFAULT_DESCRIPTION
	lifecycle_rows = build_lifecycle_rows(software_data, generated_at, truthy_option(options, "skipEol"))
	return {
		"report_title": f"{system_title} Software Inventory Lifecycle",
		"generated_at": generated_at,
		"system_title": system_title,
		"system_key": system_key,
		"description": description,
		"lifecycle_rows": lifecycle_rows,
		"total_software": safe_text(len(lifecycle_rows)),
		"past_30_total": safe_text(sum(1 for row in lifecycle_rows if row["past_30_days"] == "Reached")),
		"past_60_total": safe_text(sum(1 for row in lifecycle_rows if row["past_60_days"] == "Reached")),
		"past_90_total": safe_text(sum(1 for row in lifecycle_rows if row["past_90_days"] == "Reached")),
	}


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
	try:
		from reportlab.lib import colors
		from reportlab.lib.pagesizes import landscape, letter
		from reportlab.lib.styles import getSampleStyleSheet
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	heading_style = styles["Heading1"]
	body_style = styles["BodyText"]
	header_style = styles["BodyText"].clone("LifecycleTableHeader")
	header_style.fontName = "Helvetica-Bold"
	header_style.alignment = 1

	document = SimpleDocTemplate(
		str(output_path),
		pagesize=landscape(letter),
		rightMargin=36,
		leftMargin=36,
		topMargin=42,
		bottomMargin=36,
		title=report_data["report_title"],
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(html.escape(report_data["report_title"]), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['description'])}", styles["Normal"]),
		PageBreak(),
		Paragraph("Software Lifecycle", heading_style),
		Spacer(1, 12),
	]

	table_rows = [
		[
			Paragraph("Hostname", header_style),
			Paragraph("Software", header_style),
			Paragraph("Version", header_style),
			Paragraph("Updated", header_style),
			Paragraph("30-Day Mark", header_style),
			Paragraph("60-Day Mark", header_style),
			Paragraph("90-Day Mark", header_style),
		]
	]
	for row in report_data["lifecycle_rows"]:
		table_rows.append(
			[
				Paragraph(html.escape(row["hostname"]), body_style),
				Paragraph(html.escape(row["software"]), body_style),
				Paragraph(html.escape(row["version"]), body_style),
				Paragraph(html.escape(row["updated"]), body_style),
				Paragraph(html.escape(row["past_30_days"]), body_style),
				Paragraph(html.escape(row["past_60_days"]), body_style),
				Paragraph(html.escape(row["past_90_days"]), body_style),
			]
		)
	if len(table_rows) == 1:
		table_rows.append(["No software inventory records returned.", "", "", "", "", "", ""])

	lifecycle_table = Table(table_rows, hAlign="LEFT", repeatRows=1, colWidths=[104, 210, 80, 110, 72, 72, 72])
	lifecycle_styles = [
		("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
		("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
		("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (4, 1), (-1, -1), "CENTER"),
		("VALIGN", (0, 0), (-1, -1), "TOP"),
		("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
	]
	lifecycle_table.setStyle(TableStyle(lifecycle_styles))
	story.append(lifecycle_table)
	document.build(story)
	return True


def create_pdf(report_data: dict, options: dict[str, str]) -> Path:
	output_path = Path(options.get("outputFile") or f"OpenRMFPro-Software-Inventory-{safe_filename_value(report_data['system_key'])}.pdf")
	if not output_path.is_absolute():
		output_path = Path.cwd() / output_path
	if write_pdf_with_reportlab(output_path, report_data):
		return output_path
	print("ERROR: reportlab is required to create this PDF. Install it with: pip install reportlab")
	sys.exit(1)


def main() -> None:
	if len(sys.argv) < REQUIRED_ARGUMENT_COUNT:
		print_usage()
		sys.exit(1)

	api_arguments = sys.argv[1:REQUIRED_ARGUMENT_COUNT]
	options = parse_optional_arguments(sys.argv[REQUIRED_ARGUMENT_COUNT:])
	options.setdefault("systemKey", api_arguments[3])
	system_package = parse_json_value_from_output(call_system_package_json_script(api_arguments))
	software_data = parse_json_value_from_output(call_software_json_script(api_arguments))
	if not isinstance(system_package, dict):
		print("ERROR: The system package endpoint did not return a JSON object.")
		sys.exit(1)

	report_data = build_report_data(system_package, software_data, options)
	output_path = create_pdf(report_data, options)
	print(f"Created PDF: {output_path.name}")


if __name__ == "__main__":
	main()
