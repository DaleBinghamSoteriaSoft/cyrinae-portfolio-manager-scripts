#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional Ghost Asset PDF
# Description: Creates a Ghost Asset data-quality PDF report for a system key.
# ============================================================

import html
import ipaddress
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE_SUFFIX = "Ghost Asset"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
HARDWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_hardware_json.py"
PATCH_DATA_SCRIPT_NAME = "get_systempackage_by_systemkey_patchdata_json.py"
CHECKLIST_SCRIPT_NAME = "get_systempackage_by_systemkey_checklists_json.py"
DEFAULT_CHECKLIST_LIMIT = 5000
DEFAULT_TOP_ROWS = 40

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
PATCH_ACTIVE_KEYS = [
	"patchscan",
	"patchScan",
	"patchScanEnabled",
	"hasPatchScan",
	"patchScanActive",
	"activePatchScan",
	"scanActive",
	"isPatchScanActive",
]
CHECKLIST_COUNT_KEYS = [
	"checklistCount",
	"checklistsCount",
	"stigChecklistCount",
	"activeChecklistCount",
	"activeStigChecklistCount",
	"assignedChecklistCount",
]
CHECKLIST_ACTIVE_KEYS = [
	"hasChecklists",
	"hasChecklist",
	"checklistsAssigned",
	"stigAssigned",
	"hasStig",
	"activeChecklist",
]
PATCH_SCORE_KEYS = [
	"totalCriticalOpen",
	"totalHighOpen",
	"totalMediumOpen",
	"totalLowOpen",
	"criticalOpen",
	"highOpen",
	"mediumOpen",
	"lowOpen",
]


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 ghost-asset/"
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


def normalized_hostname(value) -> str:
	text = normalized_value(value)
	if not text:
		return ""
	return text.split(".", 1)[0] if "." in text else text


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


def optional_int(options: dict[str, str], key: str, default_value: int) -> int:
	try:
		return int(float(options.get(key, default_value)))
	except (TypeError, ValueError):
		return default_value


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


def call_patch_data_json_script(arguments: list[str]) -> str:
	return call_json_script("patch-vulnerability", PATCH_DATA_SCRIPT_NAME, [*arguments, "groupby=false"], "patch data")


def call_checklist_json_script(arguments: list[str], options: dict[str, str]) -> str:
	checklist_arguments = list(arguments)
	if not any(argument.startswith("limit=") for argument in checklist_arguments[4:]):
		checklist_arguments.append(f"limit={optional_int(options, 'checklistLimit', DEFAULT_CHECKLIST_LIMIT)}")
	if not any(argument.startswith("page=") for argument in checklist_arguments[4:]):
		checklist_arguments.append("page=1")
	return call_json_script("checklist", CHECKLIST_SCRIPT_NAME, checklist_arguments, "checklist")


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


def first_json_value(data, keys: set[str]) -> str:
	if isinstance(data, dict):
		for key, value in data.items():
			if key in keys and value not in (None, ""):
				return safe_text(value).strip()
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
			return safe_text(value).strip()
	return ""


def first_nested_record_value(record: dict, paths: list[list[str]]) -> str:
	for path in paths:
		current_value = record
		for key in path:
			if not isinstance(current_value, dict) or key not in current_value:
				current_value = None
				break
			current_value = current_value[key]
		if current_value not in (None, ""):
			return safe_text(current_value).strip()
	return ""


def value_at_path(record: dict, path: list[str]):
	current_value = record
	for key in path:
		if not isinstance(current_value, dict) or key not in current_value:
			return None
		current_value = current_value[key]
	return current_value


def iter_scalar_values(value):
	if isinstance(value, dict):
		for nested_value in value.values():
			yield from iter_scalar_values(nested_value)
	elif isinstance(value, list):
		for nested_value in value:
			yield from iter_scalar_values(nested_value)
	elif value not in (None, ""):
		yield safe_text(value)


def truthy_value(value) -> bool:
	if isinstance(value, bool):
		return value
	if isinstance(value, (int, float)):
		return value > 0
	text = normalized_value(value)
	return text in {"1", "true", "yes", "y", "active", "enabled", "assigned", "complete", "completed", "open"}


def count_value(value) -> int:
	if isinstance(value, bool):
		return 1 if value else 0
	if isinstance(value, (int, float)):
		return max(0, int(value))
	if isinstance(value, list):
		return len(value)
	if isinstance(value, dict):
		return len(value)
	text = display_value(value)
	if not text:
		return 0
	try:
		return max(0, int(float(text)))
	except ValueError:
		return 1 if truthy_value(text) else 0


def valid_ip(value: str) -> str:
	try:
		return str(ipaddress.ip_address(display_value(value)))
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
		return normalized_hostname(direct_value)
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
	return normalized_hostname(nested_value) if nested_value else ""


def record_identity_key(record: dict) -> str:
	hostname = record_hostname(record)
	if hostname:
		return f"host:{hostname}"
	ips = extract_ips(record)
	if ips:
		return f"ip:{ips[0]}"
	return ""


def record_display_name(record: dict) -> str:
	direct_value = first_record_value(record, HOSTNAME_KEYS)
	if direct_value:
		return display_value(direct_value)
	ips = extract_ips(record)
	if ips:
		return ips[0]
	return "Unknown"


def looks_like_hardware_record(value: dict) -> bool:
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS + PATCH_ACTIVE_KEYS + CHECKLIST_COUNT_KEYS + CHECKLIST_ACTIVE_KEYS).intersection(value.keys())
		or {"hardware", "serialNumber", "assetTag", "macAddress", "operatingSystem"}.intersection(value.keys())
	)


def looks_like_checklist_record(value: dict) -> bool:
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS).intersection(value.keys())
		or {"checklistId", "checklistID", "stigId", "stigID", "stigTitle", "benchmarkId", "benchmarkTitle", "checklist", "status"}.intersection(value.keys())
	)


def looks_like_patch_asset_record(value: dict) -> bool:
	if not (set(HOSTNAME_KEYS + IP_KEYS).intersection(value.keys()) or record_hostname(value) or extract_ips(value)):
		return False
	return bool(
		set(PATCH_SCORE_KEYS + PATCH_ACTIVE_KEYS).intersection(value.keys())
		or {
			"scanDate",
			"lastScanDate",
			"vulnerabilityCount",
			"openCount",
			"severity",
			"severityText",
			"pluginId",
			"pluginID",
			"vulnerabilityId",
			"cve",
			"cves",
			"iavm",
			"pluginName",
		}.intersection(value.keys())
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
	if record_predicate(data):
		return [data]

	for key in candidate_keys:
		value = data.get(key)
		if isinstance(value, list):
			records = [record for record in value if isinstance(record, dict)]
			if records:
				return records

	found_records = []
	for value in data.values():
		if isinstance(value, (dict, list)):
			found_records.extend(find_record_list(value, candidate_keys, record_predicate))
	return found_records


def hardware_records(hardware_data) -> list[dict]:
	return find_record_list(hardware_data, ["records", "items", "data", "results", "hardware", "assets", "devices"], looks_like_hardware_record)


def checklist_records(checklist_data) -> list[dict]:
	return find_record_list(checklist_data, ["records", "items", "data", "results", "checklists", "checklist", "assets"], looks_like_checklist_record)


def patch_asset_records(patch_data) -> list[dict]:
	return find_record_list(patch_data, ["records", "items", "data", "results", "assets", "devices", "hosts", "patchData", "patches", "vulnerabilities"], looks_like_patch_asset_record)


def pandas_module():
	try:
		import pandas as pd  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		print("ERROR: pandas is required for this report. Install it in the scripts environment with: python3 -m pip install pandas")
		sys.exit(1)
	return pd


def boolean_flag_from_record(record: dict, keys: list[str]) -> bool:
	for key in keys:
		if key in record and truthy_value(record[key]):
			return True
	return False


def count_from_record(record: dict, keys: list[str]) -> int:
	for key in keys:
		if key in record:
			return count_value(record[key])
	return 0


def checklist_title(record: dict) -> str:
	return display_value(first_record_value(record, ["stigTitle", "title", "benchmarkTitle", "checklistName", "name", "stigId", "stigID", "benchmarkId"])) or "Checklist"


def patch_score_total(record: dict) -> int:
	total = 0
	for key in PATCH_SCORE_KEYS:
		if key in record:
			total += count_value(record[key])
	return total


def normalized_asset_rows(records: list[dict], source: str) -> tuple[list[dict[str, object]], list[str]]:
	rows = []
	skipped = []
	for record in records:
		identity_key = record_identity_key(record)
		hostname = record_hostname(record)
		ips = extract_ips(record)
		if not identity_key:
			skipped.append(f"{source}: missing hostname and IP address")
		rows.append(
			{
				"asset_key": identity_key,
				"hostname": hostname,
				"ip_addresses": ", ".join(ips),
				"display_name": record_display_name(record),
				"source": source,
				"raw_record": record,
			}
		)
	return rows, skipped


def build_hardware_dataframe(pd, records: list[dict]):
	rows, skipped = normalized_asset_rows(records, "hardware")
	for row in rows:
		record = row["raw_record"]
		row["hardware_present"] = bool(row["asset_key"])
		row["hardware_checklist_count"] = count_from_record(record, CHECKLIST_COUNT_KEYS)
		row["hardware_checklist_flag"] = boolean_flag_from_record(record, CHECKLIST_ACTIVE_KEYS)
		row["hardware_patch_scan_flag"] = boolean_flag_from_record(record, PATCH_ACTIVE_KEYS)
		row["operating_system"] = display_value(first_record_value(record, ["operatingSystem", "os", "osName", "platform"])) or "Unknown"
	dataframe = pd.json_normalize(rows) if rows else pd.DataFrame()
	if dataframe.empty:
		dataframe = pd.DataFrame(columns=["asset_key", "hostname", "ip_addresses", "display_name", "hardware_present", "hardware_checklist_count", "hardware_checklist_flag", "hardware_patch_scan_flag", "operating_system"])
	dataframe = dataframe[dataframe["asset_key"].astype(str) != ""].copy()
	if dataframe.empty:
		return dataframe, skipped
	grouped = dataframe.groupby("asset_key", as_index=False).agg(
		{
			"hostname": "first",
			"ip_addresses": "first",
			"display_name": "first",
			"hardware_present": "max",
			"hardware_checklist_count": "sum",
			"hardware_checklist_flag": "max",
			"hardware_patch_scan_flag": "max",
			"operating_system": "first",
		}
	)
	return grouped.rename(columns={"display_name": "hardware_name"}), skipped


def build_checklist_dataframe(pd, records: list[dict]):
	rows, skipped = normalized_asset_rows(records, "checklist")
	for row in rows:
		record = row["raw_record"]
		row["checklist_present"] = bool(row["asset_key"])
		row["checklist_title"] = checklist_title(record)
		row["checklist_status"] = display_value(first_record_value(record, ["status", "state", "checklistStatus", "assessmentStatus"])) or "Unknown"
	dataframe = pd.json_normalize(rows) if rows else pd.DataFrame()
	if dataframe.empty:
		dataframe = pd.DataFrame(columns=["asset_key", "hostname", "ip_addresses", "display_name", "checklist_present", "checklist_title", "checklist_status"])
	dataframe = dataframe[dataframe["asset_key"].astype(str) != ""].copy()
	if dataframe.empty:
		return dataframe, skipped
	grouped = dataframe.groupby("asset_key", as_index=False).agg(
		{
			"hostname": "first",
			"ip_addresses": "first",
			"display_name": "first",
			"checklist_present": "max",
			"checklist_title": lambda values: ", ".join(sorted(set(display_value(value) for value in values if display_value(value)))[:3]),
			"checklist_status": lambda values: ", ".join(sorted(set(display_value(value) for value in values if display_value(value)))[:3]),
		}
	)
	counted = dataframe.groupby("asset_key").size().reset_index(name="checklist_count")
	return grouped.merge(counted, on="asset_key", how="left").rename(columns={"display_name": "checklist_name"}), skipped


def build_patch_dataframe(pd, records: list[dict]):
	rows, skipped = normalized_asset_rows(records, "patch data")
	for row in rows:
		record = row["raw_record"]
		row["patch_present"] = bool(row["asset_key"])
		row["patch_open_total"] = patch_score_total(record)
		row["patch_scan_flag"] = boolean_flag_from_record(record, PATCH_ACTIVE_KEYS) or patch_score_total(record) > 0
		row["patch_scan_date"] = display_value(first_record_value(record, ["scanDate", "lastScanDate", "lastPatchScanDate", "updated", "updatedOn"])) or "Unknown"
	dataframe = pd.json_normalize(rows) if rows else pd.DataFrame()
	if dataframe.empty:
		dataframe = pd.DataFrame(columns=["asset_key", "hostname", "ip_addresses", "display_name", "patch_present", "patch_open_total", "patch_scan_flag", "patch_scan_date"])
	dataframe = dataframe[dataframe["asset_key"].astype(str) != ""].copy()
	if dataframe.empty:
		return dataframe, skipped
	grouped = dataframe.groupby("asset_key", as_index=False).agg(
		{
			"hostname": "first",
			"ip_addresses": "first",
			"display_name": "first",
			"patch_present": "max",
			"patch_open_total": "sum",
			"patch_scan_flag": "max",
			"patch_scan_date": "first",
		}
	)
	return grouped.rename(columns={"display_name": "patch_name"}), skipped


def first_available_text(row, keys: list[str]) -> str:
	for key in keys:
		value = row.get(key, "")
		if display_value(value) and display_value(value).lower() != "nan":
			return display_value(value)
	return "Unknown"


def build_ghost_asset_analysis(hardware_data, patch_data, checklist_data, options: dict[str, str]) -> dict[str, object]:
	pd = pandas_module()
	hardware_record_list = hardware_records(hardware_data)
	checklist_record_list = checklist_records(checklist_data)
	patch_record_list = patch_asset_records(patch_data)
	hardware_df, hardware_skipped = build_hardware_dataframe(pd, hardware_record_list)
	checklist_df, checklist_skipped = build_checklist_dataframe(pd, checklist_record_list)
	patch_df, patch_skipped = build_patch_dataframe(pd, patch_record_list)

	merged = hardware_df.merge(checklist_df, on="asset_key", how="outer", indicator="hardware_checklist_join", suffixes=("_hardware", "_checklist"))
	merged = merged.merge(patch_df, on="asset_key", how="outer", indicator="patch_join")
	if merged.empty:
		merged = pd.DataFrame(columns=["asset_key"])

	for column in ["hardware_present", "checklist_present", "patch_present", "hardware_checklist_flag", "hardware_patch_scan_flag", "patch_scan_flag"]:
		if column not in merged.columns:
			merged[column] = False
		merged[column] = merged[column].fillna(False).astype(bool)
	for column in ["hardware_checklist_count", "checklist_count", "patch_open_total"]:
		if column not in merged.columns:
			merged[column] = 0
		merged[column] = merged[column].fillna(0).astype(int)

	merged["resolved_name"] = merged.apply(lambda row: first_available_text(row, ["hardware_name", "checklist_name", "patch_name", "hostname_hardware", "hostname_checklist", "hostname"]), axis=1)
	merged["resolved_ips"] = merged.apply(lambda row: first_available_text(row, ["ip_addresses_hardware", "ip_addresses_checklist", "ip_addresses"]), axis=1)
	merged["has_checklist_evidence"] = merged["hardware_checklist_flag"] | (merged["hardware_checklist_count"] > 0) | merged["checklist_present"] | (merged["checklist_count"] > 0)
	merged["has_patch_evidence"] = merged["hardware_patch_scan_flag"] | merged["patch_present"] | merged["patch_scan_flag"]

	def missing_sources(row) -> list[str]:
		missing = []
		if not bool(row.get("has_patch_evidence", False)):
			missing.append("Patch Exists")
		if not bool(row.get("has_checklist_evidence", False)):
			missing.append("Checklist Exists")
		if not bool(row.get("hardware_present", False)):
			missing.append("Hardware Exists")
		return missing

	def base_classification(row) -> str:
		hardware_present = bool(row.get("hardware_present", False))
		checklist_present = bool(row.get("has_checklist_evidence", False))
		patch_present = bool(row.get("has_patch_evidence", False))
		if hardware_present and checklist_present and patch_present:
			return "Managed / Correlated"
		if hardware_present and not checklist_present and not patch_present:
			return "Ghost Asset"
		if hardware_present and (checklist_present ^ patch_present):
			return "Incomplete"
		if not hardware_present and patch_present:
			return "Unmanaged Asset"
		if not hardware_present and checklist_present:
			return "Orphaned Checklist Asset"
		return "Uncorrelated Asset"

	def display_classification(row) -> str:
		missing = missing_sources(row)
		classification = row.get("base_classification", "Uncorrelated Asset")
		if not missing:
			return classification
		return f"{classification} (Missing: {', '.join(missing)})"

	merged["base_classification"] = merged.apply(base_classification, axis=1)
	merged["classification"] = merged.apply(display_classification, axis=1)
	merged.loc[~merged["hardware_present"] & (merged["has_checklist_evidence"] | merged["has_patch_evidence"]), "missing_inventory"] = True
	merged["missing_inventory"] = merged.get("missing_inventory", False).fillna(False).astype(bool)

	top_rows = max(1, optional_int(options, "topRows", DEFAULT_TOP_ROWS))
	def yes_no(value: bool) -> str:
		return "Yes" if value else "No"

	def evidence_rows(dataframe):
		rows = []
		for _, row in dataframe.head(top_rows).iterrows():
			checklist_count = int(row.get("checklist_count", 0) or row.get("hardware_checklist_count", 0) or 0)
			patch_open_total = int(row.get("patch_open_total", 0) or 0)
			hardware_present = bool(row.get("hardware_present", False))
			checklist_present = bool(row.get("has_checklist_evidence", False))
			patch_present = bool(row.get("has_patch_evidence", False))
			rows.append(
				{
					"asset": first_available_text(row, ["resolved_name"]),
					"ip_addresses": first_available_text(row, ["resolved_ips"]),
					"patch": f"{yes_no(patch_present)} ({patch_open_total} open)",
					"checklist": f"{yes_no(checklist_present)} ({checklist_count})",
					"hardware": yes_no(hardware_present),
					"classification": row.get("classification", "Unknown"),
				}
			)
		return rows

	ghost_assets = merged.loc[merged["base_classification"] == "Ghost Asset"].copy()
	unmanaged_assets = merged.loc[merged["base_classification"] == "Unmanaged Asset"].copy()
	orphaned_checklists = merged.loc[merged["base_classification"] == "Orphaned Checklist Asset"].copy()
	missing_inventory = merged.loc[merged["missing_inventory"]].copy()
	classification_priority = {
		"Ghost Asset": 0,
		"Unmanaged Asset": 1,
		"Orphaned Checklist Asset": 2,
		"Incomplete": 3,
		"Uncorrelated Asset": 4,
		"Managed / Correlated": 5,
	}
	merged["classification_priority"] = merged["base_classification"].map(classification_priority).fillna(9).astype(int)
	return {
		"hardware_record_count": len(hardware_record_list),
		"checklist_record_count": len(checklist_record_list),
		"patch_asset_record_count": len(patch_record_list),
		"asset_count": int(merged["asset_key"].astype(str).ne("").sum()) if "asset_key" in merged.columns else 0,
		"ghost_asset_count": len(ghost_assets),
		"unmanaged_asset_count": len(unmanaged_assets),
		"orphaned_checklist_count": len(orphaned_checklists),
		"missing_inventory_count": len(missing_inventory),
		"evidence_rows": evidence_rows(merged.sort_values(["classification_priority", "resolved_name", "asset_key"])),
		"skipped_record_count": len(hardware_skipped) + len(checklist_skipped) + len(patch_skipped),
		"skipped_record_examples": (hardware_skipped + checklist_skipped + patch_skipped)[:8],
	}


def build_system_title(system_package: dict, options: dict[str, str]) -> str:
	title = first_json_value(system_package, {"title", "systemTitle", "system_title", "systemName", "name"})
	if title:
		return title
	return optional_value(options, "title", "systemTitle", "system_title", "systemName", "name")


def build_system_description(system_package: dict, options: dict[str, str]) -> str:
	description = first_json_value(system_package, {"description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription"})
	if description:
		return description
	return optional_value(options, "description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription")


def report_title_for_system(system_title: str) -> str:
	return f"{safe_text(system_title).strip() or 'Unknown'} {REPORT_TITLE_SUFFIX}"


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, hardware_data, patch_data, checklist_data) -> dict[str, object]:
	system_title = build_system_title(system_package, options)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"ghost_asset_analysis": build_ghost_asset_analysis(hardware_data, patch_data, checklist_data, options),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"source_script": Path(__file__).name,
	}


def truncated_text(value, max_length: int = 120) -> str:
	text = display_value(safe_text(value))
	if len(text) <= max_length:
		return text
	return text[: max_length - 3].rstrip() + "..."


def pdf_table(rows: list[list[str]], column_widths: list[int], styles, table_style):
	from reportlab.platypus import Paragraph, Table  # pyright: ignore[reportMissingModuleSource]

	table = Table(
		[[Paragraph(html.escape(safe_text(cell)), styles["BodyText"]) for cell in row] for row in rows],
		colWidths=column_widths,
		style=table_style,
		repeatRows=1,
	)
	table.hAlign = "LEFT"
	return table


def build_evidence_table(rows: list[dict[str, str]], styles, table_style):
	from reportlab.platypus import Spacer  # pyright: ignore[reportMissingModuleSource]

	table_rows = [["Asset", "IP Address(es)", "Patch Exists", "Checklist Exists", "Hardware Exists", "Classification"]]
	if rows:
		for row in rows:
			table_rows.append([row["asset"], row["ip_addresses"], row["patch"], row["checklist"], row["hardware"], row["classification"]])
	else:
		table_rows.append(["No correlated hardware, checklist, or patch evidence was found.", "", "", "", "", ""])
	return [
		pdf_table(table_rows, [105, 95, 75, 75, 65, 105], styles, table_style),
		Spacer(1, 14),
	]


def build_fallback_analysis_lines(analysis: dict[str, object]) -> list[str]:
	lines = [
		"Ghost Asset Analysis",
		"",
	]
	evidence_rows = analysis.get("evidence_rows", [])
	if isinstance(evidence_rows, list) and evidence_rows:
		for row in evidence_rows:
			lines.append(truncated_text(f"{row['asset']} | Patch Exists {row['patch']} | Checklist Exists {row['checklist']} | Hardware Exists {row['hardware']} | {row['classification']}", 88))
	else:
		lines.append("No correlated hardware, checklist, or patch evidence was found.")
	return lines


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, object]) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	left_title_style = styles["Title"].clone("LeftTitle")
	left_title_style.alignment = 0
	left_title_style.leftIndent = 0
	left_title_style.firstLineIndent = 0
	left_heading_style = styles["Heading2"].clone("LeftHeading2")
	left_heading_style.alignment = 0
	left_heading_style.leftIndent = 0
	left_heading_style.firstLineIndent = 0
	styles.add(left_heading_style)
	table_style = TableStyle(
		[
			("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
			("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
			("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
			("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
			("VALIGN", (0, 0), (-1, -1), "TOP"),
			("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F6F8FA")]),
		]
	)
	analysis = report_data["ghost_asset_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}
	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		leftMargin=36,
		rightMargin=36,
		title=safe_text(report_data["report_title"]),
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(html.escape(safe_text(report_data["report_title"])), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(safe_text(report_data['generated_at']))}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(safe_text(report_data['system_title']))}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(safe_text(report_data['system_key']))}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(safe_text(report_data['system_description']))}", styles["Normal"]),
		PageBreak(),
		Paragraph("Ghost Asset Analysis", left_title_style),
		Spacer(1, 14),
	]
	story.extend(build_evidence_table(analysis.get("evidence_rows", []), styles, table_style))
	document.build(story)
	return True


def escape_pdf_text(value: str) -> str:
	return safe_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 14) -> str:
	stream_lines = ["BT", f"/F1 {font_size} Tf", "72 720 Td"]
	for index, line in enumerate(lines):
		if index:
			stream_lines.append("0 -24 Td")
		stream_lines.append(f"({escape_pdf_text(line)}) Tj")
	stream_lines.append("ET")
	return "\n".join(stream_lines)


def write_minimal_pdf(output_path: Path, report_data: dict[str, object]) -> None:
	analysis = report_data["ghost_asset_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}
	analysis_lines = build_fallback_analysis_lines(analysis)
	analysis_page_chunks = [analysis_lines[index:index + 30] for index in range(0, len(analysis_lines), 30)] or [["Ghost Asset Analysis", "", "No correlated asset data found."]]
	page_streams = [
		make_text_page(
			[
				safe_text(report_data["report_title"]),
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"System Title: {report_data['system_title']}",
				f"System Key: {report_data['system_key']}",
				f"Description: {report_data['system_description']}",
			],
			font_size=14,
		),
	]
	page_streams.extend(make_text_page(chunk, font_size=12) for chunk in analysis_page_chunks)
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


def write_pdf(output_path: Path, report_data: dict[str, object]) -> str:
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
	base_arguments = sys.argv[1:5]
	options = parse_optional_arguments(sys.argv[5:])
	system_package = parse_json_value_from_output(call_system_package_json_script(base_arguments))
	hardware_data = parse_json_value_from_output(call_hardware_json_script(base_arguments))
	patch_data = parse_json_value_from_output(call_patch_data_json_script(base_arguments))
	checklist_data = parse_json_value_from_output(call_checklist_json_script(base_arguments, options))
	report_data = build_report_data(system_key, options, system_package, hardware_data, patch_data, checklist_data)
	output_filename = f"OpenRMFPro-Ghost-Asset-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
