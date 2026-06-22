#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional Configuration Overlap PDF
# Description: Creates a Configuration Overlap PDF cover report for a system key.
# ============================================================

import html
import ipaddress
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE_SUFFIX = "Configuration Overlap"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
HARDWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_hardware_json.py"
SOFTWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_software_json.py"
PPSM_SCRIPT_NAME = "get_systempackage_by_systemkey_ppsm_json.py"
PATCH_SCORE_DEVICES_SCRIPT_NAME = "get_systempackage_by_systemkey_patchscore_devices_json.py"
DEFAULT_BASELINE_SUPPORT_PERCENT = 80.0
DEFAULT_JACCARD_THRESHOLD = 0.75
DEFAULT_TOP_OUTLIERS = 15
DEFAULT_TOP_BASELINE_FEATURES = 20
DEFAULT_COVER_HARDWARE_LIMIT = 12
TARGET_ANOMALY_OPERATING_SYSTEM = "Microsoft Windows 10 Enterprise Build 19045"
DEFAULT_TARGET_ANOMALY_LIMIT = 40

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
OS_KEYS = [
	"operatingSystem",
	"operatingSystemName",
	"os",
	"osName",
	"platform",
]
PATCH_TOTAL_KEYS = [
	"totalOpen",
	"totalPatchOpen",
	"totalVulnerabilityOpen",
	"vulnerabilitiesOpen",
	"openVulnerabilities",
	"openPatchCount",
	"patchCount",
	"totalPatchCount",
	"totalFindings",
	"vulnerabilityCount",
	"openCount",
]
PATCH_SEVERITY_KEYS = [
	"totalCriticalOpen",
	"totalHighOpen",
	"totalMediumOpen",
	"totalLowOpen",
	"totalPatchCriticalOpen",
	"totalPatchHighOpen",
	"totalPatchMediumOpen",
	"totalPatchLowOpen",
	"criticalOpen",
	"highOpen",
	"mediumOpen",
	"lowOpen",
	"openCritical",
	"openHigh",
	"openMedium",
	"openLow",
]


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 configuration-overlap/"
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


def call_hardware_json_script(arguments: list[str]) -> str:
	return call_json_script("hardware", HARDWARE_SCRIPT_NAME, arguments, "hardware")


def call_software_json_script(arguments: list[str]) -> str:
	return call_json_script("software", SOFTWARE_SCRIPT_NAME, [*arguments, "groupby=false"], "software")


def call_ppsm_json_script(arguments: list[str]) -> str:
	return call_json_script("ports-protocols-services", PPSM_SCRIPT_NAME, [*arguments, "groupby=false"], "PPSM")


def call_patch_score_devices_json_script(arguments: list[str]) -> str:
	return call_json_script("patch-vulnerability", PATCH_SCORE_DEVICES_SCRIPT_NAME, arguments, "patch score devices")


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


def optional_float(options: dict[str, str], key: str, default_value: float) -> float:
	try:
		return float(options.get(key, default_value))
	except (TypeError, ValueError):
		return default_value


def optional_int(options: dict[str, str], key: str, default_value: int) -> int:
	try:
		return int(float(options.get(key, default_value)))
	except (TypeError, ValueError):
		return default_value


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


def normalized_value(value: str) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip()).lower()


def display_value(value: str) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip())


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


def normalize_hostname(value: str) -> str:
	return normalized_value(value)


def looks_like_software_record(value: dict) -> bool:
	return bool(
		{
			"softwareName",
			"softwareVersion",
			"applicationName",
			"productName",
			"productVersion",
			"vendor",
			"publisher",
		}.intersection(value.keys())
	)


def looks_like_ppsm_record(value: dict) -> bool:
	return bool(
		{
			"lowPortNumber",
			"highPortNumber",
			"portNumber",
			"port",
			"protocol",
			"protocolName",
			"serviceName",
			"svcName",
			"svc_name",
		}.intersection(value.keys())
	)


def looks_like_hardware_record(value: dict) -> bool:
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS).intersection(value.keys())
		or {"hardware", "serialNumber", "assetTag", "macAddress", "operatingSystem"}.intersection(value.keys())
	)


def looks_like_patch_score_device_record(value: dict) -> bool:
	return bool(
		set(HOSTNAME_KEYS + IP_KEYS + OS_KEYS + PATCH_TOTAL_KEYS + PATCH_SEVERITY_KEYS).intersection(value.keys())
		or {"patchScore", "patchscore", "vulnerabilities", "device", "asset"}.intersection(value.keys())
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


def software_records(software_data) -> list[dict]:
	return find_record_list(
		software_data,
		["records", "items", "data", "results", "software", "softwares", "applications", "assets"],
		looks_like_software_record,
	)


def hardware_records(hardware_data) -> list[dict]:
	return find_record_list(
		hardware_data,
		["records", "items", "data", "results", "hardware", "assets", "devices"],
		looks_like_hardware_record,
	)


def ppsm_records(ppsm_data) -> list[dict]:
	return find_record_list(
		ppsm_data,
		["records", "items", "data", "results", "ppsm", "pps", "portsProtocolsServices", "ports"],
		looks_like_ppsm_record,
	)


def patch_score_device_records(patch_score_devices_data) -> list[dict]:
	return find_record_list(
		patch_score_devices_data,
		["records", "items", "data", "results", "patchScoreDevices", "patchscoreDevices", "patchScores", "devices", "assets"],
		looks_like_patch_score_device_record,
	)


def record_hostname(record: dict) -> str:
	direct_value = first_record_value(record, HOSTNAME_KEYS)
	if direct_value:
		return normalize_hostname(direct_value)
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
	return normalize_hostname(nested_value) if nested_value else ""


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


def record_operating_system(record: dict) -> str:
	direct_value = first_record_value(record, OS_KEYS)
	if direct_value:
		return display_value(direct_value)
	nested_value = first_nested_record_value(
		record,
		[
			["asset", "operatingSystem"],
			["asset", "operatingSystemName"],
			["asset", "os"],
			["device", "operatingSystem"],
			["device", "operatingSystemName"],
			["device", "os"],
			["host", "operatingSystem"],
			["host", "os"],
			["operatingSystem", "name"],
			["os", "name"],
		],
	)
	return display_value(nested_value) if nested_value else "Unknown"


def patch_open_count(record: dict):
	total_count = first_numeric_json_value(record, set(PATCH_TOTAL_KEYS))
	if total_count is not None:
		return total_count
	severity_counts = [first_numeric_json_value(record, {key}) for key in PATCH_SEVERITY_KEYS]
	severity_counts = [count for count in severity_counts if count is not None]
	if severity_counts:
		return sum(severity_counts)
	return None


def software_feature(record: dict) -> str:
	name = display_value(
		first_record_value(record, ["softwareName", "software", "applicationName", "appName", "productName", "name", "title"])
	)
	version = display_value(first_record_value(record, ["version", "softwareVersion", "productVersion", "release"])).lower()
	if not name:
		return ""
	return f"software:{name.lower()}:{version}" if version else f"software:{name.lower()}"


def ppsm_feature(record: dict) -> str:
	protocol = normalized_value(first_record_value(record, ["protocol", "protocolName", "proto", "ipProtocol"])) or "unknown-protocol"
	low_port = display_value(first_record_value(record, ["lowPortNumber", "portNumber", "lowPort", "fromPort", "port"]))
	high_port = display_value(first_record_value(record, ["highPortNumber", "highPort", "toPort"]))
	service = normalized_value(first_record_value(record, ["serviceName", "svcName", "svc_name", "service", "name"]))
	if not low_port and not high_port and not service:
		return ""
	port = low_port or high_port or "unknown-port"
	if high_port and high_port != low_port:
		port = f"{port}-{high_port}"
	return f"port:{protocol}:{port}:{service or 'unknown-service'}"


def feature_display_name(feature: str) -> str:
	parts = feature.split(":")
	if not parts:
		return feature
	if parts[0] == "software":
		if len(parts) > 2 and parts[2]:
			return f"Software: {parts[1]} ({parts[2]})"
		return f"Software: {parts[1]}"
	if parts[0] == "port" and len(parts) >= 4:
		return f"Port: {parts[1].upper()} {parts[2]} {parts[3]}"
	return feature


def add_feature(features_by_host: dict[str, set[str]], skipped_records: list[str], record: dict, feature: str, record_type: str) -> None:
	hostname = record_hostname(record)
	if not hostname:
		skipped_records.append(f"{record_type}: missing hostname")
		return
	if not feature:
		skipped_records.append(f"{record_type}: missing comparable feature for {hostname}")
		return
	features_by_host[hostname].add(feature)


def jaccard_similarity(left_features: set[str], right_features: set[str]) -> float:
	union = left_features | right_features
	if not union:
		return 1.0
	return len(left_features & right_features) / len(union)


def build_host_profiles(software_data, ppsm_data) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]], list[str], int, int]:
	software_by_host = defaultdict(set)
	ppsm_by_host = defaultdict(set)
	skipped_records = []
	software_record_list = software_records(software_data)
	ppsm_record_list = ppsm_records(ppsm_data)

	for record in software_record_list:
		add_feature(software_by_host, skipped_records, record, software_feature(record), "software")
	for record in ppsm_record_list:
		add_feature(ppsm_by_host, skipped_records, record, ppsm_feature(record), "ppsm")

	all_hosts = sorted(set(software_by_host) | set(ppsm_by_host))
	profiles = {hostname: set(software_by_host[hostname]) | set(ppsm_by_host[hostname]) for hostname in all_hosts}
	return profiles, dict(software_by_host), dict(ppsm_by_host), skipped_records, len(software_record_list), len(ppsm_record_list)


def build_patch_score_summary(patch_score_devices_data) -> dict[str, object]:
	patch_by_host = {}
	os_groups = defaultdict(list)
	skipped_records = []
	records = patch_score_device_records(patch_score_devices_data)
	for index, record in enumerate(records):
		hostname = record_hostname(record)
		if not hostname:
			skipped_records.append("patch: missing hostname")
			continue
		patch_count = patch_open_count(record)
		operating_system = record_operating_system(record)
		row = {
			"hostname": hostname,
			"display_name": record_display_name(record),
			"operating_system": operating_system,
			"patch_count": patch_count,
			"record_index": index,
		}
		patch_by_host[hostname] = row
		if patch_count is not None and normalized_value(operating_system) not in ("", "unknown"):
			os_groups[normalized_value(operating_system)].append(row)

	anomaly_rows = []
	for operating_system_key, rows in os_groups.items():
		counts = [row["patch_count"] for row in rows if row["patch_count"] is not None]
		if len(set(counts)) <= 1:
			continue
		expected_count = Counter(counts).most_common(1)[0][0]
		for row in rows:
			if row["patch_count"] == expected_count:
				continue
			row["patch_anomaly"] = True
			row["patch_expected_count"] = expected_count
			anomaly_rows.append(
				{
					"hostname": row["hostname"],
					"operating_system": row["operating_system"],
					"patch_count": str(row["patch_count"]),
					"expected_patch_count": str(expected_count),
				}
			)

	return {
		"patch_by_host": patch_by_host,
		"patch_record_count": len(records),
		"patch_anomaly_count": len(anomaly_rows),
		"patch_anomaly_rows": sorted(anomaly_rows, key=lambda row: (normalized_value(row["operating_system"]), row["hostname"])),
		"patch_skipped_record_count": len(skipped_records),
		"patch_skipped_record_examples": skipped_records[:5],
	}


def patch_display_value(patch_row) -> str:
	if not isinstance(patch_row, dict):
		return "N/A"
	patch_count = patch_row.get("patch_count")
	patch_text = "Unknown" if patch_count is None else str(patch_count)
	if patch_row.get("patch_anomaly"):
		return f"{patch_text} (Anomaly: {patch_row.get('operating_system', 'Unknown')} expected {patch_row.get('patch_expected_count', 'Unknown')})"
	return patch_text


def add_operating_systems_from_records(os_by_host: dict[str, str], records: list[dict]) -> None:
	for record in records:
		hostname = record_hostname(record)
		if not hostname or hostname in os_by_host:
			continue
		operating_system = record_operating_system(record)
		if normalized_value(operating_system) not in ("", "unknown"):
			os_by_host[hostname] = operating_system


def build_operating_systems_by_host(hardware_data, software_data, ppsm_data, patch_by_host: dict[str, dict]) -> dict[str, str]:
	os_by_host = {}
	add_operating_systems_from_records(os_by_host, hardware_records(hardware_data))
	for hostname, patch_row in patch_by_host.items():
		if hostname in os_by_host or not isinstance(patch_row, dict):
			continue
		operating_system = safe_text(patch_row.get("operating_system", "Unknown"))
		if normalized_value(operating_system) not in ("", "unknown"):
			os_by_host[hostname] = operating_system
	add_operating_systems_from_records(os_by_host, software_records(software_data))
	add_operating_systems_from_records(os_by_host, ppsm_records(ppsm_data))
	return os_by_host


def count_distribution_text(values: list[object]) -> str:
	if not values:
		return "N/A"
	texts = ["Unknown" if value is None else safe_text(value) for value in values]
	counts = Counter(texts)
	if len(counts) == 1:
		return texts[0]
	return "Mixed: " + ", ".join(f"{value} ({count} hosts)" for value, count in sorted(counts.items(), key=lambda item: (item[0] == "Unknown", item[0])))


def build_operating_system_group_rows(hostnames: list[str], os_by_host: dict[str, str], software_by_host: dict[str, set[str]], ppsm_by_host: dict[str, set[str]], patch_by_host: dict[str, dict]) -> list[dict[str, str]]:
	groups = defaultdict(list)
	for hostname in hostnames:
		operating_system = os_by_host.get(hostname, "Unknown")
		groups[display_value(operating_system) or "Unknown"].append(hostname)

	rows = []
	for operating_system, grouped_hosts in sorted(groups.items(), key=lambda item: (normalized_value(item[0]) == "unknown", normalized_value(item[0]))):
		sorted_hosts = sorted(grouped_hosts)
		software_counts = [len(software_by_host.get(hostname, set())) for hostname in sorted_hosts]
		ppsm_counts = [len(ppsm_by_host.get(hostname, set())) for hostname in sorted_hosts]
		patch_counts = [patch_by_host[hostname].get("patch_count") if isinstance(patch_by_host.get(hostname), dict) else "N/A" for hostname in sorted_hosts]
		rows.append(
			{
				"operating_system": operating_system,
				"host_count": str(len(sorted_hosts)),
				"hostnames": ", ".join(sorted_hosts),
				"software_count": count_distribution_text(software_counts),
				"ppsm_count": count_distribution_text(ppsm_counts),
				"patch_count": count_distribution_text(patch_counts),
			}
		)
	return rows


def closest_reference_features(hostname: str, reference_hosts: list[str], features_by_host: dict[str, set[str]]) -> tuple[str, set[str]]:
	host_features = features_by_host.get(hostname, set())
	if not reference_hosts:
		return "", set()
	reference_hostname = max(
		reference_hosts,
		key=lambda reference_host: (
			jaccard_similarity(host_features, features_by_host.get(reference_host, set())),
			normalize_hostname(reference_host),
		),
	)
	return reference_hostname, features_by_host.get(reference_hostname, set())


def expected_count_for_hosts(counts_by_host: dict[str, int]) -> int:
	count_frequencies = Counter(counts_by_host.values())
	return sorted(count_frequencies.items(), key=lambda item: (-item[1], item[0]))[0][0]


def feature_difference_reason(hostname: str, reference_hosts: list[str], features_by_host: dict[str, set[str]], label: str, expected_count: int, actual_count: int, max_features: int = 3) -> str:
	_, reference_features = closest_reference_features(hostname, reference_hosts, features_by_host)
	host_features = features_by_host.get(hostname, set())
	differences = []
	extra_features = sorted(host_features - reference_features, key=feature_display_name)
	missing_features = sorted(reference_features - host_features, key=feature_display_name)
	feature_limit = max(1, min(max_features, abs(actual_count - expected_count)))
	if actual_count > expected_count and extra_features:
		differences.append(f"{label} extra " + ", ".join(feature_display_name(feature) for feature in extra_features[:feature_limit]))
	elif actual_count < expected_count and missing_features:
		differences.append(f"{label} missing " + ", ".join(feature_display_name(feature) for feature in missing_features[:feature_limit]))
	else:
		if extra_features:
			differences.append(f"{label} extra " + ", ".join(feature_display_name(feature) for feature in extra_features[:feature_limit]))
		if missing_features:
			differences.append(f"{label} missing " + ", ".join(feature_display_name(feature) for feature in missing_features[:feature_limit]))
	return "; ".join(differences) if differences else f"{label} count differs, but no comparable missing/extra details were found"


def anomaly_count_text(label: str, count: int, expected_count: int) -> str:
	if count == expected_count:
		return f"{label} {count}"
	return f"{label} {count} (expected {expected_count})"


def build_count_anomaly_bullets(grouped_hosts: list[str], software_by_host: dict[str, set[str]], ppsm_by_host: dict[str, set[str]]) -> list[str]:
	if len(grouped_hosts) < 2:
		return []
	ppsm_counts = {hostname: len(ppsm_by_host.get(hostname, set())) for hostname in grouped_hosts}
	software_counts = {hostname: len(software_by_host.get(hostname, set())) for hostname in grouped_hosts}
	expected_ppsm_count = expected_count_for_hosts(ppsm_counts)
	expected_software_count = expected_count_for_hosts(software_counts)
	ppsm_reference_hosts = sorted(hostname for hostname, ppsm_count in ppsm_counts.items() if ppsm_count == expected_ppsm_count)
	software_reference_hosts = sorted(hostname for hostname, software_count in software_counts.items() if software_count == expected_software_count)
	ppsm_anomaly_hosts = sorted(
		hostname
		for hostname in grouped_hosts
		if ppsm_counts[hostname] != expected_ppsm_count
	)
	software_anomaly_hosts = sorted(
		hostname
		for hostname in grouped_hosts
		if software_counts[hostname] != expected_software_count
	)
	if not ppsm_anomaly_hosts and not software_anomaly_hosts:
		return []
	bullets = []
	for hostname in ppsm_anomaly_hosts:
		bullet_prefix = (
			f"{hostname}: Software {software_counts[hostname]}, "
			f"{anomaly_count_text('PPS', ppsm_counts[hostname], expected_ppsm_count)}"
		)
		bullets.append(
			f"{bullet_prefix} — {feature_difference_reason(hostname, ppsm_reference_hosts, ppsm_by_host, 'PPS', expected_ppsm_count, ppsm_counts[hostname])}."
		)
	for hostname in software_anomaly_hosts:
		bullet_prefix = (
			f"{hostname}: {anomaly_count_text('Software', software_counts[hostname], expected_software_count)}, "
			f"PPS {ppsm_counts[hostname]}"
		)
		bullets.append(
			f"{bullet_prefix} — {feature_difference_reason(hostname, software_reference_hosts, software_by_host, 'Software', expected_software_count, software_counts[hostname], abs(software_counts[hostname] - expected_software_count))}."
		)
	return bullets


def build_operating_system_anomalies(hostnames: list[str], os_by_host: dict[str, str], software_by_host: dict[str, set[str]], ppsm_by_host: dict[str, set[str]], options: dict[str, str]) -> dict[str, list[str]]:
	anomaly_limit = max(1, optional_int(options, "targetAnomalyLimit", DEFAULT_TARGET_ANOMALY_LIMIT))
	groups = defaultdict(list)
	for hostname in hostnames:
		operating_system = display_value(os_by_host.get(hostname, "Unknown")) or "Unknown"
		groups[operating_system].append(hostname)
	anomalies = {}
	for operating_system, grouped_hosts in sorted(groups.items(), key=lambda item: (normalized_value(item[0]) == "unknown", normalized_value(item[0]))):
		bullets = build_count_anomaly_bullets(sorted(grouped_hosts), software_by_host, ppsm_by_host)
		if bullets:
			anomalies[operating_system] = bullets[:anomaly_limit]
	return anomalies


def build_target_operating_system_anomalies(hostnames: list[str], os_by_host: dict[str, str], software_by_host: dict[str, set[str]], ppsm_by_host: dict[str, set[str]], options: dict[str, str]) -> dict[str, list[str]]:
	target_operating_system = optional_value(options, "anomalyOperatingSystem", "targetAnomalyOperatingSystem")
	if target_operating_system == "Unknown":
		return build_operating_system_anomalies(hostnames, os_by_host, software_by_host, ppsm_by_host, options)
	target_key = normalized_value(target_operating_system)
	target_hosts = sorted(hostname for hostname in hostnames if normalized_value(os_by_host.get(hostname, "Unknown")) == target_key)
	if not target_hosts:
		return {}
	bullets = build_count_anomaly_bullets(target_hosts, software_by_host, ppsm_by_host)
	anomaly_limit = max(1, optional_int(options, "targetAnomalyLimit", DEFAULT_TARGET_ANOMALY_LIMIT))
	return {target_operating_system: bullets[:anomaly_limit]}


def build_similarity_rows(profiles: dict[str, set[str]]) -> tuple[list[dict[str, str]], dict[str, float]]:
	if len(profiles) < 2:
		return [], {hostname: 1.0 for hostname in profiles}

	scores_by_host = {hostname: [] for hostname in profiles}
	for left_host, right_host in combinations(sorted(profiles), 2):
		score = jaccard_similarity(profiles[left_host], profiles[right_host])
		scores_by_host[left_host].append(score)
		scores_by_host[right_host].append(score)

	average_scores = {
		hostname: (sum(scores) / len(scores) if scores else 1.0)
		for hostname, scores in scores_by_host.items()
	}
	rows = [
		{
			"hostname": hostname,
			"average_overlap": f"{average_scores[hostname] * 100:.1f}%",
			"feature_count": str(len(profiles[hostname])),
		}
		for hostname in sorted(profiles, key=lambda host: (average_scores[host], host))
	]
	return rows, average_scores


def build_configuration_overlap_analysis(hardware_data, software_data, ppsm_data, patch_score_devices_data, options: dict[str, str]) -> dict[str, object]:
	baseline_support_percent = max(0.0, min(100.0, optional_float(options, "baselineSupportPercent", DEFAULT_BASELINE_SUPPORT_PERCENT)))
	jaccard_threshold = max(0.0, min(1.0, optional_float(options, "jaccardThreshold", DEFAULT_JACCARD_THRESHOLD)))
	top_outliers = max(1, optional_int(options, "topOutliers", DEFAULT_TOP_OUTLIERS))
	top_baseline_features = max(1, optional_int(options, "topBaselineFeatures", DEFAULT_TOP_BASELINE_FEATURES))
	profiles, software_by_host, ppsm_by_host, skipped_records, software_record_count, ppsm_record_count = build_host_profiles(software_data, ppsm_data)
	patch_summary = build_patch_score_summary(patch_score_devices_data)
	patch_by_host = patch_summary["patch_by_host"] if isinstance(patch_summary.get("patch_by_host"), dict) else {}
	os_by_host = build_operating_systems_by_host(hardware_data, software_data, ppsm_data, patch_by_host)
	asset_count = len(profiles)
	feature_support = Counter(feature for features in profiles.values() for feature in features)
	baseline_minimum_count = max(1, int((asset_count * baseline_support_percent + 99.999) // 100)) if asset_count else 0
	baseline_features = sorted(
		[feature for feature, count in feature_support.items() if count >= baseline_minimum_count],
		key=lambda feature: (-feature_support[feature], feature),
	)
	similarity_rows, average_scores = build_similarity_rows(profiles)

	outlier_rows = []
	outlier_hosts = set()
	for hostname, features in profiles.items():
		missing_baseline = [feature for feature in baseline_features if feature not in features]
		unique_features = sorted([feature for feature in features if feature_support[feature] == 1])
		average_overlap = average_scores.get(hostname, 1.0)
		if average_overlap < jaccard_threshold or missing_baseline or unique_features:
			outlier_hosts.add(hostname)
			outlier_rows.append(
				{
					"hostname": hostname,
					"average_overlap": f"{average_overlap * 100:.1f}%",
					"software_count": str(len(software_by_host.get(hostname, set()))),
					"ppsm_count": str(len(ppsm_by_host.get(hostname, set()))),
					"missing_baseline_count": str(len(missing_baseline)),
					"unique_feature_count": str(len(unique_features)),
					"missing_baseline": ", ".join(feature_display_name(feature) for feature in missing_baseline[:5]) or "None",
					"unique_features": ", ".join(feature_display_name(feature) for feature in unique_features[:5]) or "None",
				}
			)
	outlier_rows.sort(key=lambda row: (float(row["average_overlap"].rstrip("%")), -int(row["unique_feature_count"]), row["hostname"]))
	baseline_rows = [
		{
			"feature": feature_display_name(feature),
			"support": f"{feature_support[feature]}/{asset_count}",
			"support_percent": f"{(feature_support[feature] / asset_count * 100) if asset_count else 0:.1f}%",
		}
		for feature in baseline_features[:top_baseline_features]
	]
	all_row_hosts = sorted(set(profiles) | set(patch_by_host), key=lambda host: (average_scores.get(host, 1.0), host))
	os_group_rows = build_operating_system_group_rows(all_row_hosts, os_by_host, software_by_host, ppsm_by_host, patch_by_host)
	target_operating_system_anomalies = build_target_operating_system_anomalies(all_row_hosts, os_by_host, software_by_host, ppsm_by_host, options)
	host_rows = [
		{
			"hostname": hostname,
			"operating_system": os_by_host.get(hostname, "Unknown"),
			"average_overlap": f"{average_scores.get(hostname, 1.0) * 100:.1f}%" if hostname in profiles else "N/A",
			"software_count": str(len(software_by_host.get(hostname, set()))),
			"ppsm_count": str(len(ppsm_by_host.get(hostname, set()))),
			"patch_count": patch_display_value(patch_by_host.get(hostname)),
			"feature_count": str(len(profiles.get(hostname, set()))),
			"outlier": "Yes" if hostname in outlier_hosts else "No",
		}
		for hostname in all_row_hosts
	]
	return {
		"asset_count": asset_count,
		"software_record_count": software_record_count,
		"ppsm_record_count": ppsm_record_count,
		"patch_record_count": patch_summary["patch_record_count"],
		"patch_anomaly_count": patch_summary["patch_anomaly_count"],
		"patch_anomaly_rows": patch_summary["patch_anomaly_rows"],
		"software_feature_count": len({feature for features in software_by_host.values() for feature in features}),
		"ppsm_feature_count": len({feature for features in ppsm_by_host.values() for feature in features}),
		"total_feature_count": len(feature_support),
		"baseline_feature_count": len(baseline_features),
		"baseline_support_percent": f"{baseline_support_percent:.1f}%",
		"baseline_minimum_count": baseline_minimum_count,
		"jaccard_threshold": f"{jaccard_threshold * 100:.1f}%",
		"outlier_count": len(outlier_rows),
		"baseline_rows": baseline_rows,
		"outlier_rows": outlier_rows[:top_outliers],
		"os_group_rows": os_group_rows,
		"target_operating_system_anomalies": target_operating_system_anomalies,
		"host_rows": host_rows,
		"similarity_rows": similarity_rows[:top_outliers],
		"skipped_record_count": len(skipped_records) + int(patch_summary["patch_skipped_record_count"]),
		"skipped_record_examples": (skipped_records + patch_summary["patch_skipped_record_examples"])[:5],
	}


def build_system_title(system_package: dict, options: dict[str, str]) -> str:
	title = first_json_value(
		system_package,
		{"title", "systemTitle", "system_title", "systemName", "name"},
	)
	if title:
		return title
	return optional_value(options, "title", "systemTitle", "system_title", "systemName", "name")


def build_system_description(system_package: dict, options: dict[str, str]) -> str:
	description = first_json_value(
		system_package,
		{"description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription"},
	)
	if description:
		return description
	return optional_value(options, "description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription")


def report_title_for_system(system_title: str) -> str:
	return f"{safe_text(system_title).strip() or 'Unknown'} {REPORT_TITLE_SUFFIX}"


def build_framework_levels(package_framework: dict) -> list[dict[str, str]]:
	framework_levels = package_framework.get("frameworkLevels", [])
	if not isinstance(framework_levels, list):
		return []

	levels = []
	for level in framework_levels:
		if not isinstance(level, dict):
			continue
		category = safe_text(level.get("levelCategory")).strip()
		value = safe_text(level.get("levelValue")).strip()
		if category or value:
			levels.append({"category": category, "value": value})
	return levels


def format_framework_level(level: dict[str, str]) -> str:
	category = safe_text(level.get("category")).strip()
	value = safe_text(level.get("value")).strip()
	if category and value:
		return f"{category}: {value}"
	return category or value or "Unknown"


def build_hardware_device_summary(hardware_data, options: dict[str, str]) -> dict[str, object]:
	records = hardware_records(hardware_data)
	cover_limit = max(1, optional_int(options, "coverHardwareLimit", DEFAULT_COVER_HARDWARE_LIMIT))
	devices = []
	seen_keys = set()
	for index, record in enumerate(records):
		identity_key = record_identity_key(record) or f"record:{index}"
		if identity_key in seen_keys:
			continue
		seen_keys.add(identity_key)
		devices.append(
			{
				"asset": record_display_name(record),
			}
		)
	devices.sort(key=lambda row: normalized_value(row["asset"]))
	return {
		"total_count": len(devices),
		"display_count": min(len(devices), cover_limit),
		"devices": devices[:cover_limit],
	}


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, hardware_data, software_data, ppsm_data, patch_score_devices_data) -> dict[str, object]:
	system_title = build_system_title(system_package, options)
	package_framework = system_package.get("packageFramework", {})
	if not isinstance(package_framework, dict):
		package_framework = {}
	return {
		"system_key": system_key,
		"title": safe_text(system_package.get("title")).strip() or system_title,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"number_of_checklists": safe_text(system_package.get("numberOfChecklists")).strip() or "0",
		"framework_title": safe_text(package_framework.get("frameworkTitle")).strip() or "Unknown",
		"framework_acronym": safe_text(package_framework.get("frameworkAcronym")).strip() or "Unknown",
		"framework_version": safe_text(package_framework.get("frameworkVersion")).strip() or "Unknown",
		"framework_levels": build_framework_levels(package_framework),
		"hardware_device_summary": build_hardware_device_summary(hardware_data, options),
		"configuration_overlap_analysis": build_configuration_overlap_analysis(hardware_data, software_data, ppsm_data, patch_score_devices_data, options),
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


def build_cover_hardware_section(summary: dict[str, object], styles, table_style):
	from reportlab.platypus import Paragraph, Spacer  # pyright: ignore[reportMissingModuleSource]

	total_count = int(summary.get("total_count", 0) or 0)
	display_count = int(summary.get("display_count", 0) or 0)
	devices = summary.get("devices", [])
	table_rows = [["Hardware Device"]]
	if isinstance(devices, list) and devices:
		for device in devices:
			if isinstance(device, dict):
				table_rows.append([safe_text(device.get("asset", "Unknown"))])
	else:
		table_rows.append(["No hardware devices were found."])
	section = [
		Spacer(1, 12),
		Paragraph("Total Number of Hardware Devices", styles["LeftHeading2"]),
		Spacer(1, 6),
		pdf_table(table_rows, [300], styles, table_style),
	]
	if total_count > display_count:
		section.extend(
			[
				Spacer(1, 6),
				Paragraph(f"Showing first {display_count} of {total_count} hardware devices.", styles["Normal"]),
			]
		)
	return section


def build_overlap_summary_lines(analysis: dict[str, object]) -> list[str]:
	return [
		f"Assets Matched by Hostname: {analysis['asset_count']}",
		f"Software Records Loaded: {analysis['software_record_count']}",
		f"Ports/Protocols/Services Records Loaded: {analysis['ppsm_record_count']}",
		f"Patch Score Device Records Loaded: {analysis['patch_record_count']}",
		f"Software Features: {analysis['software_feature_count']}",
		f"Ports/Protocols/Services Features: {analysis['ppsm_feature_count']}",
		f"Total Comparable Features: {analysis['total_feature_count']}",
		f"Baseline Support Threshold: {analysis['baseline_support_percent']} ({analysis['baseline_minimum_count']} assets minimum)",
		f"Jaccard Outlier Threshold: {analysis['jaccard_threshold']}",
		f"Baseline Features Discovered: {analysis['baseline_feature_count']}",
		f"Potential Drift/Outlier Assets: {analysis['outlier_count']}",
		f"Patch OS Anomalies: {analysis['patch_anomaly_count']}",
		f"Skipped Records: {analysis['skipped_record_count']}",
	]


def host_rows_by_operating_system(host_rows: object) -> list[tuple[str, list[dict]]]:
	if not isinstance(host_rows, list):
		return []
	groups = defaultdict(list)
	for row in host_rows:
		if not isinstance(row, dict):
			continue
		operating_system = display_value(row.get("operating_system", "Unknown")) or "Unknown"
		groups[operating_system].append(row)
	return [
		(
			operating_system,
			sorted(rows, key=lambda row: normalize_hostname(safe_text(row.get("hostname", "")))),
		)
		for operating_system, rows in sorted(groups.items(), key=lambda item: (normalized_value(item[0]) == "unknown", normalized_value(item[0])))
	]


def anomaly_bullets_for_operating_system(analysis: dict[str, object], operating_system: str) -> list[str]:
	anomalies = analysis.get("target_operating_system_anomalies", {})
	if not isinstance(anomalies, dict):
		return []
	operating_system_key = normalized_value(operating_system)
	for anomaly_operating_system, bullets in anomalies.items():
		if normalized_value(anomaly_operating_system) != operating_system_key or not isinstance(bullets, list):
			continue
		return [safe_text(bullet) for bullet in bullets if safe_text(bullet).strip()]
	return []


def build_fallback_overlap_lines(analysis: dict[str, object]) -> list[str]:
	lines = ["Configuration Overlap Analysis"]
	os_host_groups = host_rows_by_operating_system(analysis.get("host_rows", []))
	if os_host_groups:
		for operating_system, rows in os_host_groups:
			lines.extend(["", operating_system])
			for row in rows:
				lines.append(
					truncated_text(
						f"{row['hostname']}: software {row['software_count']}, PPS {row['ppsm_count']}, patch {row['patch_count']}, {row['average_overlap']} overlap",
						88,
					)
				)
			anomaly_bullets = anomaly_bullets_for_operating_system(analysis, operating_system)
			if anomaly_bullets:
				lines.extend(["", "Anomalies"])
				for bullet in anomaly_bullets:
					lines.append(truncated_text(f"- {bullet}", 88))
	else:
		lines.extend(["", "No hostname-matched assets found in software or PPS records."])
	patch_anomaly_rows = analysis.get("patch_anomaly_rows", [])
	if isinstance(patch_anomaly_rows, list) and patch_anomaly_rows:
		lines.extend(["", "Patch OS Anomalies"])
		for row in patch_anomaly_rows:
			lines.append(
				truncated_text(
					f"{row['hostname']}: {row['operating_system']} patch {row['patch_count']} expected {row['expected_patch_count']}",
					88,
				)
			)
	return lines


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, object]) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	def draw_page_number(canvas, doc) -> None:
		canvas.saveState()
		canvas.setFont("Helvetica", 9)
		canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 18, f"Page {canvas.getPageNumber()}")
		canvas.restoreState()

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
	analysis = report_data["configuration_overlap_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}
	os_host_groups = host_rows_by_operating_system(analysis.get("host_rows", []))
	patch_anomaly_rows = [["Hostname", "Operating System", "Patch", "Expected"]]
	for row in analysis.get("patch_anomaly_rows", []):
		patch_anomaly_rows.append([row["hostname"], row["operating_system"], row["patch_count"], row["expected_patch_count"]])

	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		leftMargin=36,
		rightMargin=36,
		title=safe_text(report_data["report_title"]),
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(safe_text(report_data["report_title"]), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"Title: {html.escape(report_data['title'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		Paragraph(f"Number of Checklists: {html.escape(report_data['number_of_checklists'])}", styles["Normal"]),
		Paragraph(f"Framework Title: {html.escape(report_data['framework_title'])}", styles["Normal"]),
		Paragraph(f"Framework Acronym: {html.escape(report_data['framework_acronym'])}", styles["Normal"]),
		Paragraph(f"Framework Version: {html.escape(report_data['framework_version'])}", styles["Normal"]),
		Paragraph("Framework Levels:", styles["Normal"]),
		*([
			Paragraph(html.escape(format_framework_level(level)), styles["Normal"])
			for level in report_data["framework_levels"]
		] if report_data["framework_levels"] else [Paragraph("None returned.", styles["Normal"])]),
	]
	hardware_summary = report_data.get("hardware_device_summary", {})
	if isinstance(hardware_summary, dict):
		story.append(Paragraph(f"Total Number of Hardware Devices: {int(hardware_summary.get('total_count', 0) or 0)}", styles["Normal"]))
	story.extend(
		[
			PageBreak(),
			Paragraph("Configuration Overlap Analysis", left_title_style),
		]
	)
	if os_host_groups:
		for operating_system, rows in os_host_groups:
			table_rows = [["Hostname", "Software", "PPS", "Patch", "Avg Overlap"]]
			for row in rows:
				table_rows.append([row["hostname"], row["software_count"], row["ppsm_count"], row["patch_count"], row["average_overlap"]])
			anomaly_bullets = anomaly_bullets_for_operating_system(analysis, operating_system)
			story.extend(
				[
					Spacer(1, 14),
					Paragraph(html.escape(operating_system), left_heading_style),
					Spacer(1, 8),
					pdf_table(table_rows, [170, 75, 55, 130, 70], styles, table_style),
				]
			)
			if anomaly_bullets:
				story.extend([Spacer(1, 10), Paragraph("Anomalies", left_heading_style), Spacer(1, 4)])
				for bullet in anomaly_bullets:
					story.append(Paragraph(f"• {html.escape(bullet)}", styles["Normal"]))
	else:
		story.extend(
			[
				Spacer(1, 14),
				Paragraph("No hostname-matched assets found in software or PPS records.", styles["Normal"]),
			]
		)
	if len(patch_anomaly_rows) > 1:
		story.extend(
			[
				Spacer(1, 14),
				Paragraph("Patch OS Anomalies", left_heading_style),
				Spacer(1, 8),
				Paragraph("Devices with the same operating system should have matching patch totals. Rows below differ from the most common patch total for that operating system.", styles["Normal"]),
				Spacer(1, 8),
				pdf_table(patch_anomaly_rows, [150, 190, 75, 75], styles, table_style),
			]
		)
	document.build(story, onFirstPage=draw_page_number, onLaterPages=draw_page_number)
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


def add_page_number_to_page_stream(page_stream: str, page_number: int, page_width: int) -> str:
	return (
		page_stream
		+ "\nBT\n"
		+ "/F1 9 Tf\n"
		+ f"1 0 0 1 {page_width - 72} 18 Tm ({escape_pdf_text(f'Page {page_number}')}) Tj\n"
		+ "ET"
	)


def write_minimal_pdf(output_path: Path, report_data: dict[str, object]) -> None:
	analysis = report_data["configuration_overlap_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}
	hardware_summary = report_data.get("hardware_device_summary", {})
	if not isinstance(hardware_summary, dict):
		hardware_summary = {}
	hardware_lines = [
		f"Total Number of Hardware Devices: {int(hardware_summary.get('total_count', 0) or 0)}",
	]
	overlap_lines = build_fallback_overlap_lines(analysis)
	overlap_page_chunks = [overlap_lines[index:index + 30] for index in range(0, len(overlap_lines), 30)] or [["Configuration Overlap Analysis", "", "No hostname-matched assets found in software or PPS records."]]
	page_streams = [
		make_text_page(
			[
				safe_text(report_data["report_title"]),
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"Title: {report_data['title']}",
				f"System Key: {report_data['system_key']}",
				f"Description: {report_data['system_description']}",
				f"Number of Checklists: {report_data['number_of_checklists']}",
				f"Framework Title: {report_data['framework_title']}",
				f"Framework Acronym: {report_data['framework_acronym']}",
				f"Framework Version: {report_data['framework_version']}",
				"Framework Levels:",
				*([f"- {format_framework_level(level)}" for level in report_data["framework_levels"]] or ["None returned."]),
				*hardware_lines,
			],
			font_size=14,
		),
	]
	page_streams.extend(make_text_page(chunk, font_size=12) for chunk in overlap_page_chunks)
	page_streams = [
		add_page_number_to_page_stream(page_stream, page_number, 612)
		for page_number, page_stream in enumerate(page_streams, start=1)
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
	options = parse_optional_arguments(sys.argv[5:])
	system_package = parse_json_value_from_output(call_system_package_json_script(sys.argv[1:5]))
	hardware_data = parse_json_value_from_output(call_hardware_json_script(sys.argv[1:5]))
	software_data = parse_json_value_from_output(call_software_json_script(sys.argv[1:5]))
	ppsm_data = parse_json_value_from_output(call_ppsm_json_script(sys.argv[1:5]))
	patch_score_devices_data = parse_json_value_from_output(call_patch_score_devices_json_script(sys.argv[1:5]))
	report_data = build_report_data(system_key, options, system_package, hardware_data, software_data, ppsm_data, patch_score_devices_data)
	output_filename = f"OpenRMFPro-Configuration-Overlap-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
