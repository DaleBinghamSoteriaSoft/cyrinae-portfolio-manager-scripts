#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional Configuration Overlap PDF
# Description: Creates a Configuration Overlap PDF cover report for a system key.
# ============================================================

import html
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
SOFTWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_software_json.py"
PPSM_SCRIPT_NAME = "get_systempackage_by_systemkey_ppsm_json.py"
DEFAULT_BASELINE_SUPPORT_PERCENT = 80.0
DEFAULT_JACCARD_THRESHOLD = 0.75
DEFAULT_TOP_OUTLIERS = 15
DEFAULT_TOP_BASELINE_FEATURES = 20


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


def call_software_json_script(arguments: list[str]) -> str:
	return call_json_script("software", SOFTWARE_SCRIPT_NAME, [*arguments, "groupby=false"], "software")


def call_ppsm_json_script(arguments: list[str]) -> str:
	return call_json_script("ports-protocols-services", PPSM_SCRIPT_NAME, [*arguments, "groupby=false"], "PPSM")


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


def normalized_value(value: str) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip()).lower()


def display_value(value: str) -> str:
	return re.sub(r"\s+", " ", safe_text(value).strip())


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


def ppsm_records(ppsm_data) -> list[dict]:
	return find_record_list(
		ppsm_data,
		["records", "items", "data", "results", "ppsm", "pps", "portsProtocolsServices", "ports"],
		looks_like_ppsm_record,
	)


def record_hostname(record: dict) -> str:
	direct_value = first_record_value(
		record,
		[
			"hostname",
			"hostName",
			"host_name",
			"deviceName",
			"devicename",
			"assetName",
			"computerName",
			"machineName",
		],
	)
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


def build_configuration_overlap_analysis(software_data, ppsm_data, options: dict[str, str]) -> dict[str, object]:
	baseline_support_percent = max(0.0, min(100.0, optional_float(options, "baselineSupportPercent", DEFAULT_BASELINE_SUPPORT_PERCENT)))
	jaccard_threshold = max(0.0, min(1.0, optional_float(options, "jaccardThreshold", DEFAULT_JACCARD_THRESHOLD)))
	top_outliers = max(1, optional_int(options, "topOutliers", DEFAULT_TOP_OUTLIERS))
	top_baseline_features = max(1, optional_int(options, "topBaselineFeatures", DEFAULT_TOP_BASELINE_FEATURES))
	profiles, software_by_host, ppsm_by_host, skipped_records, software_record_count, ppsm_record_count = build_host_profiles(software_data, ppsm_data)
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
	host_rows = [
		{
			"hostname": hostname,
			"average_overlap": f"{average_scores.get(hostname, 1.0) * 100:.1f}%",
			"software_count": str(len(software_by_host.get(hostname, set()))),
			"ppsm_count": str(len(ppsm_by_host.get(hostname, set()))),
			"feature_count": str(len(profiles[hostname])),
			"outlier": "Yes" if hostname in outlier_hosts else "No",
		}
		for hostname in sorted(profiles, key=lambda host: (average_scores.get(host, 1.0), host))
	]
	return {
		"asset_count": asset_count,
		"software_record_count": software_record_count,
		"ppsm_record_count": ppsm_record_count,
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
		"host_rows": host_rows,
		"similarity_rows": similarity_rows[:top_outliers],
		"skipped_record_count": len(skipped_records),
		"skipped_record_examples": skipped_records[:5],
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


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, software_data, ppsm_data) -> dict[str, object]:
	system_title = build_system_title(system_package, options)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"configuration_overlap_analysis": build_configuration_overlap_analysis(software_data, ppsm_data, options),
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


def build_overlap_summary_lines(analysis: dict[str, object]) -> list[str]:
	return [
		f"Assets Matched by Hostname: {analysis['asset_count']}",
		f"Software Records Loaded: {analysis['software_record_count']}",
		f"Ports/Protocols/Services Records Loaded: {analysis['ppsm_record_count']}",
		f"Software Features: {analysis['software_feature_count']}",
		f"Ports/Protocols/Services Features: {analysis['ppsm_feature_count']}",
		f"Total Comparable Features: {analysis['total_feature_count']}",
		f"Baseline Support Threshold: {analysis['baseline_support_percent']} ({analysis['baseline_minimum_count']} assets minimum)",
		f"Jaccard Outlier Threshold: {analysis['jaccard_threshold']}",
		f"Baseline Features Discovered: {analysis['baseline_feature_count']}",
		f"Potential Drift/Outlier Assets: {analysis['outlier_count']}",
		f"Skipped Records: {analysis['skipped_record_count']}",
	]


def build_fallback_overlap_lines(analysis: dict[str, object]) -> list[str]:
	lines = ["Configuration Overlap Analysis", "", "All Matched Hostnames"]
	host_rows = analysis["host_rows"]
	if isinstance(host_rows, list) and host_rows:
		for row in host_rows:
			lines.append(
				truncated_text(
					f"{row['hostname']}: software {row['software_count']}, PPS {row['ppsm_count']}, {row['average_overlap']} overlap, outlier {row['outlier']}",
					88,
				)
			)
	else:
		lines.append("No hostname-matched assets found in software or PPS records.")
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
	host_rows = [["Hostname", "Software", "PPS", "Avg Overlap", "Outlier"]]
	for row in analysis.get("host_rows", []):
		host_rows.append([row["hostname"], row["software_count"], row["ppsm_count"], row["average_overlap"], row["outlier"]])
	if len(host_rows) == 1:
		host_rows.append(["No hostname-matched assets found in software or PPS records.", "", "", "", ""])

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
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		PageBreak(),
		Paragraph("Configuration Overlap Analysis", left_title_style),
		Spacer(1, 10),
		Paragraph("All software and ports/protocols/services records are matched by hostname, flattened into configuration features, and compared with Jaccard similarity.", styles["Normal"]),
		Spacer(1, 14),
		Paragraph("All Matched Hostnames", left_heading_style),
		Spacer(1, 8),
		pdf_table(host_rows, [190, 90, 70, 70, 70], styles, table_style),
	]
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
	analysis = report_data["configuration_overlap_analysis"]
	if not isinstance(analysis, dict):
		analysis = {}
	overlap_lines = build_fallback_overlap_lines(analysis)
	overlap_page_chunks = [overlap_lines[index:index + 30] for index in range(0, len(overlap_lines), 30)] or [["Configuration Overlap Analysis", "", "No hostname-matched assets found in software or PPS records."]]
	page_streams = [
		make_text_page(
			[
				safe_text(report_data["report_title"]),
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"System Key: {report_data['system_key']}",
				f"System Title: {report_data['system_title']}",
				f"Description: {report_data['system_description']}",
			],
			font_size=14,
		),
	]
	page_streams.extend(make_text_page(chunk, font_size=12) for chunk in overlap_page_chunks)
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
	software_data = parse_json_value_from_output(call_software_json_script(sys.argv[1:5]))
	ppsm_data = parse_json_value_from_output(call_ppsm_json_script(sys.argv[1:5]))
	report_data = build_report_data(system_key, options, system_package, software_data, ppsm_data)
	output_filename = f"OpenRMFPro-Configuration-Overlap-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
