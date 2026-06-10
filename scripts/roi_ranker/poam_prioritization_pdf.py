#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional RoI Ranker PDF
# Description: Creates a POAM prioritization PDF report for a system key.
# ============================================================

import html
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE = "OpenRMF Professional RoI Ranker"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
POAM_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
PATCHDATA_SCRIPT_NAME = "get_systempackage_by_systemkey_patchdata_json.py"
REPORT_SECTIONS = [
	{"title": "RoI Prioritization Summary", "anchor": "roi-prioritization-summary", "page_number": "2"},
	{"title": "Top Prioritized POAM Items", "anchor": "top-prioritized-poam-items", "page_number": "3"},
	{"title": "POAM Type RoI Summary", "anchor": "poam-type-roi-summary", "page_number": "4"},
	{"title": "Completion Window Summary", "anchor": "completion-window-summary", "page_number": "5"},
	{"title": "Scoring Model", "anchor": "scoring-model", "page_number": "6"},
]
STATUS_COLUMNS = ["Ongoing", "Completed", "Accepted"]
POAM_TYPE_DEFINITIONS = [
	("artifactId", "Checklist Vulnerability"),
	("patchScanId", "Patch Vulnerability"),
	("statementId", "Compliance Statement"),
	("inheritedControlId", "Inherited Controls"),
	("vulnScanId", "Technology Vulnerability"),
]
MANUAL_POAM_TYPE = "Manually Added / Deleted Items"
RAW_SEVERITY_FIELD_KEYS = ["rawSeverity", "rawSeverityString", "rawSeverityValue", "severity", "severityString"]
RESIDUAL_RISK_FIELD_KEYS = [
	"residualRiskLevelMitigations",
	"residualRiskLevelMitigation",
	"residualRisk",
	"residualRiskString",
	"resultingResidualRisk",
]
SCORE_WEIGHTS = {
	"raw_severity": {"Critical": 50, "High": 40, "Moderate": 25, "Low": 10, "Blank": 0},
	"residual_risk": {"Very High": 25, "High": 20, "Moderate": 12, "Low": 5, "Very Low": 2, "Blank": 0},
	"status": {"Ongoing": 20, "Accepted": 5, "Completed": -20, "Other": 0},
	"completion_window": {"Past Due": 20, "Due in 0-30 Days": 15, "Due in 31-60 Days": 10, "Due in 61-90 Days": 5, "Due After 90 Days": 0, "No Date": 8},
	"poam_type": {"Patch Vulnerability": 8, "Checklist Vulnerability": 6, "Technology Vulnerability": 6, "Compliance Statement": 4, "Inherited Controls": 2, MANUAL_POAM_TYPE: 1},
	"false_positive": {"Yes": -30, "No": 0},
}
SEVERITY_WEIGHTS = {"Critical": 10, "Very High": 10, "High": 7, "Moderate": 4, "Low": 1, "Very Low": 1, "Blank": 1}
BROAD_PATCH_ASSET_THRESHOLD = 10


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 'RoI Ranker/"
		+ Path(__file__).name
		+ "' <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
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


def call_patchdata_json_script(arguments: list[str]) -> str | None:
	source_script = Path(__file__).resolve().parents[1] / "patch-vulnerability" / PATCHDATA_SCRIPT_NAME
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print("WARNING: The patchdata JSON script failed. Continuing with POAM-only effort scoring.")
		if result.stderr.strip():
			print(result.stderr.strip())
		return None
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
	print("ERROR: Could not find JSON in the child script output.")
	print(output)
	sys.exit(1)


def parse_json_value_from_output_or_none(output: str | None):
	if not output:
		return None
	decoder = json.JSONDecoder()
	for index, character in enumerate(output):
		if character not in "[{":
			continue
		try:
			parsed, _ = decoder.raw_decode(output[index:])
			return parsed
		except json.JSONDecodeError:
			continue
	return None


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


def first_value(record: dict, keys: list[str]) -> str:
	for key in keys:
		value = record.get(key)
		if value not in (None, ""):
			return safe_text(value)
	return ""


def first_nested_value(record: dict, paths: list[list[str]]) -> str:
	for path in paths:
		current_value = record
		for key in path:
			if not isinstance(current_value, dict) or key not in current_value:
				current_value = None
				break
			current_value = current_value[key]
		if current_value not in (None, ""):
			return safe_text(current_value)
	return ""


def looks_like_poam_record(value: dict) -> bool:
	poam_keys = {
		"poamItemId",
		"poamLinkedId",
		"controlVulnerabilityDescription",
		"securityControlNumber",
		"status",
		"statusString",
		"poamStatus",
		"scheduledCompletionDate",
	}
	return bool(poam_keys.intersection(value.keys()))


def find_record_list(data, candidate_keys: list[str]) -> list[dict]:
	if isinstance(data, list):
		return [record for record in data if isinstance(record, dict)]
	if not isinstance(data, dict):
		return []
	if looks_like_poam_record(data):
		return [data]

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
	if value_text in {"completed", "complete", "closed"}:
		return "Completed"
	if value_text in {"accepted", "risk accepted", "risk acceptance"}:
		return "Accepted"
	if value_text in {"ongoing", "on going", "in progress", "active", "open", "new"}:
		return "Ongoing"
	return safe_text(value).strip() or "Other"


def poam_status(record: dict) -> str:
	status = first_value(
		record,
		[
			"status",
			"statusString",
			"poamStatus",
			"poamStatusString",
			"poamStatusName",
			"workflowStatus",
			"state",
		],
	)
	if not status:
		status = first_nested_value(record, [["status", "name"], ["poamStatus", "name"], ["workflow", "status"]])
	return normalize_status(status)


def has_poam_type_value(record: dict, key: str) -> bool:
	value = record.get(key)
	return safe_text(value).strip().lower() not in {"", "none", "null"}


def poam_type(record: dict) -> str:
	for key, label in POAM_TYPE_DEFINITIONS:
		if has_poam_type_value(record, key):
			return label
	return MANUAL_POAM_TYPE


def normalize_raw_severity(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"critical", "very high", "veryhigh", "cat i", "cat 1", "i", "4", "5"}:
		return "Critical"
	if value_text in {"high", "cat ii", "cat 2", "ii", "3"}:
		return "High"
	if value_text in {"medium", "moderate", "cat iii", "cat 3", "iii", "2"}:
		return "Moderate"
	if value_text in {"low", "1"}:
		return "Low"
	return "Blank"


def normalize_residual_risk(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"very high", "veryhigh", "critical", "cat i", "cat 1", "i", "5"}:
		return "Very High"
	if value_text in {"high", "cat ii", "cat 2", "ii", "4"}:
		return "High"
	if value_text in {"moderate", "medium", "cat iii", "cat 3", "iii", "3"}:
		return "Moderate"
	if value_text in {"low", "2", "1"}:
		return "Low"
	if value_text in {"very low", "verylow"}:
		return "Very Low"
	return "Blank"


def raw_severity(record: dict) -> str:
	return normalize_raw_severity(first_value(record, RAW_SEVERITY_FIELD_KEYS))


def residual_risk(record: dict) -> str:
	return normalize_residual_risk(first_value(record, RESIDUAL_RISK_FIELD_KEYS))


def scheduled_completion_value(record: dict) -> str:
	return first_value(
		record,
		[
			"scheduledCompletionDate",
			"scheduledCompletionDateString",
			"scheduledCompletion",
			"scheduledCompletionString",
			"milestoneScheduledCompletionDate",
			"milestoneCompletionDate",
			"completionDate",
		],
	)


def parse_date_value(value):
	value_text = safe_text(value).strip()
	if not value_text:
		return None

	normalized_value = value_text.replace("Z", "+00:00")
	try:
		return datetime.fromisoformat(normalized_value).astimezone().date()
	except ValueError:
		pass

	for date_format in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y", "%Y-%m-%d"):
		try:
			return datetime.strptime(value_text, date_format).date()
		except ValueError:
			continue
	return None


def bool_value(value) -> bool:
	if isinstance(value, bool):
		return value
	if isinstance(value, (int, float)):
		return value != 0
	value_text = safe_text(value).strip().lower()
	return value_text in {"true", "yes", "y", "1"}


def false_positive(record: dict) -> bool:
	return bool_value(first_value(record, ["falsePositive", "isFalsePositive", "false_positive"]))


def completion_window(record: dict) -> str:
	scheduled_date = parse_date_value(scheduled_completion_value(record))
	if scheduled_date is None:
		return "No Date"
	days_until_due = (scheduled_date - datetime.now().astimezone().date()).days
	if days_until_due < 0:
		return "Past Due"
	if days_until_due <= 30:
		return "Due in 0-30 Days"
	if days_until_due <= 60:
		return "Due in 31-60 Days"
	if days_until_due <= 90:
		return "Due in 61-90 Days"
	return "Due After 90 Days"


def poam_identifier(record: dict) -> str:
	return first_value(record, ["poamItemId", "poamLinkedId", "id", "internalIdString", "vulnerabilityId", "vulnId"]) or "Unknown"


def control_number(record: dict) -> str:
	return first_value(record, ["securityControlNumber", "control", "controlNumber", "cci", "cciNumber"])


def vulnerability_title(record: dict) -> str:
	title = first_value(
		record,
		[
			"controlVulnerabilityDescription",
			"vulnerabilityDescription",
			"description",
			"title",
			"vulnTitle",
			"statement",
		],
	)
	return re.sub(r"\s+", " ", title).strip() or "No description returned"


def affected_asset_count(record: dict) -> int:
	for key in ["devicesAffected", "assetsAffected", "affectedAssets", "deviceCount", "assetCount", "hostCount", "hostsAffected"]:
		value = record.get(key)
		if isinstance(value, (int, float)):
			return max(int(value), 1)
		value_text = safe_text(value).strip()
		if value_text.isdigit():
			return max(int(value_text), 1)
		if value_text and any(separator in value_text for separator in [",", ";", "|"]):
			return max(len([item for item in re.split(r"[,;|]", value_text) if item.strip()]), 1)

	for key in ["devices", "assets", "hosts", "deviceNames", "assetNames", "hostNames"]:
		value = record.get(key)
		if isinstance(value, list):
			return max(len(value), 1)
		if isinstance(value, dict):
			return max(len(value), 1)

	for key in ["deviceName", "devicename", "hostName", "hostname", "assetName", "asset", "name"]:
		if safe_text(record.get(key)).strip():
			return 1
	return 1


def normalized_identifier_values(record: dict, keys: list[str]) -> set[str]:
	values = set()
	for key in keys:
		value = record.get(key)
		if isinstance(value, (list, tuple, set)):
			for item in value:
				item_text = safe_text(item).strip().lower()
				if item_text:
					values.add(item_text)
		else:
			value_text = safe_text(value).strip().lower()
			if value_text:
				values.add(value_text)
	return values


def build_patch_identifier_lookup(patch_data) -> set[str]:
	patch_records = find_record_list(patch_data, ["records", "items", "data", "results", "patchdata", "patchData", "patches"])
	identifiers = set()
	for record in patch_records:
		identifiers.update(normalized_identifier_values(record, ["patchScanId", "pluginId", "pluginID", "pluginName", "id", "vulnerabilityId", "vulnId"]))
	return identifiers


def is_patch_backed(record: dict, patch_identifier_lookup: set[str]) -> bool:
	if has_poam_type_value(record, "patchScanId"):
		return True
	poam_patch_identifiers = normalized_identifier_values(record, ["patchScanId", "pluginId", "pluginID", "pluginName", "vulnerabilityId", "vulnId", "sourceId", "sourceName"])
	return bool(poam_patch_identifiers.intersection(patch_identifier_lookup))


def effort_score_and_reason(record: dict, asset_count: int, patch_identifier_lookup: set[str] | None = None) -> tuple[int, str]:
	patch_identifier_lookup = patch_identifier_lookup or set()
	if is_patch_backed(record, patch_identifier_lookup):
		if asset_count >= BROAD_PATCH_ASSET_THRESHOLD:
			return 2, "Patch remediation across many affected assets"
		return 1, "Patch remediation available"
	if has_poam_type_value(record, "artifactId") or has_poam_type_value(record, "vulnScanId"):
		return 3, "Checklist or technology configuration change"
	if has_poam_type_value(record, "statementId") or has_poam_type_value(record, "inheritedControlId"):
		return 4, "Compliance or inherited-control evidence/process work"
	if bool_value(record.get("manuallyAdded")):
		return 5, "Manual POAM item requiring analyst triage"
	return 5, "Unknown remediation path requiring manual triage"


def import_pandas():
	try:
		import pandas as pd  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		print("ERROR: pandas is required for the POAM prioritization matrix. Install it with: python3 -m pip install pandas")
		sys.exit(1)
	return pd


def build_poam_prioritization_matrix(records: list[dict], patch_data=None):
	pd = import_pandas()
	patch_identifier_lookup = build_patch_identifier_lookup(patch_data)
	rows = []
	for record in records:
		status = poam_status(record)
		if status != "Ongoing":
			continue
		severity = residual_risk(record)
		asset_count = affected_asset_count(record)
		effort, effort_reason = effort_score_and_reason(record, asset_count, patch_identifier_lookup)
		severity_weight = SEVERITY_WEIGHTS.get(severity, 1)
		impact = severity_weight * asset_count
		rows.append(
			{
				"poam_id": poam_identifier(record),
				"control": control_number(record) or "Not Set",
				"description": truncate_text(vulnerability_title(record), 110),
				"poam_type": poam_type(record),
				"status": status,
				"severity": severity,
				"severity_weight": severity_weight,
				"affected_assets": asset_count,
				"impact": impact,
				"effort": effort,
				"effort_reason": effort_reason,
				"optimization_score": impact / effort if effort else impact,
				"risk_weight": impact,
				"completion_window": completion_window(record),
				"scheduled_completion": scheduled_completion_value(record) or "Not Set",
			}
		)

	columns = [
		"poam_id",
		"control",
		"description",
		"poam_type",
		"status",
		"severity",
		"severity_weight",
		"affected_assets",
		"impact",
		"effort",
		"effort_reason",
		"optimization_score",
		"risk_weight",
		"completion_window",
		"scheduled_completion",
	]
	if not rows:
		return pd.DataFrame(columns=columns)
	return pd.DataFrame(rows, columns=columns).sort_values(
		by=["optimization_score", "risk_weight", "affected_assets"],
		ascending=[False, False, False],
	).reset_index(drop=True)


def dataframe_rows(dataframe, limit: int) -> list[dict[str, str]]:
	rows = []
	for _, row in dataframe.head(limit).iterrows():
		rows.append(
			{
				"rank": safe_text(len(rows) + 1),
				"poam_id": safe_text(row["poam_id"]),
				"control": safe_text(row["control"]),
				"description": safe_text(row["description"]),
				"poam_type": safe_text(row["poam_type"]),
				"severity": safe_text(row["severity"]),
				"affected_assets": safe_text(int(row["affected_assets"])),
				"impact": safe_text(int(row["impact"])),
				"effort": safe_text(int(row["effort"])),
				"optimization_score": f"{float(row['optimization_score']):.2f}",
				"effort_reason": safe_text(row["effort_reason"]),
			}
		)
	return rows


def residual_risk_display_label(value: str) -> str:
	severity = safe_text(value).strip()
	if severity == "Moderate":
		return "Medium"
	if severity == "Blank":
		return "Not Set"
	return severity or "Not Set"


def effort_display_label(effort_score: int, effort_reason: str) -> str:
	reason = safe_text(effort_reason)
	if reason.startswith("Patch remediation available"):
		return "Low / Patch"
	if reason.startswith("Patch remediation across"):
		return "Low-Med / Patch"
	if reason.startswith("Checklist"):
		return "Medium / Config"
	if reason.startswith("Compliance"):
		return "Med-High / Evidence"
	return "High / Manual" if effort_score >= 5 else safe_text(effort_score)


def fix_type_label(poam_type_value: str, effort_reason: str) -> str:
	if safe_text(effort_reason).startswith("Patch"):
		return "Patch"
	if poam_type_value in {"Checklist Vulnerability", "Technology Vulnerability"}:
		return "Configuration"
	if poam_type_value in {"Compliance Statement", "Inherited Controls"}:
		return "Compliance"
	return "Manual"


def simplified_matrix_rows(dataframe, limit: int | None = None) -> list[dict[str, str]]:
	rows = []
	total_risk_weight = float(dataframe["risk_weight"].sum()) if len(dataframe) else 0.0
	cumulative_risk_weight = 0.0
	matrix_rows = dataframe if limit is None else dataframe.head(limit)
	for _, row in matrix_rows.iterrows():
		cumulative_risk_weight += float(row["risk_weight"])
		cumulative_risk_percent = (cumulative_risk_weight / total_risk_weight * 100) if total_risk_weight else 0.0
		rows.append(
			{
				"poam_id": safe_text(row["poam_id"]),
				"title": safe_text(row["description"]),
				"severity": residual_risk_display_label(row["severity"]),
				"impact": safe_text(int(row["impact"])),
				"effort": effort_display_label(int(row["effort"]), row["effort_reason"]),
				"priority_score": f"{float(row['optimization_score']):.2f}",
				"cumulative_risk_percent": f"{cumulative_risk_percent:.1f}%",
			}
		)
	return rows


def build_executive_summary_rows(matrix) -> list[dict[str, str]]:
	open_items = len(matrix)
	total_risk_weight = int(matrix["risk_weight"].sum()) if open_items else 0
	top_three = matrix.head(3)
	top_three_risk_weight = int(top_three["risk_weight"].sum()) if open_items else 0
	risk_reduction_percent = (top_three_risk_weight / total_risk_weight * 100) if total_risk_weight else 0
	patch_top_three_count = int(top_three["effort_reason"].str.startswith("Patch", na=False).sum()) if open_items else 0
	return [
		{"metric": "Open POAM Items Scored", "value": safe_text(open_items), "note": "Live POAM records filtered to open/ongoing items."},
		{"metric": "Total Open POAM Risk Weight", "value": safe_text(total_risk_weight), "note": "Sum of Severity Weight × Affected Assets."},
		{"metric": "Top 3 Risk Weight", "value": safe_text(top_three_risk_weight), "note": "Risk weight addressed by the top three ranked fixes."},
		{"metric": "Top 3 Risk Reduction", "value": f"{risk_reduction_percent:.1f}%", "note": "Percent of total open POAM risk weight addressed by the top three fixes."},
		{"metric": "Patch Fixes in Top 3", "value": safe_text(patch_top_three_count), "note": "Top three items identified as patch-backed POAMs."},
	]


def build_executive_statement(top_three_rows: list[dict[str, str]], summary_rows: list[dict[str, str]]) -> str:
	patch_count = next((row["value"] for row in summary_rows if row["metric"] == "Patch Fixes in Top 3"), "0")
	risk_reduction = next((row["value"] for row in summary_rows if row["metric"] == "Top 3 Risk Reduction"), "0.0%")
	if not top_three_rows:
		return "No open POAM items were returned for prioritization."
	return f"Fixing the top 3 prioritized items resolves {risk_reduction} of the total open POAM risk weight; {patch_count} of those top fixes are patch vulnerabilities."


def truncate_text(value: str, max_length: int = 120) -> str:
	value_text = safe_text(value).strip()
	if len(value_text) <= max_length:
		return value_text
	return value_text[: max_length - 1].rstrip() + "…"


def priority_score(record: dict) -> int:
	type_label = poam_type(record)
	status_label = poam_status(record)
	false_positive_label = "Yes" if false_positive(record) else "No"
	score = 0
	score += SCORE_WEIGHTS["raw_severity"].get(raw_severity(record), 0)
	score += SCORE_WEIGHTS["residual_risk"].get(residual_risk(record), 0)
	score += SCORE_WEIGHTS["status"].get(status_label, SCORE_WEIGHTS["status"]["Other"])
	score += SCORE_WEIGHTS["completion_window"].get(completion_window(record), 0)
	score += SCORE_WEIGHTS["poam_type"].get(type_label, 0)
	score += SCORE_WEIGHTS["false_positive"][false_positive_label]
	return max(score, 0)


def roi_band(score: int) -> str:
	if score >= 95:
		return "Highest"
	if score >= 75:
		return "High"
	if score >= 45:
		return "Medium"
	return "Low"


def build_ranked_poam_items(records: list[dict]) -> list[dict[str, str]]:
	ranked_records = sorted(
		records,
		key=lambda record: (
			priority_score(record),
			SCORE_WEIGHTS["raw_severity"].get(raw_severity(record), 0),
			SCORE_WEIGHTS["residual_risk"].get(residual_risk(record), 0),
		),
		reverse=True,
	)
	rows = []
	for rank, record in enumerate(ranked_records, start=1):
		score = priority_score(record)
		rows.append(
			{
				"rank": safe_text(rank),
				"score": safe_text(score),
				"roi_band": roi_band(score),
				"poam_id": poam_identifier(record),
				"status": poam_status(record),
				"raw_severity": raw_severity(record),
				"residual_risk": residual_risk(record),
				"completion_window": completion_window(record),
				"scheduled_completion": scheduled_completion_value(record) or "Not Set",
				"poam_type": poam_type(record),
				"control": control_number(record),
				"description": truncate_text(vulnerability_title(record)),
			}
		)
	return rows


def average(values: list[int]) -> float:
	if not values:
		return 0.0
	return sum(values) / len(values)


def build_summary_rows(ranked_rows: list[dict[str, str]]) -> list[dict[str, str]]:
	total_items = len(ranked_rows)
	high_priority = sum(1 for row in ranked_rows if row["roi_band"] in {"Highest", "High"})
	past_due = sum(1 for row in ranked_rows if row["completion_window"] == "Past Due")
	ongoing = sum(1 for row in ranked_rows if row["status"] == "Ongoing")
	no_date = sum(1 for row in ranked_rows if row["completion_window"] == "No Date")
	avg_score = average([int(row["score"]) for row in ranked_rows])
	return [
		{"metric": "Total POAM Items", "value": safe_text(total_items), "note": "All POAM records returned by the API."},
		{"metric": "High RoI Targets", "value": safe_text(high_priority), "note": "Items ranked Highest or High by weighted score."},
		{"metric": "Ongoing Items", "value": safe_text(ongoing), "note": "Open/in-progress POAM items."},
		{"metric": "Past Due Items", "value": safe_text(past_due), "note": "Items with scheduled completion dates before today."},
		{"metric": "Ongoing Items Without Dates", "value": safe_text(no_date), "note": "Items missing a usable scheduled completion date."},
		{"metric": "Average Priority Score", "value": f"{avg_score:.1f}", "note": "Average weighted RoI score across returned POAM items."},
	]


def build_type_summary_rows(ranked_rows: list[dict[str, str]]) -> list[dict[str, str]]:
	type_totals = defaultdict(lambda: {"count": 0, "score_total": 0, "highest": 0, "high": 0, "medium": 0, "low": 0})
	for row in ranked_rows:
		type_bucket = type_totals[row["poam_type"]]
		type_bucket["count"] += 1
		type_bucket["score_total"] += int(row["score"])
		type_bucket[row["roi_band"].lower()] += 1
	rows = []
	for label in [*[label for _, label in POAM_TYPE_DEFINITIONS], MANUAL_POAM_TYPE]:
		bucket = type_totals[label]
		rows.append(
			{
				"poam_type": label,
				"count": safe_text(bucket["count"]),
				"average_score": f"{bucket['score_total'] / bucket['count']:.1f}" if bucket["count"] else "0.0",
				"highest": safe_text(bucket["highest"]),
				"high": safe_text(bucket["high"]),
				"medium": safe_text(bucket["medium"]),
				"low": safe_text(bucket["low"]),
			}
		)
	return rows


def build_completion_window_rows(ranked_rows: list[dict[str, str]]) -> list[dict[str, str]]:
	window_labels = ["Past Due", "Due in 0-30 Days", "Due in 31-60 Days", "Due in 61-90 Days", "Due After 90 Days", "No Date"]
	window_totals = {label: {"count": 0, "score_total": 0, "high_priority": 0} for label in window_labels}
	for row in ranked_rows:
		bucket = window_totals[row["completion_window"]]
		bucket["count"] += 1
		bucket["score_total"] += int(row["score"])
		if row["roi_band"] in {"Highest", "High"}:
			bucket["high_priority"] += 1
	return [
		{
			"completion_window": label,
			"count": safe_text(window_totals[label]["count"]),
			"high_priority": safe_text(window_totals[label]["high_priority"]),
			"average_score": f"{window_totals[label]['score_total'] / window_totals[label]['count']:.1f}" if window_totals[label]["count"] else "0.0",
		}
		for label in window_labels
	]


def build_scoring_model_rows() -> list[dict[str, str]]:
	rows = []
	for category, weights in SCORE_WEIGHTS.items():
		label = category.replace("_", " ").title()
		for value, score in weights.items():
			rows.append({"category": label, "value": safe_text(value), "points": safe_text(score)})
	return rows


def build_table_of_contents_rows() -> list[dict[str, str]]:
	return [section.copy() for section in REPORT_SECTIONS]


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


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, poam_data, patch_data=None) -> dict:
	system_title = build_system_title(system_package, options)
	matrix = build_poam_prioritization_matrix(poam_records(poam_data), patch_data)
	top_three_rows = dataframe_rows(matrix, 3)
	top_ten_rows = dataframe_rows(matrix, 10)
	priority_matrix_rows = simplified_matrix_rows(matrix)
	executive_summary_rows = build_executive_summary_rows(matrix)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title, system_key),
		"system_description": build_system_description(system_package, options),
		"executive_statement": build_executive_statement(top_three_rows, executive_summary_rows),
		"executive_summary_rows": executive_summary_rows,
		"top_three_rows": top_three_rows,
		"top_ten_rows": top_ten_rows,
		"priority_matrix_rows": priority_matrix_rows,
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
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"
	table_header_style.fontSize = 7
	table_header_style.leading = 8
	small_style = styles["BodyText"].clone("SmallTableText")
	small_style.fontSize = 7
	small_style.leading = 8
	subheading_style = styles["BodyText"].clone("RoISubheading")
	subheading_style.fontName = "Helvetica-Bold"
	subheading_style.fontSize = 10
	subheading_style.leading = 12

	def paragraph_cell(value: str, style=None):
		return Paragraph("<br/>".join(html.escape(line) for line in safe_text(value).splitlines()), style or styles["BodyText"])

	def styled_table(rows, col_widths, right_align_from: int = 1):
		table = Table(rows, hAlign="LEFT", colWidths=col_widths, repeatRows=1)
		table.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
					("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
					("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
					("ALIGN", (0, 0), (-1, 0), "CENTER"),
					("ALIGN", (right_align_from, 1), (-1, -1), "RIGHT"),
					("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
				]
			)
		)
		return table

	executive_summary_table = styled_table(
		[
			[Paragraph("Metric", table_header_style), Paragraph("Value", table_header_style), Paragraph("Notes", table_header_style)],
			*[[row["metric"], row["value"], paragraph_cell(row["note"])] for row in report_data["executive_summary_rows"]],
		],
		[180, 80, 260],
	)
	priority_matrix_table = styled_table(
		[
			[
				Paragraph("POAM_ID", table_header_style),
				Paragraph("Title", table_header_style),
				Paragraph("Severity", table_header_style),
				Paragraph("Impact", table_header_style),
				Paragraph("Effort", table_header_style),
				Paragraph("Priority&nbsp;Score", table_header_style),
				Paragraph("Cumulative Risk %", table_header_style),
			],
			*[
				[
					paragraph_cell(row["poam_id"], small_style),
					paragraph_cell(row["title"], small_style),
					row["severity"],
					row["impact"],
					paragraph_cell(row["effort"], small_style),
					row["priority_score"],
					row["cumulative_risk_percent"],
				]
				for row in report_data["priority_matrix_rows"]
			],
		],
		[55, 185, 55, 45, 80, 75, 45],
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
		Paragraph(report_data["report_title"], styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		PageBreak(),
		Paragraph("Live Open POAM Items Prioritization Matrix", styles["Heading1"]),
		Spacer(1, 8),
		priority_matrix_table if report_data["priority_matrix_rows"] else Paragraph("No open POAM items were returned for prioritization.", styles["Normal"]),
		Spacer(1, 18),
		Paragraph("Executive Summary", styles["Heading1"]),
		Spacer(1, 8),
		Paragraph(html.escape(report_data["executive_statement"]), subheading_style),
		Spacer(1, 12),
		executive_summary_table,
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
	priority_matrix_lines = ["Live Open POAM Items Prioritization Matrix", "", "POAM_ID | Title | Severity | Impact | Effort | Priority Score | Cumulative Risk %", "------- | ----- | -------- | ------ | ------ | -------------- | -----------------"]
	for row in report_data["priority_matrix_rows"]:
		priority_matrix_lines.append(f"{row['poam_id']} | {row['title']} | {row['severity']} | {row['impact']} | {row['effort']} | {row['priority_score']} | {row['cumulative_risk_percent']}")
	executive_lines = ["Executive Summary", "", report_data["executive_statement"], "", "Metric | Value | Notes", "------ | ----- | -----"]
	for row in report_data["executive_summary_rows"]:
		executive_lines.append(f"{row['metric']} | {row['value']} | {row['note']}")
	page_streams = [
		make_text_page(
			[
				report_data["report_title"],
				"",
				f"Date Generated: {report_data['generated_at']}",
				f"System Key: {report_data['system_key']}",
				f"System Title: {report_data['system_title']}",
				f"Description: {report_data['system_description']}",
			],
			font_size=14,
		),
		*[make_text_page(priority_matrix_lines[index:index + 36]) for index in range(0, len(priority_matrix_lines), 36)],
		*[make_text_page(executive_lines[index:index + 36]) for index in range(0, len(executive_lines), 36)],
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
	poam_data = parse_json_value_from_output(call_poam_json_script([*sys.argv[1:5], "grouped=false"]))
	patch_data = parse_json_value_from_output_or_none(call_patchdata_json_script([*sys.argv[1:5], "closed=false", "groupby=false"]))
	report_data = build_report_data(system_key, options, system_package, poam_data, patch_data)
	output_filename = f"OpenRMFPro-poam-prioritization-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
