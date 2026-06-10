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
import copy
from datetime import datetime
from io import BytesIO
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
	sys.path.insert(0, str(SCRIPT_DIR))

from risk_settings import RISK_SETTINGS

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE = "OpenRMF Professional Risk Profiler"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
READINESS_SCORE_SCRIPT_NAME = "get_systempackage_by_systemkey_readinessscore_json.py"
READINESS_SETTINGS_SCRIPT_NAME = "get_systempackage_by_systemkey_readinesssettings_json.py"
POAM_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
CHECKLIST_MISSINGDATA_SCRIPT_NAME = "get_systempackage_by_systemkey_missingdata_json.py"
COMPLIANCE_SCRIPT_NAME = "get_systempackage_by_systemkey_compliance_json.py"
COMPLIANCE_ALLCONTROLS_SCRIPT_NAME = "get_systempackage_by_systemkey_compliance_by_complianceid_allcontrolscore_json.py"
PPSM_SCRIPT_NAME = "get_systempackage_by_systemkey_ppsm_json.py"
APPROVED_PPS_SCRIPT_NAME = "get_systempackage_by_systemkey_approvedpps_json.py"
GENERAL_APPROVED_PPS_SCRIPT_NAME = "get_approvedpps_json.py"
STATUS_COLUMNS = ["Open", "Not a Finding", "Not Applicable", "Not Reviewed"]
REPORT_SECTIONS = [
	{"title": "Checklist Risk", "anchor": "checklist-risk"},
	{"title": "Checklist Missing Data", "anchor": "checklist-missing-data"},
	{"title": "Cyber Readiness Score", "anchor": "cyber-readiness-score"},
	{"title": "Patch Vulnerability Risk", "anchor": "patch-vulnerability-risk"},
	{"title": "POAM Risk Area", "anchor": "poam-items"},
	{"title": "POAM False Positives Risk", "anchor": "poam-false-positives-risk"},
	{"title": "Compliance", "anchor": "compliance"},
	{"title": "Ports/Protocols/Services", "anchor": "pps-boundaries"},
	{"title": "Risk Settings", "anchor": "risk-settings"},
]


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


def call_poam_json_script(arguments: list[str]) -> str:
	source_script = Path(__file__).resolve().parents[1] / "poam" / POAM_SCRIPT_NAME
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print("ERROR: The POAM JSON script failed.")
		if result.stdout.strip():
			print(result.stdout.strip())
		if result.stderr.strip():
			print(result.stderr.strip())
		sys.exit(result.returncode)
	return result.stdout


def call_child_script_result(source_script: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
	return subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)


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


def parse_json_value_from_output_or_none(output: str):
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


def score_value(score: dict, key: str) -> str:
	return str(score.get(key, 0))


def numeric_count(value: str) -> int:
	try:
		return int(float(str(value).strip()))
	except ValueError:
		return 0


def safe_text(value) -> str:
	if value is None:
		return ""
	return str(value)


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


def compliance_records(compliance_data) -> list[dict]:
	return find_record_list(compliance_data, ["records", "items", "data", "results", "compliance", "compliances"])


def control_score_records(control_score_data) -> list[dict]:
	return find_record_list(control_score_data, ["records", "items", "data", "results", "controls", "allControls", "controlScores"])


def extract_compliance_id(compliance_data) -> str:
	if isinstance(compliance_data, dict):
		direct = first_value(compliance_data, ["internalIdString", "complianceId", "complianceID", "systemComplianceId", "id"])
		if direct:
			return direct
		nested = first_nested_value(
			compliance_data,
			[
				["compliance", "internalIdString"],
				["compliance", "complianceId"],
				["compliance", "id"],
				["data", "internalIdString"],
				["data", "complianceId"],
				["data", "id"],
			],
		)
		if nested:
			return nested
	for record in compliance_records(compliance_data):
		compliance_id = first_value(record, ["internalIdString", "complianceId", "complianceID", "systemComplianceId", "id"])
		if compliance_id:
			return compliance_id
	return ""


def percentage_value(record: dict, keys: list[str]) -> float | None:
	value = first_value(record, keys)
	if not value:
		value = first_nested_value(record, [["score", key] for key in keys])
	if not value:
		return None
	try:
		return float(str(value).strip().rstrip("%"))
	except (TypeError, ValueError):
		return None


def readiness_value(data, keys: list[str]) -> str:
	if isinstance(data, dict):
		for key in keys:
			value = data.get(key)
			if value not in (None, ""):
				return safe_text(value).strip()
		for value in data.values():
			found_value = readiness_value(value, keys)
			if found_value:
				return found_value
	elif isinstance(data, list):
		for item in data:
			found_value = readiness_value(item, keys)
			if found_value:
				return found_value
	return ""


def readiness_score_number(value: str) -> float | None:
	try:
		return float(safe_text(value).strip())
	except ValueError:
		return None


READINESS_GRADE_PREFIXES = ["Excellent", "Good", "Poor", "Fail"]


def readiness_settings_record(data) -> dict:
	if isinstance(data, dict):
		if any(f"grade{prefix}Label" in data for prefix in READINESS_GRADE_PREFIXES):
			return data
		for value in data.values():
			found_record = readiness_settings_record(value)
			if found_record:
				return found_record
	elif isinstance(data, list):
		for item in data:
			found_record = readiness_settings_record(item)
			if found_record:
				return found_record
	return {}


def readiness_setting_number(settings: dict, key: str) -> float | None:
	try:
		value = settings.get(key)
		if value in (None, ""):
			return None
		return float(safe_text(value).strip())
	except (TypeError, ValueError):
		return None


def readiness_setting_value(settings: dict, key: str, null_display: str = "Not Used") -> str:
	if key not in settings:
		return "Missing Data"
	value = settings.get(key)
	if value is None:
		return null_display
	if value == "":
		return "Missing Data"
	return safe_text(value)


def readiness_grade_label(settings: dict, prefix: str, default_label: str) -> str:
	label = safe_text(settings.get(f"grade{prefix}Label")).strip()
	return label or default_label


def readiness_good_label(readiness_settings_data=None) -> str:
	settings = readiness_settings_record(readiness_settings_data)
	return readiness_grade_label(settings, "Good", "Good")


def readiness_grade_prefix_for_label(label: str, readiness_settings_data=None) -> str:
	settings = readiness_settings_record(readiness_settings_data)
	label_text = safe_text(label).strip()
	for prefix in READINESS_GRADE_PREFIXES:
		if label_text == readiness_grade_label(settings, prefix, prefix):
			return prefix
	return label_text


def readiness_score_label(score: float, readiness_settings_data=None) -> str:
	settings = readiness_settings_record(readiness_settings_data)
	if settings:
		for prefix in READINESS_GRADE_PREFIXES:
			minimum_score = readiness_setting_number(settings, f"grade{prefix}MinimumScore")
			maximum_score = readiness_setting_number(settings, f"grade{prefix}MaxScore")
			if minimum_score is None and maximum_score is None:
				continue
			if minimum_score is not None and score < minimum_score:
				continue
			if maximum_score is not None and score > maximum_score:
				continue
			return readiness_grade_label(settings, prefix, prefix)
	if score < 0:
		return ""
	if score <= 4:
		return "Excellent"
	if score <= 5.5:
		return "Good"
	if score <= 10:
		return "Poor"
	if score <= 999999999999:
		return "Fail"
	return "Fail"


def readiness_weight_setting(settings: dict, key: str, readiness_settings_data) -> str:
	value = readiness_setting_value(settings, key)
	return value


def readiness_grade_setting(settings: dict, prefix: str, include_max_critical_allowed: bool = False) -> str:
	setting_lines = [
		f"Max Score = {readiness_setting_value(settings, f'grade{prefix}MaxScore')}",
		f"Min Score = {readiness_setting_value(settings, f'grade{prefix}MinimumScore')}",
	]
	if include_max_critical_allowed:
		setting_lines.append(f"Max Critical Allowed = {readiness_setting_value(settings, f'grade{prefix}MaxCriticalAllowed')}")
	return "\n".join(setting_lines)


def build_cyber_readiness_settings_rows(readiness_settings_data) -> list[dict[str, str]]:
	settings = readiness_settings_record(readiness_settings_data)
	if not settings:
		return []
	rows = []
	for label, key in [
		("Checklist High Weight", "complianceChecklistWeightHigh"),
		("Checklist Medium Weight", "complianceChecklistWeightMedium"),
		("Checklist Low Weight", "complianceChecklistWeightLow"),
	]:
		rows.append({"category": label, "setting": readiness_weight_setting(settings, key, readiness_settings_data)})
	for label, key in [
		("Patch Critical Weight", "patchVulnerabilityWeightCritical"),
		("Patch High Weight", "patchVulnerabilityWeightHigh"),
		("Patch Medium Weight", "patchVulnerabilityWeightMedium"),
		("Patch Low Weight", "patchVulnerabilityWeightLow"),
	]:
		rows.append({"category": label, "setting": readiness_weight_setting(settings, key, readiness_settings_data)})
	for prefix, default_label, include_max_critical_allowed in [
		("Excellent", "Excellent", True),
		("Good", "Good", False),
		("Poor", "Poor", False),
		("Fail", "Fail", False),
	]:
		label = readiness_grade_label(settings, prefix, default_label)
		rows.append({"category": label, "setting": readiness_grade_setting(settings, prefix, include_max_critical_allowed), "grade_prefix": prefix})
	return rows


def readiness_open_count(readiness_score_data, keys: list[str]) -> int:
	value = readiness_value(readiness_score_data, keys)
	return numeric_count(value)


def readiness_open_count_or_none(readiness_score_data, keys: list[str]) -> int | None:
	value = readiness_value(readiness_score_data, keys)
	if value in (None, ""):
		return None
	return numeric_count(value)


def readiness_excellent_max_critical_allowed(readiness_settings_data) -> int | None:
	settings = readiness_settings_record(readiness_settings_data)
	value = readiness_setting_number(settings, "gradeExcellentMaxCriticalAllowed") if settings else None
	if value is None:
		return None
	return int(value)


def readiness_label_with_critical_allowance(readiness: str, score: float, readiness_score_data, readiness_settings_data, system_package: dict) -> str:
	label = readiness_score_label(score, readiness_settings_data)
	excellent_label = readiness_grade_label(readiness_settings_record(readiness_settings_data), "Excellent", "Excellent")
	if label != excellent_label:
		return label
	allowed_count = readiness_excellent_max_critical_allowed(readiness_settings_data)
	if allowed_count is None:
		return patch_readiness_label(score, system_package, readiness_settings_data) if readiness == "Patch" else label
	if readiness == "Checklist":
		score_data = system_package.get("score", {}) if isinstance(system_package, dict) else {}
		if not isinstance(score_data, dict):
			score_data = {}
		cat_1_open = readiness_open_count_or_none(readiness_score_data, ["totalChecklistCat1Open"])
		if cat_1_open is None:
			cat_1_open = numeric_count(score_value(score_data, "totalCat1Open"))
		if cat_1_open > allowed_count:
			return readiness_good_label(readiness_settings_data)
	elif readiness == "Patch":
		patch_score = system_package.get("patchScore", {}) if isinstance(system_package, dict) else {}
		if not isinstance(patch_score, dict):
			patch_score = {}
		critical_open = readiness_open_count_or_none(readiness_score_data, ["totalPatchCriticalOpen"])
		high_open = readiness_open_count_or_none(readiness_score_data, ["totalPatchHighOpen"])
		if critical_open is None:
			critical_open = numeric_count(score_value(patch_score, "totalCriticalOpen"))
		if high_open is None:
			high_open = numeric_count(score_value(patch_score, "totalHighOpen"))
		if critical_open > allowed_count or high_open > allowed_count:
			return readiness_good_label(readiness_settings_data)
	return label


def build_cyber_readiness_score_row(readiness: str, value: str, label_override: str | None = None, readiness_settings_data=None) -> dict[str, str] | None:
	score = readiness_score_number(value)
	if score is None:
		return None
	label = label_override or readiness_score_label(score, readiness_settings_data)
	if not label:
		return None
	return {"readiness": readiness, "score": f"{label}({score:.2f})", "label": label, "grade_prefix": readiness_grade_prefix_for_label(label, readiness_settings_data)}


def patch_readiness_label(score: float, system_package: dict, readiness_settings_data=None) -> str:
	label = readiness_score_label(score, readiness_settings_data)
	excellent_label = readiness_grade_label(readiness_settings_record(readiness_settings_data), "Excellent", "Excellent")
	if label != excellent_label:
		return label
	patch_score = system_package.get("patchScore", {}) if isinstance(system_package, dict) else {}
	if not isinstance(patch_score, dict):
		patch_score = {}
	critical_open = numeric_count(score_value(patch_score, "totalCriticalOpen"))
	high_open = numeric_count(score_value(patch_score, "totalHighOpen"))
	critical_excellent_max = risk_setting_count("maxPatchOpenCriticalVulnLowRisk")
	high_excellent_max = risk_setting_count("maxPatchOpenHighVulnLowRisk")
	if critical_open > critical_excellent_max or high_open > high_excellent_max:
		return "Good"
	return label


def risk_setting_percent(key: str) -> float:
	try:
		return float(safe_text(RISK_SETTINGS.get(key, 0)).strip().rstrip("%"))
	except ValueError:
		return 0.0


def build_overall_compliance_risk_rows(percentage_pairs: list[tuple[float, float]] | None = None) -> list[dict[str, str]]:
	open_high_risk_min = risk_setting_percent("minCompliancePercentOpenHighRisk")
	open_medium_risk_min = risk_setting_percent("minCompliancePercentOpenMediumRisk")
	complete_high_risk_max = risk_setting_percent("minCompliancePercentCompleteHighRisk")
	complete_medium_risk_max = risk_setting_percent("minCompliancePercentCompleteMediumRisk")
	if not percentage_pairs:
		return [
			{"title": "Compliance Percent Complete Risk", "value": "N/A", "risk": "High"},
			{"title": "Open Compliance Risk", "value": "N/A", "risk": "High"},
		]
	percentage_open_values = [percentage_open for percentage_open, _ in percentage_pairs]
	percentage_complete_values = [percentage_complete for _, percentage_complete in percentage_pairs]
	if any(percentage_complete <= complete_high_risk_max for percentage_complete in percentage_complete_values):
		complete_risk = "High"
	elif any(percentage_complete <= complete_medium_risk_max for percentage_complete in percentage_complete_values):
		complete_risk = "Medium"
	else:
		complete_risk = "Low"
	if any(percentage_open >= open_high_risk_min for percentage_open in percentage_open_values):
		open_risk = "High"
	elif any(percentage_open >= open_medium_risk_min for percentage_open in percentage_open_values):
		open_risk = "Medium"
	else:
		open_risk = "Low"
	return [
		{"title": "Compliance Percent Complete Risk", "value": f"{min(percentage_complete_values):.1f}%", "risk": complete_risk},
		{"title": "Open Compliance Risk", "value": f"{max(percentage_open_values):.1f}%", "risk": open_risk},
	]


def poam_records(poam_data) -> list[dict]:
	return find_record_list(poam_data, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


def scheduled_completion_value(record: dict) -> str:
	return first_value(record, ["scheduledCompletionDate"])


def residual_risk_mitigation_value(record: dict) -> str:
	return safe_text(record.get("residualRiskLevelMitigations"))


def office_organization_value(record: dict) -> str:
	return safe_text(record.get("officeOrganization"))


def is_empty_value(value: str) -> bool:
	return safe_text(value).strip().lower() in {"", "none", "null"}


def bool_value(value) -> bool:
	if isinstance(value, bool):
		return value
	if isinstance(value, (int, float)):
		return value != 0
	return safe_text(value).strip().lower() in {"true", "yes", "y", "1"}


def ppsm_records(ppsm_data) -> list[dict]:
	return find_record_list(ppsm_data, ["records", "items", "data", "results", "ppsm", "portsProtocolsServices"])


def ppsm_boundary_value(record: dict, boundary_number: int, direction: str) -> bool:
	direction_lower = direction.lower()
	direction_title = direction.title()
	for key in [
		f"boundary{boundary_number}{direction_title}",
		f"boundary{boundary_number}{direction_lower}",
		f"boundary{boundary_number}_{direction_lower}",
		f"boundary_{boundary_number}_{direction_lower}",
		f"boundary{boundary_number}{direction_title}Field",
		f"boundary{boundary_number}_{direction_lower}_field",
		f"boundary{boundary_number}{direction_title}Value",
		f"boundary{boundary_number}_{direction_lower}_value",
	]:
		if key in record:
			return bool_value(record.get(key))
	return False


def is_very_high_risk_value(value: str) -> bool:
	return safe_text(value).strip().lower().replace("_", " ").replace("-", " ") in {"very high", "veryhigh", "critical"}


def normalize_residual_risk_level(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"", "none", "null"}:
		return "Not Set"
	if value_text in {"very high", "veryhigh", "critical"}:
		return "Very High"
	if value_text == "high":
		return "High"
	if value_text in {"moderate", "medium"}:
		return "Moderate"
	if value_text == "low":
		return "Low"
	if value_text in {"very low", "verylow"}:
		return "Very Low"
	return safe_text(value).strip() or "Not Set"


def normalize_poam_status(value: str) -> str:
	value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
	if value_text in {"completed", "complete", "closed"}:
		return "Completed"
	if value_text in {"accepted", "risk accepted", "risk acceptance"}:
		return "Accepted"
	if value_text in {"ongoing", "on going", "in progress", "active", "open", "new"}:
		return "Ongoing"
	return safe_text(value).strip() or "Other"


def poam_status(record: dict) -> str:
	return normalize_poam_status(first_value(record, ["status", "statusString", "poamStatus", "poamStatusString", "poamStatusName", "workflowStatus", "state"]))


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


def build_poam_risk_area(poam_data) -> dict[str, str]:
	records = [record for record in poam_records(poam_data) if poam_status(record) == "Ongoing"]
	today = datetime.now().astimezone().date()
	scheduled_count = 0
	past_due_count = 0
	for record in records:
		scheduled_date = parse_date_value(scheduled_completion_value(record))
		if scheduled_date is None:
			continue
		scheduled_count += 1
		if scheduled_date < today:
			past_due_count += 1
	return {
		"risk": "High" if past_due_count else "Low",
		"past_due_count": str(past_due_count),
		"not_past_due_count": str(scheduled_count - past_due_count),
		"scheduled_count": str(scheduled_count),
		"total_count": str(len(records)),
		"as_of_date": today.strftime("%Y-%m-%d"),
	}


def build_poam_residual_risk_area(poam_data) -> dict[str, str]:
	records = poam_records(poam_data)
	total_count = len(records)
	empty_count = sum(1 for record in records if is_empty_value(residual_risk_mitigation_value(record)))
	empty_percent = (empty_count / total_count * 100) if total_count else 0
	if empty_percent > 75:
		risk = "High"
	elif empty_percent > 50:
		risk = "Moderate"
	elif empty_percent > 25:
		risk = "Low"
	else:
		risk = "Low"
	return {
		"risk": risk,
		"empty_count": str(empty_count),
		"high_empty_count": str(empty_count if risk == "High" else 0),
		"moderate_empty_count": str(empty_count if risk == "Moderate" else 0),
		"low_empty_count": str(empty_count if risk == "Low" else 0),
		"total_count": str(total_count),
		"empty_percent": f"{empty_percent:.1f}%",
	}


def build_poam_ongoing_risk_area(poam_data) -> dict[str, str]:
	records = poam_records(poam_data)
	ongoing_count = sum(1 for record in records if poam_status(record) == "Ongoing")
	accepted_count = sum(1 for record in records if poam_status(record) == "Accepted")
	accepted_percent = (accepted_count / ongoing_count * 100) if ongoing_count else 0
	if accepted_percent > 25:
		risk = "High"
	elif accepted_percent > 15:
		risk = "Moderate"
	else:
		risk = "Low"
	return {
		"risk": risk,
		"ongoing_count": str(ongoing_count),
		"accepted_count": str(accepted_count),
		"accepted_percent": f"{accepted_percent:.1f}%",
	}


def raw_severity_value(record: dict) -> str:
	return safe_text(record.get("rawSeverity"))


def poam_status_risk_level(count: int, low_risk_key: str, medium_risk_key: str) -> str:
	low_risk_max = risk_setting_count(low_risk_key)
	medium_risk_max = risk_setting_count(medium_risk_key)
	if count <= low_risk_max:
		return "Low"
	if count <= medium_risk_max:
		return "Medium"
	return "High"


def build_overall_poam_status_rows(poam_data) -> list[dict[str, str]]:
	records = poam_records(poam_data)
	row_specs = [
		(
			"POAM Ongoing Status",
			"Ongoing",
			"maxPOAMOngoingStatusLowRisk",
			"maxPOAMOngoingStatusMediumRisk",
		),
		(
			"POAM Accepted Status",
			"Accepted",
			"maxPOAMAcceptedStatusLowRisk",
			"maxPOAMAcceptedStatusMediumRisk",
		),
	]
	rows = []
	for title, status, low_risk_key, medium_risk_key in row_specs:
		count = sum(
			1
			for record in records
			if poam_status(record) == status and not is_empty_value(raw_severity_value(record))
		)
		rows.append(
			{
				"title": title,
				"count": str(count),
				"risk": poam_status_risk_level(count, low_risk_key, medium_risk_key),
			}
		)
	return rows


def build_poam_ongoing_residual_risk_area(poam_data) -> dict[str, str]:
	records = poam_records(poam_data)
	ongoing_records = [record for record in records if poam_status(record) == "Ongoing"]
	ongoing_count = len(ongoing_records)
	very_high_count = sum(1 for record in ongoing_records if is_very_high_risk_value(residual_risk_mitigation_value(record)))
	very_high_percent = (very_high_count / ongoing_count * 100) if ongoing_count else 0
	if very_high_percent > 25:
		risk = "High"
	elif very_high_percent > 10:
		risk = "Moderate"
	elif very_high_percent > 5:
		risk = "Low"
	else:
		risk = "Low"
	return {
		"risk": risk,
		"ongoing_count": str(ongoing_count),
		"very_high_count": str(very_high_count),
		"very_high_percent": f"{very_high_percent:.1f}%",
	}


def build_overall_poam_ongoing_residual_risk_rows(poam_data) -> list[dict[str, str]]:
	records = poam_records(poam_data)
	ongoing_records = [record for record in records if poam_status(record) == "Ongoing"]
	row_specs = [
		(
			"POAM Ongoing Very High Status",
			"Very High",
			"maxPOAMOngoingStatusVeryHighResidualLowRisk",
			"maxPOAMOngoingStatusVeryHighResidualMediumRisk",
		),
		(
			"POAM Ongoing High Status",
			"High",
			"maxPOAMOngoingStatusHighResidualLowRisk",
			"maxPOAMOngoingStatusHighResidualMediumRisk",
		),
		(
			"POAM Ongoing Moderate Status",
			"Moderate",
			"maxPOAMOngoingStatusModerateResidualLowRisk",
			"maxPOAMOngoingStatusModerateResidualMediumRisk",
		),
		(
			"POAM Ongoing Low Status",
			"Low",
			"maxPOAMOngoingStatusLowResidualLowRisk",
			"maxPOAMOngoingStatusLowResidualMediumRisk",
		),
		(
			"POAM Ongoing Very Low Status",
			"Very Low",
			"maxPOAMOngoingStatusVeryLowResidualLowRisk",
			"maxPOAMOngoingStatusVeryLowResidualMediumRisk",
		),
		(
			"POAM Residual Risk Not Set",
			"Not Set",
			"maxPOAMResidualRiskMitigationNotSetLowRisk",
			"maxPOAMResidualRiskMitigationNotSetMediumRisk",
		),
	]
	rows = []
	for title, residual_risk_level, low_risk_key, medium_risk_key in row_specs:
		count = sum(
			1
			for record in ongoing_records
			if normalize_residual_risk_level(residual_risk_mitigation_value(record)) == residual_risk_level
		)
		rows.append(
			{
				"title": title,
				"count": str(count),
				"risk": poam_status_risk_level(count, low_risk_key, medium_risk_key),
			}
		)
	return rows


def build_poam_office_organization_ongoing_risk_area(poam_data) -> dict[str, str]:
	records = poam_records(poam_data)
	ongoing_records = [record for record in records if poam_status(record) == "Ongoing"]
	ongoing_count = len(ongoing_records)
	empty_count = sum(1 for record in ongoing_records if is_empty_value(office_organization_value(record)))
	empty_percent = (empty_count / ongoing_count * 100) if ongoing_count else 0
	return {
		"risk": poam_office_organization_risk_level(empty_percent),
		"ongoing_count": str(ongoing_count),
		"empty_count": str(empty_count),
		"empty_percent": f"{empty_percent:.1f}%",
	}


def poam_office_organization_risk_level(empty_percent: float) -> str:
	low_risk_max = risk_setting_percent("maxPOAMOfficeEmptyPercentLowRisk")
	medium_risk_max = risk_setting_percent("maxPOAMOfficeEmptyPercentMediumRisk")
	if empty_percent <= low_risk_max:
		return "Low"
	if empty_percent <= medium_risk_max:
		return "Moderate"
	return "High"


def build_overall_poam_office_organization_risk_rows(poam_data) -> list[dict[str, str]]:
	records = poam_records(poam_data)
	ongoing_records = [record for record in records if poam_status(record) == "Ongoing"]
	ongoing_count = len(ongoing_records)
	empty_count = sum(1 for record in ongoing_records if is_empty_value(office_organization_value(record)))
	empty_percent = (empty_count / ongoing_count * 100) if ongoing_count else 0
	return [
		{
			"title": "POAM Office Organization Empty Percentage",
			"percentage": f"{empty_percent:.1f}%",
			"risk": poam_office_organization_risk_level(empty_percent),
		}
	]


def build_poam_false_positives_risk_area(poam_data) -> dict[str, str]:
	records = poam_records(poam_data)
	completed_records = [record for record in records if poam_status(record) == "Completed"]
	completed_count = len(completed_records)
	false_positive_count = sum(1 for record in completed_records if bool_value(record.get("falsePositive")))
	false_positive_percent = (false_positive_count / completed_count * 100) if completed_count else 0
	if false_positive_percent >= 50:
		risk = "High"
	elif false_positive_percent >= 20:
		risk = "Moderate"
	else:
		risk = "Low"
	return {
		"risk": risk,
		"completed_count": str(completed_count),
		"false_positive_count": str(false_positive_count),
		"false_positive_percent": f"{false_positive_percent:.1f}%",
	}


def poam_false_positive_risk_level(false_positive_percent: float) -> str:
	low_risk_max = risk_setting_percent("maxPOAMOngoingStatusFalsePositivePercentLowRisk")
	medium_risk_max = risk_setting_percent("maxPOAMOngoingStatusFalsePositivePercentMediumRisk")
	if false_positive_percent <= low_risk_max:
		return "Low"
	if false_positive_percent <= medium_risk_max:
		return "Medium"
	return "High"


def build_overall_poam_false_positives_risk_rows(poam_data) -> list[dict[str, str]]:
	records = poam_records(poam_data)
	ongoing_records = [record for record in records if poam_status(record) == "Ongoing"]
	ongoing_count = len(ongoing_records)
	false_positive_count = sum(1 for record in ongoing_records if bool_value(record.get("falsePositive")))
	false_positive_percent = (false_positive_count / ongoing_count * 100) if ongoing_count else 0
	return [
		{
			"title": "POAM Ongoing False Positive Percentage",
			"percentage": f"{false_positive_percent:.1f}%",
			"risk": poam_false_positive_risk_level(false_positive_percent),
		}
	]


def build_compliance_risk_area(arguments: list[str]) -> dict[str, str]:
	compliance_script = Path(__file__).resolve().parents[1] / "compliance" / COMPLIANCE_SCRIPT_NAME
	compliance_result = call_child_script_result(compliance_script, arguments)
	if compliance_result.returncode != 0:
		status_match = re.search(r"HTTP\s+(\d+)", compliance_result.stdout + compliance_result.stderr)
		return {
			"risk": "High",
			"status": "Not Generated",
			"http_status": status_match.group(1) if status_match else "Not 200",
			"data_found": "No",
			"compliance_id": "Unavailable",
		}
	compliance_data = parse_json_value_from_output_or_none(compliance_result.stdout)
	compliance_id = extract_compliance_id(compliance_data)
	if not compliance_data or not compliance_id:
		return {
			"risk": "High",
			"status": "Missing Compliance Data",
			"http_status": "200",
			"data_found": "No",
			"compliance_id": "Unavailable",
		}
	return {
		"risk": "Low",
		"status": "Compliance Generated",
		"http_status": "200",
		"data_found": "Yes",
		"compliance_id": compliance_id,
	}


def build_compliance_control_score_risk_area(arguments: list[str], compliance_risk_area: dict[str, str]) -> dict[str, str]:
	compliance_id = compliance_risk_area.get("compliance_id", "")
	if compliance_id in {"", "Unavailable"}:
		return {
			"risk": "High",
			"status": "Skipped; Compliance ID Unavailable",
			"record_count": "0",
			"percentage_count": "0",
			"both_zero_count": "0",
			"both_zero_percent": "0.0%",
			"average_open": "Unknown",
			"average_complete": "Unknown",
			"overall_compliance_risk_rows": build_overall_compliance_risk_rows(),
		}
	allcontrols_script = Path(__file__).resolve().parents[1] / "compliance" / COMPLIANCE_ALLCONTROLS_SCRIPT_NAME
	allcontrols_result = call_child_script_result(allcontrols_script, [*arguments, compliance_id])
	if allcontrols_result.returncode != 0:
		return {
			"risk": "High",
			"status": "Control Scores Unavailable",
			"record_count": "0",
			"percentage_count": "0",
			"both_zero_count": "0",
			"both_zero_percent": "0.0%",
			"average_open": "Unknown",
			"average_complete": "Unknown",
			"overall_compliance_risk_rows": build_overall_compliance_risk_rows(),
		}
	control_score_data = parse_json_value_from_output_or_none(allcontrols_result.stdout)
	records = control_score_records(control_score_data)
	percentage_pairs = []
	for record in records:
		percentage_open = percentage_value(record, ["percentageOpen", "percentOpen", "openPercentage"])
		percentage_complete = percentage_value(record, ["percentageComplete", "percentComplete", "completionPercentage"])
		if percentage_open is None or percentage_complete is None:
			continue
		percentage_pairs.append((percentage_open, percentage_complete))
	if not records or not percentage_pairs:
		return {
			"risk": "High",
			"status": "No Control Score Percentages Found",
			"record_count": str(len(records)),
			"percentage_count": str(len(percentage_pairs)),
			"both_zero_count": "0",
			"both_zero_percent": "0.0%",
			"average_open": "Unknown",
			"average_complete": "Unknown",
			"overall_compliance_risk_rows": build_overall_compliance_risk_rows(),
		}
	both_zero_count = sum(1 for percentage_open, percentage_complete in percentage_pairs if percentage_open == 0 and percentage_complete == 0)
	both_zero_percent = both_zero_count / len(percentage_pairs) * 100
	average_open = sum(percentage_open for percentage_open, _ in percentage_pairs) / len(percentage_pairs)
	average_complete = sum(percentage_complete for _, percentage_complete in percentage_pairs) / len(percentage_pairs)
	if both_zero_count > (len(percentage_pairs) / 2):
		risk = "High"
	elif average_open > average_complete:
		risk = "High"
	elif average_complete < 50:
		risk = "High"
	elif average_complete < 75:
		risk = "Moderate"
	else:
		risk = "Low"
	return {
		"risk": risk,
		"status": "Control Scores Evaluated",
		"record_count": str(len(records)),
		"percentage_count": str(len(percentage_pairs)),
		"both_zero_count": str(both_zero_count),
		"both_zero_percent": f"{both_zero_percent:.1f}%",
		"average_open": f"{average_open:.1f}%",
		"average_complete": f"{average_complete:.1f}%",
		"overall_compliance_risk_rows": build_overall_compliance_risk_rows(percentage_pairs),
	}


def load_ppsm_data(arguments: list[str]):
	ppsm_script = Path(__file__).resolve().parents[1] / "ports-protocols-services" / PPSM_SCRIPT_NAME
	ppsm_result = call_child_script_result(ppsm_script, arguments)
	if ppsm_result.returncode != 0:
		return None
	return parse_json_value_from_output_or_none(ppsm_result.stdout)


def load_readiness_score_data(arguments: list[str]):
	readiness_script = Path(__file__).resolve().parents[1] / "system-package" / READINESS_SCORE_SCRIPT_NAME
	readiness_result = call_child_script_result(readiness_script, arguments)
	if readiness_result.returncode != 0:
		return None
	return parse_json_value_from_output_or_none(readiness_result.stdout)


def load_readiness_settings_data(arguments: list[str]):
	readiness_settings_script = Path(__file__).resolve().parents[1] / "system-package" / READINESS_SETTINGS_SCRIPT_NAME
	readiness_settings_result = call_child_script_result(readiness_settings_script, arguments)
	if readiness_settings_result.returncode != 0:
		return None
	return parse_json_value_from_output_or_none(readiness_settings_result.stdout)


def load_approved_pps_listing(arguments: list[str]) -> dict:
	approved_pps_script = Path(__file__).resolve().parents[1] / "ports-protocols-services" / APPROVED_PPS_SCRIPT_NAME
	approved_pps_result = call_child_script_result(approved_pps_script, arguments)
	if approved_pps_result.returncode != 0:
		status_match = re.search(r"HTTP\s+(\d+)", approved_pps_result.stdout + approved_pps_result.stderr)
		return {
			"api_status": status_match.group(1) if status_match else "Not 200",
			"data": None,
			"source": "System Package Approved PPS",
		}
	approved_pps_data = parse_json_value_from_output_or_none(approved_pps_result.stdout)
	if approved_pps_items(approved_pps_data):
		return {
			"api_status": "200 OK",
			"data": approved_pps_data,
			"source": "System Package Approved PPS",
		}

	general_approved_pps_script = Path(__file__).resolve().parents[1] / "ports-protocols-services" / GENERAL_APPROVED_PPS_SCRIPT_NAME
	general_approved_pps_result = call_child_script_result(general_approved_pps_script, arguments[:3])
	if general_approved_pps_result.returncode != 0:
		status_match = re.search(r"HTTP\s+(\d+)", general_approved_pps_result.stdout + general_approved_pps_result.stderr)
		return {
			"api_status": status_match.group(1) if status_match else "Not 200",
			"data": None,
			"source": "General Approved PPS Fallback",
		}
	return {
		"api_status": "200 OK",
		"data": parse_json_value_from_output_or_none(general_approved_pps_result.stdout),
		"source": "General Approved PPS Fallback",
	}


def approved_pps_items(approved_pps_data) -> list:
	if isinstance(approved_pps_data, list):
		return approved_pps_data
	if not isinstance(approved_pps_data, dict):
		return []
	for key in ["records", "items", "data", "results", "approvedPps", "approvedPPS", "approvedpps", "pps"]:
		value = approved_pps_data.get(key)
		if isinstance(value, list):
			return value
	return [approved_pps_data] if approved_pps_data else []


def build_pps_listing_risk_area(approved_pps_listing: dict | None) -> dict[str, str]:
	if not isinstance(approved_pps_listing, dict):
		return {
			"risk": "High",
			"status": "Approved PPS Unavailable",
			"http_status": "Not 200",
			"approved_count": "0",
			"source": "Unavailable",
		}
	api_status = safe_text(approved_pps_listing.get("api_status")) or "Not 200"
	source = safe_text(approved_pps_listing.get("source")) or "Unknown"
	approved_pps_data = approved_pps_listing.get("data")
	if api_status != "200 OK":
		return {
			"risk": "High",
			"status": "Approved PPS API Failed",
			"http_status": api_status,
			"approved_count": "0",
			"source": source,
		}
	items = approved_pps_items(approved_pps_data)
	if not items:
		return {
			"risk": "High",
			"status": "No Approved PPS Returned",
			"http_status": api_status,
			"approved_count": "0",
			"source": source,
		}
	return {
		"risk": "Low",
		"status": "Approved PPS Returned",
		"http_status": api_status,
		"approved_count": str(len(items)),
		"source": source,
	}


def load_checklist_missing_data(arguments: list[str]):
	missingdata_script = Path(__file__).resolve().parents[1] / "checklist" / CHECKLIST_MISSINGDATA_SCRIPT_NAME
	missingdata_result = call_child_script_result(missingdata_script, arguments)
	if missingdata_result.returncode != 0:
		return None
	return parse_json_value_from_output_or_none(missingdata_result.stdout)


def checklist_missing_data_items(missingdata) -> list:
	if isinstance(missingdata, list):
		return missingdata
	if not isinstance(missingdata, dict):
		return []
	for key in ["records", "items", "data", "results", "missingData", "missingdata"]:
		value = missingdata.get(key)
		if isinstance(value, list):
			return value
		if isinstance(value, dict):
			return [value] if value else []
	return [missingdata] if missingdata else []


def build_checklist_missing_data_risk_area(missingdata) -> dict[str, str]:
	if missingdata is None:
		return {
			"risk": "High",
			"status": "Missing Data Unavailable",
			"returned_count": "0",
		}
	items = checklist_missing_data_items(missingdata)
	returned_count = len(items)
	risk = "High" if returned_count else "Low"
	status = "Missing Data Returned" if returned_count else "Empty Array Returned"
	return {
		"risk": risk,
		"status": status,
		"returned_count": str(returned_count),
	}


def build_pps_boundaries_risk_area(ppsm_data) -> dict[str, str]:
	records = ppsm_records(ppsm_data)
	in_crossings = 0
	out_crossings = 0
	boundary_record_count = 0
	for record in records:
		record_has_boundary = False
		for boundary_number in range(1, 9):
			if ppsm_boundary_value(record, boundary_number, "In"):
				in_crossings += 1
				record_has_boundary = True
			if ppsm_boundary_value(record, boundary_number, "Out"):
				out_crossings += 1
				record_has_boundary = True
		if record_has_boundary:
			boundary_record_count += 1
	total_crossings = in_crossings + out_crossings
	if total_crossings == 0:
		risk = "Low"
	elif total_crossings > 10:
		risk = "High"
	else:
		risk = "Medium"
	return {
		"risk": risk,
		"record_count": str(len(records)),
		"boundary_record_count": str(boundary_record_count),
		"in_crossings": str(in_crossings),
		"out_crossings": str(out_crossings),
		"total_crossings": str(total_crossings),
	}


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
			"open": score_value(score, "totalOpen"),
			"not_reviewed": score_value(score, "totalNotReviewed"),
			"not_a_finding": score_value(score, "totalNotAFinding"),
			"not_applicable": score_value(score, "totalNotApplicable"),
		},
	]


def risk_setting_count(key: str) -> int:
	return numeric_count(safe_text(RISK_SETTINGS.get(key, 0)))


def checklist_risk_level(count: int, low_risk_key: str, medium_risk_key: str) -> str:
	low_risk_max = risk_setting_count(low_risk_key)
	medium_risk_max = risk_setting_count(medium_risk_key)
	if count <= low_risk_max:
		return "Low"
	if count <= medium_risk_max:
		return "Medium"
	return "High"


def build_checklist_risk_summary_rows(system_package: dict) -> list[dict[str, str]]:
	score = system_package.get("score", {}) if isinstance(system_package, dict) else {}
	if not isinstance(score, dict):
		score = {}
	row_specs = [
		(
			"Open Cat 1 High Checklist Vulnerabilities",
			"totalCat1Open",
			"maxChecklistOpenHighVulnLowRisk",
			"maxChecklistOpenHighVulnMediumRisk",
		),
		(
			"Open Cat 2 High Checklist Vulnerabilities",
			"totalCat2Open",
			"maxChecklistOpenMediumVulnLowRisk",
			"maxChecklistOpenMediumVulnMediumRisk",
		),
		(
			"Open Cat 3 High Checklist Vulnerabilities",
			"totalCat3Open",
			"maxChecklistOpenLowVulnLowRisk",
			"maxChecklistOpenLowVulnMediumRisk",
		),
		(
			"Not Reviewed Checklist Vulnerabilities",
			"totalNotReviewed",
			"maxChecklistNotReviewedHighVulnLowRisk",
			"maxChecklistNotReviewedHighVulnMediumRisk",
		),
	]
	rows = []
	for title, score_key, low_risk_key, medium_risk_key in row_specs:
		count = numeric_count(score_value(score, score_key))
		rows.append(
			{
				"title": title,
				"score_key": score_key,
				"count": str(count),
				"low_risk_max": str(risk_setting_count(low_risk_key)),
				"medium_risk_max": str(risk_setting_count(medium_risk_key)),
				"risk": checklist_risk_level(count, low_risk_key, medium_risk_key),
			}
		)
	return rows


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


def patch_vulnerability_risk_level(count: int, low_risk_key: str, medium_risk_key: str) -> str:
	low_risk_max = risk_setting_count(low_risk_key)
	medium_risk_max = risk_setting_count(medium_risk_key)
	if count <= low_risk_max:
		return "Low"
	if count <= medium_risk_max:
		return "Medium"
	return "High"


def build_patch_vulnerability_risk_summary_rows(system_package: dict) -> list[dict[str, str]]:
	patch_score = system_package.get("patchScore", {}) if isinstance(system_package, dict) else {}
	if not isinstance(patch_score, dict):
		patch_score = {}
	row_specs = [
		(
			"Critical Open Patch Vulnerabilities",
			"totalCriticalOpen",
			"maxPatchOpenCriticalVulnLowRisk",
			"maxPatchOpenCriticalVulnMediumRisk",
		),
		(
			"High Open Patch Vulnerabilities",
			"totalHighOpen",
			"maxPatchOpenHighVulnLowRisk",
			"maxPatchOpenHighVulnMediumRisk",
		),
		(
			"Medium Open Patch Vulnerabilities",
			"totalMediumOpen",
			"maxPatchOpenMediumVulnLowRisk",
			"maxPatchOpenMediumVulnMediumRisk",
		),
		(
			"Low Open Patch Vulnerabilities",
			"totalLowOpen",
			"maxPatchOpenLowVulnLowRisk",
			"maxPatchOpenLowVulnMediumRisk",
		),
	]
	rows = []
	for title, score_key, low_risk_key, medium_risk_key in row_specs:
		count = numeric_count(score_value(patch_score, score_key))
		rows.append(
			{
				"title": title,
				"score_key": score_key,
				"count": str(count),
				"low_risk_max": str(risk_setting_count(low_risk_key)),
				"medium_risk_max": str(risk_setting_count(medium_risk_key)),
				"risk": patch_vulnerability_risk_level(count, low_risk_key, medium_risk_key),
			}
		)
	return rows


def build_cyber_readiness_score_rows(readiness_score_data, system_package: dict, readiness_settings_data=None) -> list[dict[str, str]]:
	checklist_score = readiness_value(readiness_score_data, ["totalChecklistCyberReadiness"])
	patch_score = readiness_value(readiness_score_data, ["totalPatchCyberReadiness"])
	checklist_score_number = readiness_score_number(checklist_score)
	patch_score_number = readiness_score_number(patch_score)
	checklist_label = readiness_label_with_critical_allowance("Checklist", checklist_score_number, readiness_score_data, readiness_settings_data, system_package) if checklist_score_number is not None else None
	patch_label = readiness_label_with_critical_allowance("Patch", patch_score_number, readiness_score_data, readiness_settings_data, system_package) if patch_score_number is not None else None
	rows = []
	for row in [
		build_cyber_readiness_score_row("Checklist", checklist_score, checklist_label, readiness_settings_data),
		build_cyber_readiness_score_row("Patch", patch_score, patch_label, readiness_settings_data),
	]:
		if row is not None:
			rows.append(row)
	return rows


def build_risk_settings_rows() -> list[dict[str, str]]:
	return [{"key": key, "value": safe_text(value)} for key, value in RISK_SETTINGS.items()]


def build_table_of_contents_rows() -> list[dict[str, str]]:
	rows = []
	page_number = 1
	same_page_as_previous = {"compliance-control-score", "pps-listing"}
	for section in REPORT_SECTIONS:
		if section["anchor"] not in same_page_as_previous:
			page_number += 1
		rows.append({"title": section["title"], "anchor": section["anchor"], "page_number": str(page_number)})
	return rows


def build_system_description(system_package: dict, options: dict[str, str]) -> str:
	description = first_json_value(
		system_package,
		{"description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription"},
	)
	if description:
		return description
	return optional_value(options, "description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription")


def build_system_title(system_package: dict, options: dict[str, str]) -> str:
	title = first_json_value(
		system_package,
		{"title", "systemTitle", "system_title", "systemName", "name"},
	)
	if title:
		return title
	return optional_value(options, "title", "systemTitle", "system_title", "systemName", "name")


def report_title_for_system(system_title: str) -> str:
	return f"{safe_text(system_title).strip() or 'Unknown'} Risk Profiler"


def build_report_data(system_key: str, options: dict[str, str], system_package: dict, poam_data, compliance_risk_area: dict[str, str], compliance_control_score_risk_area: dict[str, str], ppsm_data=None, checklist_missing_data=None, approved_pps_listing=None, readiness_score_data=None, readiness_settings_data=None) -> dict[str, str]:
	system_title = build_system_title(system_package, options)
	return {
		"system_key": system_key,
		"system_title": system_title,
		"report_title": report_title_for_system(system_title),
		"system_description": build_system_description(system_package, options),
		"framework_title": framework_value(system_package, options, {"frameworkTitle", "frameworktitle", "framework_title"}, "frameworkTitle", "frameworktitle", "framework_title"),
		"framework_version": framework_value(system_package, options, {"frameworkVersion", "frameworkversion", "framework_version"}, "frameworkVersion", "frameworkversion", "framework_version"),
		"table_of_contents_rows": build_table_of_contents_rows(),
		"cat_status_rows": build_cat_status_rows(system_package),
		"checklist_risk_summary_rows": build_checklist_risk_summary_rows(system_package),
		"cyber_readiness_score_rows": build_cyber_readiness_score_rows(readiness_score_data, system_package, readiness_settings_data),
		"cyber_readiness_settings_rows": build_cyber_readiness_settings_rows(readiness_settings_data),
		"checklist_missing_data_risk_area": build_checklist_missing_data_risk_area(checklist_missing_data),
		"patch_vulnerability_risk_rows": build_patch_vulnerability_risk_rows(system_package),
		"patch_vulnerability_risk_summary_rows": build_patch_vulnerability_risk_summary_rows(system_package),
		"poam_risk_area": build_poam_risk_area(poam_data),
		"poam_residual_risk_area": build_poam_residual_risk_area(poam_data),
		"poam_ongoing_risk_area": build_poam_ongoing_risk_area(poam_data),
		"overall_poam_status_rows": build_overall_poam_status_rows(poam_data),
		"poam_ongoing_residual_risk_area": build_poam_ongoing_residual_risk_area(poam_data),
		"overall_poam_ongoing_residual_risk_rows": build_overall_poam_ongoing_residual_risk_rows(poam_data),
		"poam_office_organization_ongoing_risk_area": build_poam_office_organization_ongoing_risk_area(poam_data),
		"overall_poam_office_organization_risk_rows": build_overall_poam_office_organization_risk_rows(poam_data),
		"poam_false_positives_risk_area": build_poam_false_positives_risk_area(poam_data),
		"overall_poam_false_positives_risk_rows": build_overall_poam_false_positives_risk_rows(poam_data),
		"compliance_risk_area": compliance_risk_area,
		"compliance_control_score_risk_area": compliance_control_score_risk_area,
		"overall_compliance_risk_rows": compliance_control_score_risk_area.get("overall_compliance_risk_rows", build_overall_compliance_risk_rows()),
		"pps_boundaries_risk_area": build_pps_boundaries_risk_area(ppsm_data),
		"pps_listing_risk_area": build_pps_listing_risk_area(approved_pps_listing),
		"risk_settings_rows": build_risk_settings_rows(),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
		"source_script": Path(__file__).name,
	}


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, str]) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	class SectionPageNumberDocTemplate(SimpleDocTemplate):
		def __init__(self, *args, **kwargs):
			super().__init__(*args, **kwargs)
			self.section_page_numbers = {}

		def afterFlowable(self, flowable):
			anchor = getattr(flowable, "_toc_anchor", None)
			if anchor and anchor not in self.section_page_numbers:
				self.section_page_numbers[anchor] = self.page

	styles = getSampleStyleSheet()
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"
	readiness_score_style = styles["BodyText"].clone("ReadinessScore")
	readiness_score_style.alignment = 2
	readiness_settings_style = styles["BodyText"].clone("ReadinessSettings")
	readiness_settings_style.alignment = 0
	subheading_style = styles["BodyText"].clone("RiskProfilerSubheading")
	subheading_style.fontName = "Helvetica-Bold"
	subheading_style.fontSize = 10
	subheading_style.leading = 12
	contents_link_style = styles["BodyText"].clone("ContentsLink")
	contents_link_style.fontSize = 9
	contents_link_style.leading = 11
	contents_link_style.textColor = colors.blue
	anchor_marker_style = styles["Normal"].clone("AnchorMarker")
	anchor_marker_style.fontSize = 0
	anchor_marker_style.leading = 0
	poam_section_gap = 14
	poam_heading_gap = 8

	def anchored_heading(title: str, anchor: str):
		paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', styles["Heading1"])
		paragraph._toc_anchor = anchor
		return paragraph

	def anchored_subheading(title: str, anchor: str):
		paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', styles["Heading2"])
		paragraph._toc_anchor = anchor
		return paragraph

	def anchor_marker(anchor: str):
		paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>', anchor_marker_style)
		paragraph._toc_anchor = anchor
		return paragraph

	def contents_link(title: str, anchor: str):
		return Paragraph(f'<a href="#{html.escape(anchor, quote=True)}" color="blue">{html.escape(title)}</a>', contents_link_style)

	def readiness_label_from_text(value: str) -> str:
		return safe_text(value).split("(", 1)[0].strip()

	def readiness_label_cell(value: str, label: str = "", cell_style=None):
		cell_style = cell_style or readiness_score_style
		value_text = "<br/>".join(html.escape(line) for line in safe_text(value).splitlines())
		label_text = label or readiness_label_from_text(value)
		if label_text == "Excellent":
			return Paragraph(f'<font color="white" backColor="#0000FF">{value_text}</font>', cell_style)
		if label_text == "Good":
			return Paragraph(f'<font color="white" backColor="#008000">{value_text}</font>', cell_style)
		if label_text == "Poor":
			return Paragraph(f'<font color="black" backColor="#FFFF00">{value_text}</font>', cell_style)
		if label_text == "Fail":
			return Paragraph(f'<font color="white" backColor="#800000">{value_text}</font>', cell_style)
		return Paragraph(value_text, cell_style)

	def readiness_score_cell(row: dict[str, str]):
		return readiness_label_cell(row["score"], row.get("grade_prefix", row.get("label", "")))

	def readiness_settings_category_cell(row: dict[str, str]):
		if row.get("grade_prefix"):
			return readiness_label_cell(row["category"], row["grade_prefix"], readiness_settings_style)
		return Paragraph(row["category"], styles["BodyText"])

	def build_contents_table(contents_rows):
		contents_table_rows = [[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)]]
		contents_table_rows.extend(
			[
				contents_link(row["title"], row["anchor"]),
				row["page_number"],
			]
			for row in contents_rows
		)
		contents_table = Table(contents_table_rows, hAlign="LEFT", colWidths=[380, 90])
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
		return contents_table

	contents_table = build_contents_table(report_data["table_of_contents_rows"])
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
	checklist_risk_summary_table = Table(
		[
			[
				Paragraph("Checklist Risk Type", table_header_style),
				Paragraph("Count", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["count"],
					row["risk"],
				]
				for row in report_data["checklist_risk_summary_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[330, 70, 70],
	)
	checklist_risk_summary_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["checklist_risk_summary_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Medium":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		checklist_risk_summary_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	checklist_risk_summary_table.setStyle(TableStyle(checklist_risk_summary_style))
	checklist_missing_data_risk_area = report_data["checklist_missing_data_risk_area"]
	checklist_missing_data_risk_table = Table(
		[
			["Metric", "Value"],
			["Status", checklist_missing_data_risk_area["status"]],
			["Returned Missing Data Items", checklist_missing_data_risk_area["returned_count"]],
			["Risk", checklist_missing_data_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[260, 180],
	)
	checklist_missing_data_risk_color = colors.red
	checklist_missing_data_risk_text_color = colors.white
	if checklist_missing_data_risk_area["risk"] == "Low":
		checklist_missing_data_risk_color = colors.yellow
		checklist_missing_data_risk_text_color = colors.black
	checklist_missing_data_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 3), (1, 3), checklist_missing_data_risk_color),
				("TEXTCOLOR", (1, 3), (1, 3), checklist_missing_data_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	cyber_readiness_score_table = Table(
		[
			[
				Paragraph("Readiness", table_header_style),
				Paragraph("Score", table_header_style),
			],
			*[
				[
					Paragraph(row["readiness"], styles["BodyText"]),
					readiness_score_cell(row),
				]
				for row in report_data["cyber_readiness_score_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[220, 180],
	)
	cyber_readiness_score_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	cyber_readiness_score_table.setStyle(TableStyle(cyber_readiness_score_style))
	cyber_readiness_settings_table = Table(
		[
			[
				Paragraph("Category", table_header_style),
				Paragraph("Setting", table_header_style),
			],
			*[
				[
					readiness_settings_category_cell(row),
					readiness_label_cell(row["setting"], cell_style=readiness_settings_style),
				]
				for row in report_data["cyber_readiness_settings_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[210, 190],
	)
	cyber_readiness_settings_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (-1, -1), "LEFT"),
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
	patch_vulnerability_risk_summary_table = Table(
		[
			[
				Paragraph("Patch Vulnerability Type", table_header_style),
				Paragraph("Open", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["count"],
					row["risk"],
				]
				for row in report_data["patch_vulnerability_risk_summary_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[330, 70, 70],
	)
	patch_vulnerability_risk_summary_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["patch_vulnerability_risk_summary_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Medium":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		patch_vulnerability_risk_summary_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	patch_vulnerability_risk_summary_table.setStyle(TableStyle(patch_vulnerability_risk_summary_style))
	poam_risk_area = report_data["poam_risk_area"]
	poam_risk_table = Table(
		[
			["Metric", "Value"],
			["Ongoing POAM Records", poam_risk_area["total_count"]],
			["Scheduled Completion Dates", poam_risk_area["scheduled_count"]],
			["Not Past Due Scheduled Completion Dates", poam_risk_area["not_past_due_count"]],
			["Past Due Scheduled Completion Dates", poam_risk_area["past_due_count"]],
		],
		hAlign="LEFT",
		colWidths=[260, 180],
	)
	poam_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 4), (1, 4), colors.red),
				("TEXTCOLOR", (1, 4), (1, 4), colors.white),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	poam_residual_risk_area = report_data["poam_residual_risk_area"]
	poam_residual_risk_table = Table(
		[
			["Metric", "Value"],
			["Total POAM Records", poam_residual_risk_area["total_count"]],
			["Empty Resulting Residual Risk Mitigation Fields", poam_residual_risk_area["empty_count"]],
			["Empty Percentage", poam_residual_risk_area["empty_percent"]],
			["Risk", poam_residual_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[300, 140],
	)
	residual_risk_color = colors.red
	residual_risk_text_color = colors.white
	if poam_residual_risk_area["risk"] == "Moderate":
		residual_risk_color = colors.orange
		residual_risk_text_color = colors.black
	elif poam_residual_risk_area["risk"] == "Low":
		residual_risk_color = colors.yellow
		residual_risk_text_color = colors.black
	poam_residual_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 4), (1, 4), residual_risk_color),
				("TEXTCOLOR", (1, 4), (1, 4), residual_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	poam_ongoing_risk_area = report_data["poam_ongoing_risk_area"]
	poam_ongoing_risk_table = Table(
		[
			["Metric", "Value"],
			["Ongoing Items", poam_ongoing_risk_area["ongoing_count"]],
			["Accepted Items", poam_ongoing_risk_area["accepted_count"]],
			["Accepted Percentage of Ongoing Items", poam_ongoing_risk_area["accepted_percent"]],
			["Risk", poam_ongoing_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[300, 140],
	)
	ongoing_risk_color = colors.red
	ongoing_risk_text_color = colors.white
	if poam_ongoing_risk_area["risk"] == "Moderate":
		ongoing_risk_color = colors.orange
		ongoing_risk_text_color = colors.black
	elif poam_ongoing_risk_area["risk"] == "Low":
		ongoing_risk_color = colors.yellow
		ongoing_risk_text_color = colors.black
	poam_ongoing_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 4), (1, 4), ongoing_risk_color),
				("TEXTCOLOR", (1, 4), (1, 4), ongoing_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	overall_poam_status_table = Table(
		[
			[
				Paragraph("POAM Status Type", table_header_style),
				Paragraph("Count", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["count"],
					row["risk"],
				]
				for row in report_data["overall_poam_status_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[260, 110, 70],
	)
	overall_poam_status_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["overall_poam_status_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Medium":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		overall_poam_status_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	overall_poam_status_table.setStyle(TableStyle(overall_poam_status_style))
	poam_ongoing_residual_risk_area = report_data["poam_ongoing_residual_risk_area"]
	poam_ongoing_residual_risk_table = Table(
		[
			["Metric", "Value"],
			["Ongoing Items", poam_ongoing_residual_risk_area["ongoing_count"]],
			["Very High Resulting Residual Risk Mitigation Items", poam_ongoing_residual_risk_area["very_high_count"]],
			["Very High Percentage of Ongoing Items", poam_ongoing_residual_risk_area["very_high_percent"]],
			["Risk", poam_ongoing_residual_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[330, 120],
	)
	ongoing_residual_risk_color = colors.red
	ongoing_residual_risk_text_color = colors.white
	if poam_ongoing_residual_risk_area["risk"] == "Moderate":
		ongoing_residual_risk_color = colors.orange
		ongoing_residual_risk_text_color = colors.black
	elif poam_ongoing_residual_risk_area["risk"] == "Low":
		ongoing_residual_risk_color = colors.yellow
		ongoing_residual_risk_text_color = colors.black
	poam_ongoing_residual_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 4), (1, 4), ongoing_residual_risk_color),
				("TEXTCOLOR", (1, 4), (1, 4), ongoing_residual_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	overall_poam_ongoing_residual_risk_table = Table(
		[
			[
				Paragraph("POAM Residual Risk Type", table_header_style),
				Paragraph("Count", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["count"],
					row["risk"],
				]
				for row in report_data["overall_poam_ongoing_residual_risk_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[260, 90, 70],
	)
	overall_poam_ongoing_residual_risk_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["overall_poam_ongoing_residual_risk_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Medium":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		overall_poam_ongoing_residual_risk_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	overall_poam_ongoing_residual_risk_table.setStyle(TableStyle(overall_poam_ongoing_residual_risk_style))
	poam_office_organization_ongoing_risk_area = report_data["poam_office_organization_ongoing_risk_area"]
	poam_office_organization_ongoing_risk_table = Table(
		[
			["Metric", "Value"],
			["Ongoing Items", poam_office_organization_ongoing_risk_area["ongoing_count"]],
			["Empty Office Organization Items", poam_office_organization_ongoing_risk_area["empty_count"]],
			["Empty Percentage of Ongoing Items", poam_office_organization_ongoing_risk_area["empty_percent"]],
			["Risk", poam_office_organization_ongoing_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[300, 140],
	)
	office_organization_risk_color = colors.red
	office_organization_risk_text_color = colors.white
	if poam_office_organization_ongoing_risk_area["risk"] == "Moderate":
		office_organization_risk_color = colors.orange
		office_organization_risk_text_color = colors.black
	elif poam_office_organization_ongoing_risk_area["risk"] == "Low":
		office_organization_risk_color = colors.yellow
		office_organization_risk_text_color = colors.black
	poam_office_organization_ongoing_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 4), (1, 4), office_organization_risk_color),
				("TEXTCOLOR", (1, 4), (1, 4), office_organization_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	overall_poam_office_organization_risk_table = Table(
		[
			[
				Paragraph("POAM Office Organization Risk Type", table_header_style),
				Paragraph("Percentage", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["percentage"],
					row["risk"],
				]
				for row in report_data["overall_poam_office_organization_risk_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[290, 90, 70],
	)
	overall_poam_office_organization_risk_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["overall_poam_office_organization_risk_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Moderate":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		overall_poam_office_organization_risk_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	overall_poam_office_organization_risk_table.setStyle(TableStyle(overall_poam_office_organization_risk_style))
	poam_false_positives_risk_area = report_data["poam_false_positives_risk_area"]
	poam_false_positives_risk_table = Table(
		[
			["Metric", "Value"],
			["Completed Items", poam_false_positives_risk_area["completed_count"]],
			["False Positive Completed Items", poam_false_positives_risk_area["false_positive_count"]],
			["False Positive Percentage of Completed Items", poam_false_positives_risk_area["false_positive_percent"]],
			["Risk", poam_false_positives_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[320, 130],
	)
	false_positives_risk_color = colors.red
	false_positives_risk_text_color = colors.white
	if poam_false_positives_risk_area["risk"] == "Moderate":
		false_positives_risk_color = colors.orange
		false_positives_risk_text_color = colors.black
	elif poam_false_positives_risk_area["risk"] == "Low":
		false_positives_risk_color = colors.yellow
		false_positives_risk_text_color = colors.black
	poam_false_positives_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 4), (1, 4), false_positives_risk_color),
				("TEXTCOLOR", (1, 4), (1, 4), false_positives_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	overall_poam_false_positives_risk_table = Table(
		[
			[
				Paragraph("POAM False Positives Risk Type", table_header_style),
				Paragraph("Percentage", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["percentage"],
					row["risk"],
				]
				for row in report_data["overall_poam_false_positives_risk_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[290, 90, 70],
	)
	overall_poam_false_positives_risk_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["overall_poam_false_positives_risk_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Medium":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		overall_poam_false_positives_risk_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	overall_poam_false_positives_risk_table.setStyle(TableStyle(overall_poam_false_positives_risk_style))
	compliance_risk_area = report_data["compliance_risk_area"]
	compliance_risk_table = Table(
		[
			["Metric", "Value"],
			["Status", compliance_risk_area["status"]],
			["Compliance Data Found", compliance_risk_area["data_found"]],
			["Risk", compliance_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[250, 240],
	)
	compliance_risk_color = colors.red if compliance_risk_area["risk"] == "High" else colors.yellow
	compliance_risk_text_color = colors.white if compliance_risk_area["risk"] == "High" else colors.black
	compliance_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 3), (1, 3), compliance_risk_color),
				("TEXTCOLOR", (1, 3), (1, 3), compliance_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	overall_compliance_risk_table = Table(
		[
			[
				Paragraph("Compliance Risk Type", table_header_style),
				Paragraph("Value", table_header_style),
				Paragraph("Risk", table_header_style),
			],
			*[
				[
					Paragraph(row["title"], styles["BodyText"]),
					row["value"],
					row["risk"],
				]
				for row in report_data["overall_compliance_risk_rows"]
			],
		],
		hAlign="LEFT",
		colWidths=[260, 90, 90],
	)
	overall_compliance_risk_style = [
		("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
		("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
		("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
		("ALIGN", (0, 0), (-1, 0), "CENTER"),
		("ALIGN", (1, 1), (-1, -1), "RIGHT"),
		("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
	]
	for row_index, row in enumerate(report_data["overall_compliance_risk_rows"], start=1):
		risk_color = colors.red
		risk_text_color = colors.white
		if row["risk"] == "Medium":
			risk_color = colors.orange
			risk_text_color = colors.black
		elif row["risk"] == "Low":
			risk_color = colors.yellow
			risk_text_color = colors.black
		overall_compliance_risk_style.extend(
			[
				("BACKGROUND", (2, row_index), (2, row_index), risk_color),
				("TEXTCOLOR", (2, row_index), (2, row_index), risk_text_color),
			]
		)
	overall_compliance_risk_table.setStyle(TableStyle(overall_compliance_risk_style))
	compliance_control_score_risk_area = report_data["compliance_control_score_risk_area"]
	compliance_control_score_risk_table = Table(
		[
			["Metric", "Value"],
			["Status", compliance_control_score_risk_area["status"]],
			["Number of Controls", compliance_control_score_risk_area["record_count"]],
			["Number of Controls with no Compliance Records", compliance_control_score_risk_area["both_zero_count"]],
			["Percentage of Controls with no Compliance Records", compliance_control_score_risk_area["both_zero_percent"]],
			["Risk", compliance_control_score_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[260, 180],
	)
	compliance_control_score_risk_color = colors.red
	compliance_control_score_risk_text_color = colors.white
	if compliance_control_score_risk_area["risk"] == "Moderate":
		compliance_control_score_risk_color = colors.orange
		compliance_control_score_risk_text_color = colors.black
	elif compliance_control_score_risk_area["risk"] == "Low":
		compliance_control_score_risk_color = colors.yellow
		compliance_control_score_risk_text_color = colors.black
	compliance_control_score_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 5), (1, 5), compliance_control_score_risk_color),
				("TEXTCOLOR", (1, 5), (1, 5), compliance_control_score_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	pps_boundaries_risk_area = report_data["pps_boundaries_risk_area"]
	pps_boundaries_risk_table = Table(
		[
			["Metric", "Value"],
			["PPS Records Checked", pps_boundaries_risk_area["record_count"]],
			["Records with Boundaries", pps_boundaries_risk_area["boundary_record_count"]],
			["Boundary In Crossings", pps_boundaries_risk_area["in_crossings"]],
			["Boundary Out Crossings", pps_boundaries_risk_area["out_crossings"]],
			["Total Boundary Crossings", pps_boundaries_risk_area["total_crossings"]],
			["Risk", pps_boundaries_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[260, 180],
	)
	pps_boundaries_risk_color = colors.red
	pps_boundaries_risk_text_color = colors.white
	if pps_boundaries_risk_area["risk"] == "Medium":
		pps_boundaries_risk_color = colors.orange
		pps_boundaries_risk_text_color = colors.black
	elif pps_boundaries_risk_area["risk"] == "Low":
		pps_boundaries_risk_color = colors.yellow
		pps_boundaries_risk_text_color = colors.black
	pps_boundaries_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 6), (1, 6), pps_boundaries_risk_color),
				("TEXTCOLOR", (1, 6), (1, 6), pps_boundaries_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	pps_listing_risk_area = report_data["pps_listing_risk_area"]
	pps_listing_risk_table = Table(
		[
			["Metric", "Value"],
			["Status", pps_listing_risk_area["status"]],
			["Approved PPS Items", pps_listing_risk_area["approved_count"]],
			["Risk", pps_listing_risk_area["risk"]],
		],
		hAlign="LEFT",
		colWidths=[260, 180],
	)
	pps_listing_risk_color = colors.red
	pps_listing_risk_text_color = colors.white
	if pps_listing_risk_area["risk"] == "Low":
		pps_listing_risk_color = colors.yellow
		pps_listing_risk_text_color = colors.black
	pps_listing_risk_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
				("BACKGROUND", (1, 3), (1, 3), pps_listing_risk_color),
				("TEXTCOLOR", (1, 3), (1, 3), pps_listing_risk_text_color),
				("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
				("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
				("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 1), (1, -1), "RIGHT"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	risk_settings_table = Table(
		[
			["Risk Setting", "Value"],
			*[[Paragraph(row["key"], styles["BodyText"]), row["value"]] for row in report_data["risk_settings_rows"]],
		],
		hAlign="LEFT",
		colWidths=[360, 100],
		repeatRows=1,
	)
	risk_settings_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
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

	document = SectionPageNumberDocTemplate(
		str(output_path),
		pagesize=letter,
		title=report_data["report_title"],
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(report_data["report_title"], styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		Paragraph(f"Framework Title: {html.escape(report_data['framework_title'])}", styles["Normal"]),
		Paragraph(f"Framework Version: {html.escape(report_data['framework_version'])}", styles["Normal"]),
		Spacer(1, 18),
		contents_table,
		PageBreak(),
		anchored_heading("Checklist Risk", "checklist-risk"),
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
		Spacer(1, 12),
		Paragraph("Overall Checklist Risk", styles["Heading2"]),
		Spacer(1, 8),
		checklist_risk_summary_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("Checklist Missing Data", "checklist-missing-data"),
		Spacer(1, 8),
		Paragraph("Any checklist vulnerabilities marked as Not a Finding or N/A but missing comments or details about why that is.", subheading_style),
		Spacer(1, 12),
		checklist_missing_data_risk_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("Cyber Readiness Score", "cyber-readiness-score"),
		Spacer(1, 12),
		cyber_readiness_score_table,
		Spacer(1, 16),
		Paragraph("Readiness Settings", styles["Heading1"]),
		Spacer(1, 8),
		cyber_readiness_settings_table if report_data["cyber_readiness_settings_rows"] else Paragraph("Readiness settings data was not returned.", styles["Normal"]),
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("Patch Vulnerability Risk", "patch-vulnerability-risk"),
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
	story.extend(
		[
		Spacer(1, 12),
		Paragraph("Overall Patch Vulnerability Risk", styles["Heading2"]),
		Spacer(1, 8),
		patch_vulnerability_risk_summary_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("POAM Risk Area", "poam-items"),
		Spacer(1, poam_heading_gap),
		Paragraph("Completion Dates", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		poam_risk_table,
		]
	)
	story.extend(
		[
		Spacer(1, poam_section_gap),
		anchor_marker("poam-residual-risk"),
		Paragraph("Residual Risk", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		poam_residual_risk_table,
		]
	)
	story.extend(
		[
		Spacer(1, poam_section_gap),
		anchor_marker("poam-ongoing-risk"),
		Paragraph("Ongoing Risk", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		poam_ongoing_risk_table,
		Spacer(1, poam_section_gap),
		Paragraph("Overall POAM Status", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		overall_poam_status_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchor_marker("poam-ongoing-residual-risk"),
		KeepTogether([
			Paragraph("Ongoing Residual Risk", styles["Heading2"]),
			Spacer(1, poam_heading_gap),
			poam_ongoing_residual_risk_table,
		]),
		Spacer(1, poam_section_gap),
		Paragraph("Overall POAM Residual Risk", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		overall_poam_ongoing_residual_risk_table,
		]
	)
	story.extend(
		[
		Spacer(1, poam_section_gap),
		anchor_marker("poam-office-organization-ongoing-risk"),
		Paragraph("Office Organization Ongoing Risk", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		poam_office_organization_ongoing_risk_table,
		Spacer(1, poam_section_gap),
		Paragraph("Overall POAM Office Organization Risk", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		overall_poam_office_organization_risk_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchor_marker("poam-false-positives-risk"),
		KeepTogether([
			Paragraph("False Positives Risk", styles["Heading2"]),
			Spacer(1, poam_heading_gap),
			poam_false_positives_risk_table,
		]),
		Spacer(1, poam_section_gap),
		Paragraph("Overall POAM False Positives Risk", styles["Heading2"]),
		Spacer(1, poam_heading_gap),
		overall_poam_false_positives_risk_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("Compliance", "compliance"),
		Spacer(1, 12),
		compliance_risk_table,
		Spacer(1, 12),
		Paragraph("Overall Compliance Risk", styles["Heading2"]),
		Spacer(1, 8),
		overall_compliance_risk_table,
		Spacer(1, 12),
		anchored_subheading("Compliance Control Score", "compliance-control-score"),
		Spacer(1, 8),
		compliance_control_score_risk_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("Ports/Protocols/Services Boundaries", "pps-boundaries"),
		Spacer(1, 12),
		pps_boundaries_risk_table,
		Spacer(1, 12),
		anchored_heading("Ports/Protocols/Services Listing", "pps-listing"),
		Spacer(1, 12),
		pps_listing_risk_table,
		]
	)
	story.extend(
		[
		PageBreak(),
		anchored_heading("Risk Settings", "risk-settings"),
		Spacer(1, 12),
		risk_settings_table,
		]
	)
	measurement_buffer = BytesIO()
	measurement_document = SectionPageNumberDocTemplate(
		measurement_buffer,
		pagesize=letter,
		title=report_data["report_title"],
		author="OpenRMF Professional External API Scripts",
	)
	measurement_document.build(copy.deepcopy(story))
	for row in report_data["table_of_contents_rows"]:
		page_number = measurement_document.section_page_numbers.get(row["anchor"])
		if page_number:
			row["page_number"] = str(page_number)
	updated_contents_table = build_contents_table(report_data["table_of_contents_rows"])
	for index, flowable in enumerate(story):
		if flowable is contents_table:
			story[index] = updated_contents_table
			break
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
	cat_status_lines.extend(
		[
			"",
			"Overall Checklist Risk",
			"Checklist Risk Type | Count | Risk",
			"------------------- | ----- | ----",
		]
	)
	for row in report_data["checklist_risk_summary_rows"]:
		cat_status_lines.append(f"{row['title']} | {row['count']} | {row['risk']}")
	cyber_readiness_score_lines = [
		"Cyber Readiness Score",
		"",
		"Readiness | Score",
		"--------- | -----",
	]
	for row in report_data["cyber_readiness_score_rows"]:
		cyber_readiness_score_lines.append(f"{row['readiness']} | {row['score']}")
	cyber_readiness_score_lines.extend(
		[
			"",
			"Readiness Settings",
			"Category | Setting",
			"-------- | -------",
		]
	)
	if report_data["cyber_readiness_settings_rows"]:
		for row in report_data["cyber_readiness_settings_rows"]:
			cyber_readiness_score_lines.append(f"{row['category']} | {safe_text(row['setting']).replace(chr(10), '; ')}")
	else:
		cyber_readiness_score_lines.append("Readiness settings data was not returned.")
	checklist_missing_data_risk_area = report_data["checklist_missing_data_risk_area"]
	checklist_missing_data_risk_lines = [
		"Checklist Missing Data",
		"Any checklist vulnerabilities marked as Not a Finding or N/A but missing comments or details about why that is.",
		"",
		f"Status: {checklist_missing_data_risk_area['status']}",
		f"Returned Missing Data Items: {checklist_missing_data_risk_area['returned_count']}",
		f"Risk: {checklist_missing_data_risk_area['risk']}",
	]
	patch_vulnerability_risk_lines = [
		"Patch Vulnerability Risk",
		"",
		"Risk      Open",
		"--------  ----",
	]
	for row in report_data["patch_vulnerability_risk_rows"]:
		patch_vulnerability_risk_lines.append(f"{row['risk']:<8}  {row['open']:>4}")
	patch_vulnerability_risk_lines.extend(["", "Patch Vulnerability Risk 2D Histogram unavailable in fallback PDF output."])
	patch_vulnerability_risk_lines.extend(
		[
			"",
			"Overall Patch Vulnerability Risk",
			"Patch Vulnerability Type | Open | Risk",
			"------------------------ | ---- | ----",
		]
	)
	for row in report_data["patch_vulnerability_risk_summary_rows"]:
		patch_vulnerability_risk_lines.append(f"{row['title']} | {row['count']} | {row['risk']}")
	poam_risk_area = report_data["poam_risk_area"]
	poam_risk_lines = [
		"POAM Risk Area",
		"Completion Dates",
		"",
		f"Ongoing POAM Records: {poam_risk_area['total_count']}",
		f"Scheduled Completion Dates: {poam_risk_area['scheduled_count']}",
		f"Not Past Due Scheduled Completion Dates: {poam_risk_area['not_past_due_count']}",
		f"Past Due Scheduled Completion Dates: {poam_risk_area['past_due_count']}",
	]
	poam_residual_risk_area = report_data["poam_residual_risk_area"]
	poam_residual_risk_lines = [
		"Residual Risk",
		"",
		f"Total POAM Records: {poam_residual_risk_area['total_count']}",
		f"High Empty Resulting Residual Risk Mitigation Fields: {poam_residual_risk_area['high_empty_count']}",
		f"Moderate Empty Resulting Residual Risk Mitigation Fields: {poam_residual_risk_area['moderate_empty_count']}",
		f"Low Empty Resulting Residual Risk Mitigation Fields: {poam_residual_risk_area['low_empty_count']}",
		f"Empty Resulting Residual Risk Mitigation Fields: {poam_residual_risk_area['empty_count']}",
		f"Empty Percentage: {poam_residual_risk_area['empty_percent']}",
		f"Risk: {poam_residual_risk_area['risk']}",
	]
	poam_ongoing_risk_area = report_data["poam_ongoing_risk_area"]
	poam_ongoing_risk_lines = [
		"Ongoing Risk",
		"",
		f"Ongoing Items: {poam_ongoing_risk_area['ongoing_count']}",
		f"Accepted Items: {poam_ongoing_risk_area['accepted_count']}",
		f"Accepted Percentage of Ongoing Items: {poam_ongoing_risk_area['accepted_percent']}",
		f"Risk: {poam_ongoing_risk_area['risk']}",
	]
	poam_ongoing_risk_lines.extend(
		[
			"",
			"Overall POAM Status",
			"POAM Status Type | Count | Risk",
			"---------------- | ----- | ----",
		]
	)
	for row in report_data["overall_poam_status_rows"]:
		poam_ongoing_risk_lines.append(f"{row['title']} | {row['count']} | {row['risk']}")
	poam_ongoing_residual_risk_area = report_data["poam_ongoing_residual_risk_area"]
	poam_ongoing_residual_risk_lines = [
		"Ongoing Residual Risk",
		"",
		f"Ongoing Items: {poam_ongoing_residual_risk_area['ongoing_count']}",
		f"Very High Resulting Residual Risk Mitigation Items: {poam_ongoing_residual_risk_area['very_high_count']}",
		f"Very High Percentage of Ongoing Items: {poam_ongoing_residual_risk_area['very_high_percent']}",
		f"Risk: {poam_ongoing_residual_risk_area['risk']}",
	]
	poam_ongoing_residual_risk_lines.extend(
		[
			"",
			"Overall POAM Residual Risk",
			"POAM Residual Risk Type | Count | Risk",
			"----------------------- | ----- | ----",
		]
	)
	for row in report_data["overall_poam_ongoing_residual_risk_rows"]:
		poam_ongoing_residual_risk_lines.append(f"{row['title']} | {row['count']} | {row['risk']}")
	poam_office_organization_ongoing_risk_area = report_data["poam_office_organization_ongoing_risk_area"]
	poam_office_organization_ongoing_risk_lines = [
		"Office Organization Ongoing Risk",
		"",
		f"Ongoing Items: {poam_office_organization_ongoing_risk_area['ongoing_count']}",
		f"Empty Office Organization Items: {poam_office_organization_ongoing_risk_area['empty_count']}",
		f"Empty Percentage of Ongoing Items: {poam_office_organization_ongoing_risk_area['empty_percent']}",
		f"Risk: {poam_office_organization_ongoing_risk_area['risk']}",
	]
	poam_office_organization_ongoing_risk_lines.extend(
		[
			"",
			"Overall POAM Office Organization Risk",
			"POAM Office Organization Risk Type | Percentage | Risk",
			"---------------------------------- | ---------- | ----",
		]
	)
	for row in report_data["overall_poam_office_organization_risk_rows"]:
		poam_office_organization_ongoing_risk_lines.append(f"{row['title']} | {row['percentage']} | {row['risk']}")
	poam_false_positives_risk_area = report_data["poam_false_positives_risk_area"]
	poam_false_positives_risk_lines = [
		"False Positives Risk",
		"",
		f"Completed Items: {poam_false_positives_risk_area['completed_count']}",
		f"False Positive Completed Items: {poam_false_positives_risk_area['false_positive_count']}",
		f"False Positive Percentage of Completed Items: {poam_false_positives_risk_area['false_positive_percent']}",
		f"Risk: {poam_false_positives_risk_area['risk']}",
	]
	poam_false_positives_risk_lines.extend(
		[
			"",
			"Overall POAM False Positives Risk",
			"POAM False Positives Risk Type | Percentage | Risk",
			"------------------------------ | ---------- | ----",
		]
	)
	for row in report_data["overall_poam_false_positives_risk_rows"]:
		poam_false_positives_risk_lines.append(f"{row['title']} | {row['percentage']} | {row['risk']}")
	poam_risk_area_lines = []
	for section_lines in [
		poam_risk_lines,
		poam_residual_risk_lines,
		poam_ongoing_risk_lines,
		poam_ongoing_residual_risk_lines,
		poam_office_organization_ongoing_risk_lines,
		poam_false_positives_risk_lines,
	]:
		if poam_risk_area_lines:
			poam_risk_area_lines.append("")
		poam_risk_area_lines.extend(section_lines)
	compliance_risk_area = report_data["compliance_risk_area"]
	compliance_risk_lines = [
		"Compliance",
		"",
		f"Status: {compliance_risk_area['status']}",
		f"Compliance Data Found: {compliance_risk_area['data_found']}",
		f"Risk: {compliance_risk_area['risk']}",
	]
	compliance_risk_lines.extend(
		[
			"",
			"Overall Compliance Risk",
			"Compliance Risk Type | Value | Risk",
			"-------------------- | ----- | ----",
		]
	)
	for row in report_data["overall_compliance_risk_rows"]:
		compliance_risk_lines.append(f"{row['title']} | {row['value']} | {row['risk']}")
	compliance_control_score_risk_area = report_data["compliance_control_score_risk_area"]
	compliance_risk_lines.extend([
		"",
		"Compliance Control Score",
		"",
		f"Status: {compliance_control_score_risk_area['status']}",
		f"Number of Controls: {compliance_control_score_risk_area['record_count']}",
		f"Number of Controls with no Compliance Records: {compliance_control_score_risk_area['both_zero_count']}",
		f"Percentage of Controls with no Compliance Records: {compliance_control_score_risk_area['both_zero_percent']}",
		f"Risk: {compliance_control_score_risk_area['risk']}",
	])
	pps_boundaries_risk_area = report_data["pps_boundaries_risk_area"]
	pps_boundaries_risk_lines = [
		"Ports/Protocols/Services Boundries",
		"",
		f"PPS Records Checked: {pps_boundaries_risk_area['record_count']}",
		f"Records with Boundaries: {pps_boundaries_risk_area['boundary_record_count']}",
		f"Boundary In Crossings: {pps_boundaries_risk_area['in_crossings']}",
		f"Boundary Out Crossings: {pps_boundaries_risk_area['out_crossings']}",
		f"Total Boundary Crossings: {pps_boundaries_risk_area['total_crossings']}",
		f"Risk: {pps_boundaries_risk_area['risk']}",
	]
	pps_listing_risk_area = report_data["pps_listing_risk_area"]
	pps_listing_risk_lines = [
		"Ports/Protocols/Services Lisitng",
		"",
		f"Status: {pps_listing_risk_area['status']}",
		f"Approved PPS Items: {pps_listing_risk_area['approved_count']}",
		f"Risk: {pps_listing_risk_area['risk']}",
	]
	pps_boundaries_risk_lines.extend(["", *pps_listing_risk_lines])
	risk_settings_lines = ["Risk Settings", ""]
	risk_settings_lines.extend([f"{row['key']}: {row['value']}" for row in report_data["risk_settings_rows"]])
	contents_lines = ["Page Title                                      Page Number", "--------------------------------------------  -----------"]
	contents_lines.extend([f"{row['title']:<44}  {row['page_number']:>11}" for row in report_data["table_of_contents_rows"]])
	page_streams = [
		make_text_page(
			[
			report_data["report_title"],
			"",
			f"Date Generated: {report_data['generated_at']}",
			f"System Key: {report_data['system_key']}",
			f"System Title: {report_data['system_title']}",
			f"Description: {report_data['system_description']}",
			f"Framework Title: {report_data['framework_title']}",
			f"Framework Version: {report_data['framework_version']}",
			"",
			*contents_lines,
			],
			font_size=14,
		),
		make_text_page(cat_status_lines),
		make_text_page(checklist_missing_data_risk_lines),
		make_text_page(cyber_readiness_score_lines),
		make_text_page(patch_vulnerability_risk_lines),
		*[make_text_page(poam_risk_area_lines[index:index + 36]) for index in range(0, len(poam_risk_area_lines), 36)],
		make_text_page(compliance_risk_lines),
		make_text_page(pps_boundaries_risk_lines),
		*[make_text_page(risk_settings_lines[index:index + 36]) for index in range(0, len(risk_settings_lines), 36)],
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
	poam_data = parse_json_value_from_output(call_poam_json_script([*sys.argv[1:5], "grouped=false"]))
	compliance_risk_area = build_compliance_risk_area(sys.argv[1:5])
	compliance_control_score_risk_area = build_compliance_control_score_risk_area(sys.argv[1:5], compliance_risk_area)
	ppsm_data = load_ppsm_data(sys.argv[1:5])
	checklist_missing_data = load_checklist_missing_data(sys.argv[1:5])
	approved_pps_listing = load_approved_pps_listing(sys.argv[1:5])
	readiness_score_data = load_readiness_score_data(sys.argv[1:5])
	readiness_settings_data = load_readiness_settings_data(sys.argv[1:5])
	report_data = build_report_data(system_key, options, system_package, poam_data, compliance_risk_area, compliance_control_score_risk_area, ppsm_data, checklist_missing_data, approved_pps_listing, readiness_score_data, readiness_settings_data)
	output_filename = f"OpenRMFPro-Risk-Profiler-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
