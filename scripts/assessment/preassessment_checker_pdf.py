#!/usr/bin/env python3

import html
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
CHECKLISTS_SCRIPT_NAME = "get_systempackage_by_systemkey_checklists_json.py"
CHECKLIST_MISSINGDATA_SCRIPT_NAME = "get_systempackage_by_systemkey_missingdata_json.py"
HARDWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_hardware_json.py"
COMPLIANCE_SCRIPT_NAME = "get_systempackage_by_systemkey_compliance_json.py"
COMPLIANCE_ALLCONTROLS_SCRIPT_NAME = "get_systempackage_by_systemkey_compliance_by_complianceid_allcontrolscore_json.py"
POAM_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
PATCH_SCORE_SCRIPT_NAME = "get_systempackage_by_systemkey_patchscore_json.py"
APPROVED_PPS_SCRIPT_NAME = "get_systempackage_by_systemkey_approvedpps_json.py"
TECH_VULNERABILITY_SCRIPT_NAME = "get_systempackage_by_systemkey_techvulnerabilitydata_json.py"
COMPLIANCE_GENERATED_DATE_KEYS = {
	"generatedat",
	"generateddate",
	"generatedon",
	"dategenerated",
	"compliancegeneratedat",
	"compliancegenerateddate",
	"lastgeneratedat",
	"lastgenerateddate",
	"lastgeneratedon",
	"lastrunat",
	"lastrundate",
	"createdat",
	"createddate",
	"updatedat",
	"updateddate",
}


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 assessment/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey>"
	)


def safe_filename_value(value: str) -> str:
	safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
	return safe_value.strip(".-") or "unknown-system"


def call_child_script(source_script: Path, arguments: list[str]) -> str:
	result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
	if result.returncode != 0:
		print(f"ERROR: {source_script.name} failed.")
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
	print("ERROR: Could not find JSON in script output.")
	print(output)
	sys.exit(1)


def safe_text(value) -> str:
	if value is None:
		return ""
	return str(value)


def normalized_key(value: str) -> str:
	return re.sub(r"[^a-z0-9]+", "", safe_text(value).lower())


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


def first_json_value_by_normalized_key(data, keys: set[str]) -> str:
	if isinstance(data, dict):
		for key, value in data.items():
			if normalized_key(key) in keys and value not in (None, ""):
				return safe_text(value).strip()
		for value in data.values():
			found_value = first_json_value_by_normalized_key(value, keys)
			if found_value:
				return found_value
	elif isinstance(data, list):
		for item in data:
			found_value = first_json_value_by_normalized_key(item, keys)
			if found_value:
				return found_value
	return ""


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


def compliance_records(compliance_data) -> list[dict]:
	return find_record_list(compliance_data, ["records", "items", "data", "results", "compliance", "compliances"])


def control_score_records(control_score_data) -> list[dict]:
	return find_record_list(control_score_data, ["records", "items", "data", "results", "controls", "allControls", "controlScores"])


def poam_records(poam_data) -> list[dict]:
	return find_record_list(poam_data, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


def hardware_records(hardware_data) -> list[dict]:
	return find_record_list(hardware_data, ["records", "items", "data", "results", "hardware", "devices", "assets"])


def tech_vulnerability_records(tech_vulnerability_data) -> list[dict]:
	records = find_record_list(tech_vulnerability_data, ["records", "items", "data", "results", "vulnerabilities", "techVulnerabilities", "techVulnerabilityData"])
	if records:
		return records
	if isinstance(tech_vulnerability_data, dict) and any(key in tech_vulnerability_data for key in ["severity", "severityString", "rawSeverity", "title", "description", "status"]):
		return [tech_vulnerability_data]
	return []


def checklist_missing_data_items(missingdata) -> list:
	if isinstance(missingdata, list):
		return missingdata
	if not isinstance(missingdata, dict):
		return []
	for key in ["records", "items", "data", "results", "missingData", "missingdata"]:
		value = missingdata.get(key)
		if isinstance(value, list):
			return value
	return [missingdata] if missingdata else []


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


def build_system_title(system_package) -> str:
	title = first_json_value(system_package, {"title", "systemTitle", "system_title", "systemName", "name"})
	return title or "Unknown"


def build_system_description(system_package) -> str:
	description = first_json_value(
		system_package,
		{"description", "systemDescription", "system_description", "systemPackageDescription", "packageDescription"},
	)
	return description or "Unknown"


def numeric_value(value) -> int | None:
	try:
		return int(float(str(value).strip()))
	except (TypeError, ValueError):
		return None


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


def bool_value(value) -> bool:
	if isinstance(value, bool):
		return value
	if isinstance(value, (int, float)):
		return value != 0
	return safe_text(value).strip().lower() in {"true", "yes", "y", "1"}


def count_records(data) -> int:
	if isinstance(data, list):
		return len(data)
	if not isinstance(data, dict):
		return 0

	for key in ["total", "totalCount", "totalRecords", "recordCount", "recordsTotal", "count", "itemCount"]:
		value = numeric_value(data.get(key))
		if value is not None:
			return value

	for key in ["records", "items", "data", "results", "checklists", "hardware"]:
		value = data.get(key)
		if isinstance(value, list):
			return len(value)

	for value in data.values():
		if isinstance(value, list) and all(isinstance(record, dict) for record in value):
			return len(value)
	return 0


def parse_date_value(value):
	value_text = safe_text(value).strip()
	if not value_text:
		return None
	if value_text.endswith("Z"):
		value_text = value_text[:-1] + "+00:00"
	try:
		parsed_value = datetime.fromisoformat(value_text)
		return parsed_value.date()
	except ValueError:
		pass

	for date_format in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%m/%d/%Y", "%Y-%m-%d"):
		try:
			return datetime.strptime(value_text, date_format).date()
		except ValueError:
			continue
	return None


def is_compliance_generated_date_key(key: str) -> bool:
	candidate = normalized_key(key)
	return candidate in COMPLIANCE_GENERATED_DATE_KEYS or ("generated" in candidate and "date" in candidate)


def compliance_generated_dates(data) -> list:
	dates = []
	if isinstance(data, dict):
		for key, value in data.items():
			if is_compliance_generated_date_key(key):
				parsed_date = parse_date_value(value)
				if parsed_date is not None:
					dates.append(parsed_date)
			dates.extend(compliance_generated_dates(value))
	elif isinstance(data, list):
		for item in data:
			dates.extend(compliance_generated_dates(item))
	return dates


def latest_compliance_generated_date(compliance_data):
	dates = compliance_generated_dates(compliance_data)
	return max(dates) if dates else None


def poam_activity_age_values(data) -> list[int]:
	age_values = []
	if isinstance(data, dict):
		for key, value in data.items():
			if normalized_key(key) == "age":
				age = numeric_value(value)
				if age is not None:
					age_values.append(age)
			age_values.extend(poam_activity_age_values(value))
	elif isinstance(data, list):
		for item in data:
			age_values.extend(poam_activity_age_values(item))
	return age_values


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


def scheduled_completion_value(record: dict) -> str:
	return first_value(record, ["scheduledCompletionDate", "scheduledCompletionDateString", "scheduledCompletion", "completionDate"])


def hardware_patch_scan_value(record: dict) -> str:
	return first_value(record, ["patchscan", "patchScanEnabled", "hasPatchScan", "patchScanning", "patchScanAvailable"])


def hardware_checklists_value(record: dict) -> str:
	return first_value(record, ["checklist", "hasChecklist", "checklistAvailable", "checklists", "hasChecklists"])


def has_json_data(data) -> bool:
	if isinstance(data, dict):
		return bool(data)
	if isinstance(data, list):
		return len(data) > 0
	return data not in (None, "")


def build_control_evidence_check_row(compliance_data, control_score_data) -> dict[str, str]:
	compliance_id = extract_compliance_id(compliance_data)
	if not compliance_id:
		return {
			"item": "All controls with evidence and no 0% complete / 0% open score",
			"passed": False,
			"result": "Fail",
			"details": "Compliance is not generated or compliance ID was not found",
		}
	if control_score_data is None:
		return {
			"item": "All controls with evidence and no 0% complete / 0% open score",
			"passed": False,
			"result": "Fail",
			"details": "All control compliance scores unavailable",
		}

	records = control_score_records(control_score_data)
	controls_without_data = 0
	controls_with_percentages = 0
	for record in records:
		percentage_open = percentage_value(record, ["percentageOpen", "percentOpen", "openPercentage"])
		percentage_complete = percentage_value(record, ["percentageComplete", "percentComplete", "completionPercentage"])
		if percentage_open is None or percentage_complete is None:
			continue
		controls_with_percentages += 1
		if percentage_open == 0 and percentage_complete == 0:
			controls_without_data += 1

	passed = controls_with_percentages > 0 and controls_without_data == 0
	if controls_with_percentages == 0:
		details = f"No control score percentages found across {len(records)} controls"
	else:
		details = f"{controls_without_data} of {controls_with_percentages} controls have 0% complete and 0% open"
	return {
		"item": "All controls with evidence and no 0% complete / 0% open score",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": details,
	}


def build_poam_generated_check_row(poam_data) -> dict[str, str]:
	passed = has_json_data(poam_data)
	return {
		"item": "POAM is generated",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": "POAM data returned" if passed else "POAM data unavailable or not generated",
	}


def build_poam_activity_age_check_row(poam_data) -> dict[str, str]:
	if not has_json_data(poam_data):
		return {
			"item": "POAM has been updated within the last 30 days",
			"passed": False,
			"result": "Fail",
			"details": "POAM data unavailable or not generated",
		}
	age_values = poam_activity_age_values(poam_data)
	if not age_values:
		return {
			"item": "POAM has been updated within the last 30 days",
			"passed": False,
			"result": "Fail",
			"details": "No POAM activity age values found",
		}
	latest_age = min(age_values)
	passed = latest_age <= 30
	return {
		"item": "POAM has been updated within the last 30 days",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"Most recent POAM activity age: {latest_age} days",
	}


def build_poam_overdue_check_row(poam_data) -> dict[str, str]:
	if not has_json_data(poam_data):
		return {
			"item": "No ongoing POAM items past scheduled completion date",
			"passed": False,
			"result": "Fail",
			"details": "POAM data unavailable or not generated",
		}

	today = datetime.now().astimezone().date()
	ongoing_records = [record for record in poam_records(poam_data) if poam_status(record) == "Ongoing"]
	scheduled_count = 0
	past_due_count = 0
	for record in ongoing_records:
		scheduled_date = parse_date_value(scheduled_completion_value(record))
		if scheduled_date is None:
			continue
		scheduled_count += 1
		if scheduled_date < today:
			past_due_count += 1
	passed = past_due_count == 0
	return {
		"item": "No ongoing POAM items are past scheduled completion date",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"{past_due_count} overdue of {scheduled_count} scheduled ongoing POAM items as of {today.isoformat()}",
	}


def build_patch_critical_open_check_row(patch_score_data) -> dict[str, str]:
	if patch_score_data is None:
		return {
			"item": "No critical open patch vulnerabilities when patch scans are present",
			"passed": False,
			"result": "Fail",
			"details": "Patch score data unavailable",
		}

	contains_patch_scans = bool_value(first_json_value_by_normalized_key(patch_score_data, {"containspatchscans"}))
	if not contains_patch_scans:
		return {
			"item": "No critical open patch vulnerabilities when patch scans are present",
			"passed": True,
			"result": "Pass",
			"details": "containsPatchScans is not true",
		}

	critical_open_value = first_json_value_by_normalized_key(
		patch_score_data,
		{"totalcriticalopen", "totalpatchcriticalopen", "criticalopen", "opencritical"},
	)
	critical_open_count = numeric_value(critical_open_value)
	passed = critical_open_count == 0
	return {
		"item": "Has no critical open patch vulnerabilities when patch scans are present",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"Critical open patch vulnerabilities: {critical_open_count}" if critical_open_count is not None else "Critical open patch count unavailable",
	}


def build_approved_pps_check_row(approved_pps_data) -> dict[str, str]:
	passed = has_json_data(approved_pps_data)
	return {
		"item": "Approved ports list is loaded",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": "Approved ports list returned" if passed else "Approved ports list unavailable or not loaded",
	}


def checklist_score_data(system_package):
	if isinstance(system_package, dict):
		score = system_package.get("score")
		if isinstance(score, dict):
			return score
	return {}


def checklist_not_reviewed_count(system_package) -> int:
	score = checklist_score_data(system_package)
	total_not_reviewed = numeric_value(score.get("totalNotReviewed"))
	if total_not_reviewed is not None:
		return total_not_reviewed
	return sum(
		numeric_value(score.get(key)) or 0
		for key in ["totalCat1NotReviewed", "totalCat2NotReviewed", "totalCat3NotReviewed"]
	)


def build_checklist_not_reviewed_check_row(system_package) -> dict[str, str]:
	contains_checklists = bool_value(first_json_value_by_normalized_key(system_package, {"containschecklists"}))
	if not contains_checklists:
		return {
			"item": "No checklist vulnerabilities marked Not Reviewed when checklists are present",
			"passed": True,
			"result": "Pass",
			"details": "containsChecklists is not true",
		}
	not_reviewed_count = checklist_not_reviewed_count(system_package)
	passed = not_reviewed_count == 0
	return {
		"item": "No checklist vulnerabilities marked Not Reviewed when checklists are present",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"Not Reviewed checklist vulnerabilities: {not_reviewed_count}",
	}


def build_tech_critical_vulnerability_check_row(system_package, tech_vulnerability_data) -> dict[str, str]:
	contains_other_technologies = bool_value(first_json_value_by_normalized_key(system_package, {"containsothertechnologies"}))
	if not contains_other_technologies:
		return {
			"item": "No critical other technology vulnerabilities when other technologies are present",
			"passed": True,
			"result": "Pass",
			"details": "containsOtherTechnologies is not true",
		}
	if tech_vulnerability_data is None:
		return {
			"item": "No critical other technology vulnerabilities when other technologies are present",
			"passed": False,
			"result": "Fail",
			"details": "Critical other technology vulnerability data unavailable",
		}
	critical_count = len(tech_vulnerability_records(tech_vulnerability_data))
	passed = critical_count == 0
	return {
		"item": "No critical other technology vulnerabilities when other technologies are present",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"Critical other technology vulnerabilities: {critical_count}",
	}


def build_checklist_missing_comments_check_row(system_package, checklist_missing_data) -> dict[str, str]:
	contains_checklists = bool_value(first_json_value_by_normalized_key(system_package, {"containschecklists"}))
	if not contains_checklists:
		return {
			"item": "No checklists missing comments or details",
			"passed": True,
			"result": "Pass",
			"details": "containsChecklists is not true",
		}
	if checklist_missing_data is None:
		return {
			"item": "No checklists missing comments or details",
			"passed": False,
			"result": "Fail",
			"details": "Checklist missing data unavailable",
		}
	missing_items = checklist_missing_data_items(checklist_missing_data)
	passed = len(missing_items) == 0
	return {
		"item": "No checklists missing comments or details",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"Missing comments/details items: {len(missing_items)}",
	}


def build_hardware_scan_coverage_check_row(system_package, hardware_data) -> dict[str, str]:
	records = hardware_records(hardware_data)
	if not records:
		return {
			"item": "No missing checklist or hardware patch scan",
			"passed": False,
			"result": "Fail",
			"details": "Hardware data unavailable or empty",
		}
	missing_checklist_count = sum(1 for record in records if not bool_value(hardware_checklists_value(record)))
	missing_patch_scan_count = sum(1 for record in records if not bool_value(hardware_patch_scan_value(record)))
	passed = missing_checklist_count == 0 and missing_patch_scan_count == 0
	return {
		"item": "No missing checklist or hardware patch scan",
		"passed": passed,
		"result": "Pass" if passed else "Fail",
		"details": f"Missing checklist: {missing_checklist_count}; missing patch scan: {missing_patch_scan_count}; hardware checked: {len(records)}",
	}


def build_preassessment_check_rows(system_package, hardware, compliance_data, control_score_data, poam_data, patch_score_data, approved_pps_data, tech_vulnerability_data, checklist_missing_data) -> list[dict[str, str]]:
	generated_date = latest_compliance_generated_date(compliance_data)
	cutoff_date = datetime.now().astimezone().date() - timedelta(days=30)
	passed = generated_date is not None and generated_date >= cutoff_date
	details = f"Last generated: {generated_date.isoformat()}" if generated_date else "No generated date found"
	return [
		{
			"item": "Compliance generated within the last 30 days",
			"passed": passed,
			"result": "Pass" if passed else "Fail",
			"details": details,
		},
		build_control_evidence_check_row(compliance_data, control_score_data),
		build_poam_generated_check_row(poam_data),
		build_poam_activity_age_check_row(poam_data),
		build_poam_overdue_check_row(poam_data),
		build_patch_critical_open_check_row(patch_score_data),
		build_approved_pps_check_row(approved_pps_data),
		build_checklist_not_reviewed_check_row(system_package),
		build_tech_critical_vulnerability_check_row(system_package, tech_vulnerability_data),
		build_checklist_missing_comments_check_row(system_package, checklist_missing_data),
		build_hardware_scan_coverage_check_row(system_package, hardware),
	]


def load_system_package(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "system-package" / SYSTEM_PACKAGE_SCRIPT_NAME
	return parse_json_value_from_output(call_child_script(source_script, arguments))


def load_checklists(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "checklist" / CHECKLISTS_SCRIPT_NAME
	return parse_json_value_from_output(call_child_script(source_script, [*arguments, "limit=10000"]))


def load_checklist_missing_data(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "checklist" / CHECKLIST_MISSINGDATA_SCRIPT_NAME
	result = call_child_script_result(
		source_script,
		[
			*arguments,
			"notafinding=true",
			"notapplicable=true",
			"open=false",
			"notreviewed=false",
			"limit=10000",
		],
	)
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def load_hardware(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "hardware" / HARDWARE_SCRIPT_NAME
	return parse_json_value_from_output(call_child_script(source_script, arguments))


def load_compliance(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "compliance" / COMPLIANCE_SCRIPT_NAME
	result = call_child_script_result(source_script, arguments)
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def load_all_control_scores(arguments: list[str], compliance_data):
	compliance_id = extract_compliance_id(compliance_data)
	if not compliance_id:
		return None
	source_script = Path(__file__).resolve().parents[1] / "compliance" / COMPLIANCE_ALLCONTROLS_SCRIPT_NAME
	result = call_child_script_result(source_script, [*arguments, compliance_id])
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def load_poam(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "poam" / POAM_SCRIPT_NAME
	result = call_child_script_result(source_script, [*arguments, "grouped=false"])
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def load_patch_score(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "patch-vulnerability" / PATCH_SCORE_SCRIPT_NAME
	result = call_child_script_result(source_script, arguments)
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def load_approved_pps(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "ports-protocols-services" / APPROVED_PPS_SCRIPT_NAME
	result = call_child_script_result(source_script, arguments)
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def load_tech_vulnerability_data(arguments: list[str]):
	source_script = Path(__file__).resolve().parents[1] / "other_tech_vulnerability" / TECH_VULNERABILITY_SCRIPT_NAME
	result = call_child_script_result(
		source_script,
		[
			*arguments,
			"critical=true",
			"info=false",
			"minor=false",
			"major=false",
			"blocker=false",
			"closed=false",
			"open=true",
		],
	)
	if result.returncode != 0:
		return None
	return parse_json_value_from_output(result.stdout)


def build_report_data(system_key: str, system_package, checklists, hardware, compliance_data, control_score_data, poam_data, patch_score_data, approved_pps_data, tech_vulnerability_data, checklist_missing_data) -> dict[str, str]:
	system_title = build_system_title(system_package)
	return {
		"report_title": f"{system_title} Pre-Assessment Checks",
		"system_key": system_key,
		"system_title": system_title,
		"system_description": build_system_description(system_package),
		"checklist_count": str(count_records(checklists)),
		"hardware_count": str(count_records(hardware)),
		"check_rows": build_preassessment_check_rows(system_package, hardware, compliance_data, control_score_data, poam_data, patch_score_data, approved_pps_data, tech_vulnerability_data, checklist_missing_data),
		"generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
	}


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, str]) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	table_header_style = styles["BodyText"].clone("PreAssessmentTableHeader")
	table_header_style.fontName = "Helvetica-Bold"
	result_style = styles["BodyText"].clone("PreAssessmentResult")
	result_style.alignment = 1
	item_style = styles["BodyText"].clone("PreAssessmentItem")
	detail_style = styles["BodyText"].clone("PreAssessmentDetail")
	detail_style.fontSize = 8
	detail_style.leading = 10
	detail_style.textColor = colors.HexColor("#555555")

	check_table_rows = [
		[Paragraph("Items Checked", table_header_style), Paragraph("Pass/Fail", table_header_style)],
	]
	for row in report_data["check_rows"]:
		result_color = "#008000" if row["passed"] else "#B00020"
		result_mark = "✓" if row["passed"] else "✕"
		check_table_rows.append(
			[
				Paragraph(html.escape(row["item"]), item_style),
				Paragraph(f"<font color=\"{result_color}\"><b>{result_mark}</b></font>", result_style),
			]
		)
	check_table = Table(check_table_rows, colWidths=[390, 90], hAlign="LEFT")
	check_table.setStyle(
		TableStyle(
			[
				("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9EEF7")),
				("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B7B7B7")),
				("VALIGN", (0, 0), (-1, -1), "TOP"),
				("ALIGN", (1, 0), (1, -1), "CENTER"),
				("LEFTPADDING", (0, 0), (-1, -1), 8),
				("RIGHTPADDING", (0, 0), (-1, -1), 8),
				("TOPPADDING", (0, 0), (-1, -1), 7),
				("BOTTOMPADDING", (0, 0), (-1, -1), 7),
			]
		)
	)
	document = SimpleDocTemplate(
		str(output_path),
		pagesize=letter,
		title=report_data["report_title"],
		author="OpenRMF Professional External API Scripts",
	)
	story = [
		Paragraph(html.escape(report_data["report_title"]), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(report_data['system_description'])}", styles["Normal"]),
		Paragraph(f"Total Number of Checklists: {html.escape(report_data['checklist_count'])}", styles["Normal"]),
		Paragraph(f"Total Number of Hardware: {html.escape(report_data['hardware_count'])}", styles["Normal"]),
		PageBreak(),
		Paragraph('<a name="items-checked"/>Items Checked', styles["Heading1"]),
		Spacer(1, 12),
		check_table,
	]
	document.build(story)
	return True


def pdf_text(value: str) -> str:
	return safe_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap_pdf_line(text: str, max_length: int = 88) -> list[str]:
	words = safe_text(text).split()
	if not words:
		return [""]
	lines = []
	current_line = words[0]
	for word in words[1:]:
		if len(current_line) + len(word) + 1 > max_length:
			lines.append(current_line)
			current_line = word
		else:
			current_line += " " + word
	lines.append(current_line)
	return lines


def write_minimal_pdf(output_path: Path, report_data: dict[str, str]) -> None:
	page_one_lines = [
		report_data["report_title"],
		"",
		f"Date Generated: {report_data['generated_at']}",
		f"System Key: {report_data['system_key']}",
		f"System Title: {report_data['system_title']}",
		f"Description: {report_data['system_description']}",
		f"Total Number of Checklists: {report_data['checklist_count']}",
		f"Total Number of Hardware: {report_data['hardware_count']}",
	]
	page_two_lines = ["Items Checked", "", "Items Checked                                                        Pass/Fail", "------------------------------------------------------------------  ---------"]
	for row in report_data["check_rows"]:
		wrapped_item_lines = wrap_pdf_line(row["item"], 66)
		for index, item_line in enumerate(wrapped_item_lines):
			result_value = row["result"].upper() if index == 0 else ""
			page_two_lines.append(f"{item_line:<66}  {result_value:>9}")

	def make_text_stream(lines: list[str]) -> str:
		wrapped_lines = []
		for line in lines:
			wrapped_lines.extend(wrap_pdf_line(line))

		stream_lines = ["BT", "/F1 14 Tf", "50 742 Td"]
		for index, line in enumerate(wrapped_lines):
			if index:
				stream_lines.append("0 -20 Td")
			stream_lines.append(f"({pdf_text(line)}) Tj")
		stream_lines.append("ET")
		return "\n".join(stream_lines)

	page_streams = [make_text_stream(page_one_lines), make_text_stream(page_two_lines)]

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

	script_arguments = sys.argv[1:5]
	system_key = sys.argv[4]
	system_package = load_system_package(script_arguments)
	checklists = load_checklists(script_arguments)
	checklist_missing_data = load_checklist_missing_data(script_arguments)
	hardware = load_hardware(script_arguments)
	compliance_data = load_compliance(script_arguments)
	control_score_data = load_all_control_scores(script_arguments, compliance_data)
	poam_data = load_poam(script_arguments)
	patch_score_data = load_patch_score(script_arguments)
	approved_pps_data = load_approved_pps(script_arguments)
	tech_vulnerability_data = load_tech_vulnerability_data(script_arguments)
	report_data = build_report_data(system_key, system_package, checklists, hardware, compliance_data, control_score_data, poam_data, patch_score_data, approved_pps_data, tech_vulnerability_data, checklist_missing_data)
	output_filename = f"OpenRMFPro-Pre-Assessment-{safe_filename_value(system_key)}.pdf"
	output_path = Path(output_filename)
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_filename}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
