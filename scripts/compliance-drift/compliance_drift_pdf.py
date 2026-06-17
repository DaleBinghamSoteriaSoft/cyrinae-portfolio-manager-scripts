#!/usr/bin/env python3

import html
import json
import math
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
REPORT_TITLE_SUFFIX = "Compliance Drift"
SYSTEM_PACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
CHECKLIST_SCRIPT_NAME = "get_systempackage_by_systemkey_checklists_json.py"
PATCH_DATA_SCRIPT_NAME = "get_systempackage_by_systemkey_patchdata_json.py"
DEFAULT_CHECKLIST_LIMIT = 5000
DEFAULT_TOP_ROWS = 25
DEFAULT_MIN_MODEL_ROWS = 8
DEFAULT_WEEKLY_GRAPH_WEEKS = 12
COMPLIANCE_THRESHOLD = 80.0
WEEKDAY_NAMES = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

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
CHECKLIST_STATUS_KEYS = [
	"status",
	"state",
	"findingStatus",
	"result",
	"complianceStatus",
	"assessmentStatus",
	"vulnerabilityStatus",
]
CHECKLIST_OPEN_COUNT_KEYS = [
	"openCount",
	"openFindings",
	"openItems",
	"openStigItems",
	"notReviewedCount",
	"notReviewed",
	"failedCount",
	"failCount",
	"nonCompliantCount",
	"catIOpen",
	"catIIOpen",
	"catIIIOpen",
]
CHECKLIST_OPEN_TOTAL_KEYS = [
	"openCount",
	"openFindings",
	"openItems",
	"openStigItems",
	"notReviewedCount",
	"notReviewed",
	"failedCount",
	"failCount",
	"nonCompliantCount",
]
CHECKLIST_OPEN_CATEGORY_KEYS = ["catIOpen", "catIIOpen", "catIIIOpen"]
CHECKLIST_TOTAL_COUNT_KEYS = [
	"totalCount",
	"totalFindings",
	"totalItems",
	"stigItemCount",
	"ruleCount",
	"vulnerabilityCount",
	"checkCount",
]
PATCH_OPEN_COUNT_KEYS = [
	"totalOpen",
	"openCount",
	"openVulnerabilities",
	"vulnerabilitiesOpen",
	"openPatchCount",
	"patchCount",
	"totalPatchCount",
	"totalFindings",
	"vulnerabilityCount",
	"totalCriticalOpen",
	"totalHighOpen",
	"totalMediumOpen",
	"totalLowOpen",
	"criticalOpen",
	"highOpen",
	"mediumOpen",
	"lowOpen",
]
PATCH_OPEN_TOTAL_KEYS = [
	"totalOpen",
	"openCount",
	"openVulnerabilities",
	"vulnerabilitiesOpen",
	"openPatchCount",
	"patchCount",
	"totalPatchCount",
	"totalFindings",
	"vulnerabilityCount",
]
PATCH_OPEN_SEVERITY_COUNT_KEYS = [
	"totalCriticalOpen",
	"totalHighOpen",
	"totalMediumOpen",
	"totalLowOpen",
	"criticalOpen",
	"highOpen",
	"mediumOpen",
	"lowOpen",
]
PATCH_SEVERITY_KEYS = ["severity", "risk", "criticality", "level", "vulnerabilitySeverity"]
DATE_KEYS = ["scanDate", "lastScanDate", "lastPatchScanDate", "updated", "updatedOn", "created", "createdOn", "date"]


def get_project_python_executable() -> str:
	project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
	return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
	print("ERROR: Missing required parameters.")
	print(
		"Usage from the scripts folder: python3 compliance-drift/"
		+ Path(__file__).name
		+ " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
	)
	print("Optional: outputFile=<pdf> snapshotCsv=<csv> generatedAt=<iso-date> checklistLimit=5000 topRows=25 minModelRows=8")


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


def parse_optional_arguments(arguments: list[str]) -> dict[str, str]:
	parsed = {}
	for argument in arguments:
		if "=" not in argument:
			print(f"ERROR: Optional arguments must use KEY=VALUE format. Invalid value: {argument}")
			sys.exit(1)
		key, value = argument.split("=", 1)
		parsed[key] = value
	return parsed


def optional_int(options: dict[str, str], key: str, default_value: int) -> int:
	try:
		return int(float(options.get(key, default_value)))
	except (TypeError, ValueError):
		return default_value


def optional_value(options: dict[str, str], *keys: str) -> str:
	for key in keys:
		value = options.get(key)
		if value not in (None, ""):
			return value
	return ""


def bool_option(options: dict[str, str], key: str, default_value: bool) -> bool:
	value = options.get(key)
	if value in (None, ""):
		return default_value
	return normalized_value(value) in {"1", "true", "yes", "y", "on"}


def pandas_module():
	try:
		import pandas as pd  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		print("ERROR: pandas is required for this report. Install it in the scripts environment with: python3 -m pip install pandas")
		sys.exit(1)
	return pd


def linear_regression_class():
	try:
		from sklearn.linear_model import LinearRegression  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return None
	return LinearRegression


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


def call_checklist_json_script(arguments: list[str], options: dict[str, str]) -> str:
	checklist_arguments = list(arguments)
	if not any(argument.startswith("limit=") for argument in checklist_arguments[4:]):
		checklist_arguments.append(f"limit={max(1, optional_int(options, 'checklistLimit', DEFAULT_CHECKLIST_LIMIT))}")
	if not any(argument.startswith("page=") for argument in checklist_arguments[4:]):
		checklist_arguments.append("page=1")
	return call_json_script("checklist", CHECKLIST_SCRIPT_NAME, checklist_arguments, "checklist")


def call_patch_data_json_script(arguments: list[str], options: dict[str, str]) -> str:
	patch_arguments = list(arguments)
	for option in ["critical=true", "high=true", "medium=true", "low=true", "info=true", "groupby=false"]:
		key = option.split("=", 1)[0]
		if not any(argument.startswith(f"{key}=") for argument in patch_arguments[4:]):
			patch_arguments.append(option)
	if not any(argument.startswith("closed=") for argument in patch_arguments[4:]):
		patch_arguments.append(f"closed={'true' if bool_option(options, 'patchClosed', False) else 'false'}")
	return call_json_script("patch-vulnerability", PATCH_DATA_SCRIPT_NAME, patch_arguments, "patch data")


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


def numeric_value(value):
	if isinstance(value, bool):
		return int(value)
	if isinstance(value, (int, float)) and not isinstance(value, bool):
		if math.isnan(value) if isinstance(value, float) else False:
			return None
		return float(value)
	if isinstance(value, str):
		cleaned = value.strip().replace(",", "")
		if not cleaned:
			return None
		try:
			return float(cleaned)
		except ValueError:
			return None
	return None


def count_value(value) -> int:
	number = numeric_value(value)
	if number is not None:
		return max(0, int(number))
	if isinstance(value, list):
		return len(value)
	return 0


def sum_count_keys(record: dict, keys: list[str]) -> int:
	total = 0
	for key in keys:
		if key in record:
			total += count_value(record[key])
	return total


def first_count_from_keys(record: dict, keys: list[str]):
	for key in keys:
		if key in record:
			return count_value(record[key])
	return None


def checklist_open_count(record: dict) -> int:
	total_count = first_count_from_keys(record, CHECKLIST_OPEN_TOTAL_KEYS)
	if total_count is not None:
		return total_count
	return sum_count_keys(record, CHECKLIST_OPEN_CATEGORY_KEYS)


def patch_open_count(record: dict) -> int:
	total_count = first_count_from_keys(record, PATCH_OPEN_TOTAL_KEYS)
	if total_count is not None:
		return total_count
	return sum_count_keys(record, PATCH_OPEN_SEVERITY_COUNT_KEYS)


def status_is_open(status: str) -> bool:
	status_key = normalized_value(status)
	if not status_key:
		return False
	return any(token in status_key for token in ["open", "fail", "failed", "not reviewed", "not_reviewed", "non-compliant", "noncompliant", "vulnerable"])


def status_is_closed(status: str) -> bool:
	status_key = normalized_value(status)
	if not status_key:
		return False
	return any(token in status_key for token in ["closed", "pass", "passed", "not a finding", "not_applicable", "not applicable", "fixed", "complete"])


def record_hostname(record: dict) -> str:
	for key in HOSTNAME_KEYS:
		value = record.get(key)
		if value not in (None, ""):
			text = display_value(value)
			return text.split(".", 1)[0].lower() if "." in text else text.lower()
	return ""


def extract_ips(record: dict) -> list[str]:
	ips = []
	for key in IP_KEYS:
		value = record.get(key)
		values = value if isinstance(value, list) else [value]
		for item in values:
			text = display_value(item)
			if text and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
				ips.append(text)
	return sorted(set(ips))


def record_identity_key(record: dict) -> str:
	hostname = record_hostname(record)
	if hostname:
		return f"host:{hostname}"
	ips = extract_ips(record)
	if ips:
		return f"ip:{ips[0]}"
	return ""


def record_display_name(record: dict) -> str:
	return display_value(first_record_value(record, HOSTNAME_KEYS)) or display_value(first_record_value(record, IP_KEYS)) or "Unknown Asset"


def looks_like_checklist_record(record: dict) -> bool:
	keys = set(record)
	return bool(keys & set(CHECKLIST_STATUS_KEYS + CHECKLIST_OPEN_COUNT_KEYS + CHECKLIST_TOTAL_COUNT_KEYS + HOSTNAME_KEYS + IP_KEYS))


def looks_like_patch_record(record: dict) -> bool:
	keys = set(record)
	return bool(keys & set(PATCH_OPEN_COUNT_KEYS + PATCH_SEVERITY_KEYS + DATE_KEYS + HOSTNAME_KEYS + IP_KEYS))


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


def checklist_records(checklist_data) -> list[dict]:
	return find_record_list(checklist_data, ["records", "items", "data", "results", "checklists", "checklist", "assets", "devices", "findings", "stigItems"], looks_like_checklist_record)


def patch_records(patch_data) -> list[dict]:
	return find_record_list(patch_data, ["records", "items", "data", "results", "assets", "devices", "hosts", "patchData", "patches", "vulnerabilities", "findings"], looks_like_patch_record)


def build_checklist_dataframe(pd, records: list[dict]):
	rows = []
	for record in records:
		asset_key = record_identity_key(record)
		if not asset_key:
			continue
		status = first_record_value(record, CHECKLIST_STATUS_KEYS)
		open_count = checklist_open_count(record)
		total_count = sum_count_keys(record, CHECKLIST_TOTAL_COUNT_KEYS)
		if open_count == 0 and status_is_open(status):
			open_count = 1
		if total_count == 0:
			total_count = max(1, open_count, 1 if status else 0)
		closed_count = 1 if status_is_closed(status) and open_count == 0 else max(0, total_count - open_count)
		rows.append(
			{
				"asset_key": asset_key,
				"asset": record_display_name(record),
				"open_stig_items": open_count,
				"total_stig_items": total_count,
				"closed_stig_items": closed_count,
			}
		)
	dataframe = pd.DataFrame(rows)
	if dataframe.empty:
		return pd.DataFrame(columns=["asset_key", "asset", "open_stig_items", "total_stig_items", "closed_stig_items"])
	return dataframe.groupby("asset_key", as_index=False).agg({"asset": "first", "open_stig_items": "sum", "total_stig_items": "sum", "closed_stig_items": "sum"})


def build_patch_dataframe(pd, records: list[dict]):
	rows = []
	for record in records:
		asset_key = record_identity_key(record)
		if not asset_key:
			continue
		open_count = patch_open_count(record)
		if open_count == 0:
			open_count = 1
		rows.append(
			{
				"asset_key": asset_key,
				"asset": record_display_name(record),
				"open_patch_vulnerabilities": open_count,
				"patch_scan_date": display_value(first_record_value(record, DATE_KEYS)) or "Unknown",
			}
		)
	dataframe = pd.DataFrame(rows)
	if dataframe.empty:
		return pd.DataFrame(columns=["asset_key", "asset", "open_patch_vulnerabilities", "patch_scan_date"])
	return dataframe.groupby("asset_key", as_index=False).agg({"asset": "first", "open_patch_vulnerabilities": "sum", "patch_scan_date": "first"})


def generated_timestamp(options: dict[str, str]) -> datetime:
	value = optional_value(options, "generatedAt", "snapshotDate", "snapshot_date")
	if value:
		try:
			return datetime.fromisoformat(value.replace("Z", "+00:00"))
		except ValueError:
			print(f"WARNING: Could not parse generatedAt={value}; using current UTC time.")
	return datetime.now(timezone.utc)


def default_snapshot_path(system_key: str) -> Path:
	return Path(__file__).resolve().parent / f"compliance-drift-history-{safe_filename_value(system_key)}.csv"


def resolve_snapshot_path(options: dict[str, str], system_key: str) -> Path:
	value = optional_value(options, "snapshotCsv", "historyCsv")
	if value:
		return Path(value).expanduser()
	return default_snapshot_path(system_key)


def build_current_snapshot(pd, checklist_df, patch_df, snapshot_time: datetime):
	merged = checklist_df.merge(patch_df, on="asset_key", how="outer", suffixes=("_checklist", "_patch"))
	if merged.empty:
		merged = pd.DataFrame(columns=["asset_key", "asset_checklist", "asset_patch", "open_stig_items", "total_stig_items", "closed_stig_items", "open_patch_vulnerabilities", "patch_scan_date"])
	for column in ["open_stig_items", "total_stig_items", "closed_stig_items", "open_patch_vulnerabilities"]:
		if column not in merged.columns:
			merged[column] = 0
		merged[column] = merged[column].fillna(0).astype(int)
	if "asset_checklist" not in merged.columns:
		merged["asset_checklist"] = ""
	if "asset_patch" not in merged.columns:
		merged["asset_patch"] = ""
	if "patch_scan_date" not in merged.columns:
		merged["patch_scan_date"] = "Unknown"
	merged["asset"] = merged.apply(lambda row: display_value(row.get("asset_checklist")) or display_value(row.get("asset_patch")) or row.get("asset_key", "Unknown Asset"), axis=1)
	merged["total_stig_items"] = merged.apply(lambda row: max(int(row["total_stig_items"]), int(row["open_stig_items"] + row["closed_stig_items"]), 1), axis=1)
	merged["compliance_score"] = ((merged["total_stig_items"] - merged["open_stig_items"]) / merged["total_stig_items"] * 100).clip(lower=0, upper=100)
	merged["snapshot_date"] = pd.to_datetime(snapshot_time.isoformat())
	return merged[["snapshot_date", "asset_key", "asset", "open_stig_items", "total_stig_items", "closed_stig_items", "open_patch_vulnerabilities", "compliance_score", "patch_scan_date"]]


def load_history(pd, snapshot_path: Path):
	columns = ["snapshot_date", "asset_key", "asset", "open_stig_items", "total_stig_items", "closed_stig_items", "open_patch_vulnerabilities", "compliance_score", "patch_scan_date"]
	if not snapshot_path.exists():
		return pd.DataFrame(columns=columns)
	try:
		dataframe = pd.read_csv(snapshot_path)
	except Exception as exc:
		print(f"WARNING: Could not read snapshot history {snapshot_path}: {exc}")
		return pd.DataFrame(columns=columns)
	for column in columns:
		if column not in dataframe.columns:
			dataframe[column] = "" if column in {"asset_key", "asset", "patch_scan_date"} else 0
	return dataframe[columns]


def update_history(pd, snapshot_path: Path, history_df, current_df):
	combined = pd.concat([history_df, current_df], ignore_index=True)
	combined["snapshot_date"] = pd.to_datetime(combined["snapshot_date"], errors="coerce")
	combined = combined.dropna(subset=["snapshot_date", "asset_key"])
	combined = combined.sort_values(["asset_key", "snapshot_date"])
	combined["snapshot_day"] = combined["snapshot_date"].dt.strftime("%Y-%m-%d")
	combined = combined.drop_duplicates(subset=["asset_key", "snapshot_day"], keep="last")
	combined = combined.drop(columns=["snapshot_day"])
	snapshot_path.parent.mkdir(parents=True, exist_ok=True)
	combined.to_csv(snapshot_path, index=False)
	return combined


def add_time_series_features(pd, dataframe):
	if dataframe.empty:
		return dataframe
	features = dataframe.copy()
	features["snapshot_date"] = pd.to_datetime(features["snapshot_date"], errors="coerce")
	for column in ["open_stig_items", "open_patch_vulnerabilities", "compliance_score"]:
		features[column] = pd.to_numeric(features[column], errors="coerce").fillna(0.0)
	features = features.sort_values(["asset_key", "snapshot_date"])
	features["previous_snapshot_date"] = features.groupby("asset_key")["snapshot_date"].shift(1)
	features["days_since_previous"] = (features["snapshot_date"] - features["previous_snapshot_date"]).dt.total_seconds() / 86400
	features["days_since_previous"] = features["days_since_previous"].replace(0, 1).fillna(0)
	features["stig_delta"] = features.groupby("asset_key")["open_stig_items"].diff().fillna(0)
	features["patch_delta"] = features.groupby("asset_key")["open_patch_vulnerabilities"].diff().fillna(0)
	features["new_open_stig_items"] = features["stig_delta"].clip(lower=0)
	features["new_open_patch_vulnerabilities"] = features["patch_delta"].clip(lower=0)
	features["weekly_stig_velocity"] = features.apply(lambda row: (row["new_open_stig_items"] / row["days_since_previous"] * 7) if row["days_since_previous"] > 0 else 0, axis=1)
	features["weekly_patch_velocity"] = features.apply(lambda row: (row["new_open_patch_vulnerabilities"] / row["days_since_previous"] * 7) if row["days_since_previous"] > 0 else 0, axis=1)
	features["daily_vulnerability_velocity"] = features.apply(lambda row: ((row["new_open_stig_items"] + row["new_open_patch_vulnerabilities"]) / row["days_since_previous"]) if row["days_since_previous"] > 0 else 0, axis=1)
	features["weekly_vulnerability_velocity"] = features["weekly_stig_velocity"] + features["weekly_patch_velocity"]
	features["compliance_score_rolling_7d"] = features.groupby("asset_key")["compliance_score"].transform(lambda series: series.rolling(window=7, min_periods=1).mean())
	features["compliance_drift"] = features.groupby("asset_key")["compliance_score"].diff().fillna(0)
	return features


def estimate_rule_based_days(row) -> str:
	compliance_score = float(row.get("compliance_score", 0) or 0)
	if compliance_score < COMPLIANCE_THRESHOLD:
		return "0"
	drift = float(row.get("compliance_drift", 0) or 0)
	weekly_velocity = float(row.get("weekly_vulnerability_velocity", 0) or 0)
	if drift < 0:
		daily_decline = abs(drift) / max(float(row.get("days_since_previous", 0) or 0), 1.0)
	elif weekly_velocity > 0:
		daily_decline = max(0.1, weekly_velocity * 0.2 / 7)
	else:
		return "No current downward trend"
	return str(int(math.ceil((compliance_score - COMPLIANCE_THRESHOLD) / daily_decline)))


def add_regression_predictions(pd, features, options: dict[str, str]):
	if features.empty:
		return features, "No history rows were available for regression."
	result = features.copy()
	result["predicted_days_below_80"] = "Insufficient history"
	result["model_method"] = "rule-based fallback"
	min_model_rows = max(3, optional_int(options, "minModelRows", DEFAULT_MIN_MODEL_ROWS))
	LinearRegression = linear_regression_class()
	current_rows = result.sort_values("snapshot_date").groupby("asset_key", as_index=False).tail(1).copy()
	if LinearRegression is None:
		result.loc[current_rows.index, "predicted_days_below_80"] = current_rows.apply(estimate_rule_based_days, axis=1)
		return result, "scikit-learn is not installed; used rule-based projection. Install with: python3 -m pip install scikit-learn"
	training = result.dropna(subset=["compliance_score", "weekly_patch_velocity", "weekly_stig_velocity", "weekly_vulnerability_velocity", "compliance_drift"]).copy()
	if len(training) < min_model_rows:
		result.loc[current_rows.index, "predicted_days_below_80"] = current_rows.apply(estimate_rule_based_days, axis=1)
		return result, f"Only {len(training)} history rows were available; used rule-based projection until at least {min_model_rows} rows exist."
	training["days_since_first"] = training.groupby("asset_key")["snapshot_date"].transform(lambda series: (series - series.min()).dt.total_seconds() / 86400)
	feature_columns = ["days_since_first", "weekly_patch_velocity", "weekly_stig_velocity", "weekly_vulnerability_velocity", "compliance_drift"]
	model = LinearRegression()
	model.fit(training[feature_columns], training["compliance_score"])
	predictions = []
	for index, row in current_rows.iterrows():
		if float(row.get("compliance_score", 0) or 0) < COMPLIANCE_THRESHOLD:
			predictions.append((index, "0"))
			continue
		asset_history = training[training["asset_key"] == row["asset_key"]]
		base_days = float(asset_history["days_since_first"].max() if not asset_history.empty else 0)
		predicted_days = "No predicted drop in 365 days"
		for day_offset in range(1, 366):
			candidate = pd.DataFrame([{**{column: float(row.get(column, 0) or 0) for column in feature_columns}, "days_since_first": base_days + day_offset}])
			predicted_score = float(model.predict(candidate[feature_columns])[0])
			if predicted_score < COMPLIANCE_THRESHOLD:
				predicted_days = str(day_offset)
				break
		predictions.append((index, predicted_days))
	for index, predicted_days in predictions:
		result.at[index, "predicted_days_below_80"] = predicted_days
		result.at[index, "model_method"] = "LinearRegression"
	return result, f"Regression model available with {len(training)} history rows."


def latest_asset_rows(features, top_rows: int) -> list[dict[str, str]]:
	if features.empty:
		return []
	latest = features.sort_values("snapshot_date").groupby("asset_key", as_index=False).tail(1).copy()
	latest["risk_sort"] = latest["predicted_days_below_80"].apply(lambda value: int(value) if safe_text(value).isdigit() else 9999)
	latest = latest.sort_values(["risk_sort", "compliance_score", "weekly_vulnerability_velocity"], ascending=[True, True, False])
	rows = []
	for _, row in latest.head(top_rows).iterrows():
		rows.append(
			{
				"asset": display_value(row.get("asset")) or display_value(row.get("asset_key")),
				"compliance": f"{float(row.get('compliance_score', 0) or 0):.1f}%",
				"rolling": f"{float(row.get('compliance_score_rolling_7d', 0) or 0):.1f}%",
				"open_stig": str(int(float(row.get("open_stig_items", 0) or 0))),
				"open_patch": str(int(float(row.get("open_patch_vulnerabilities", 0) or 0))),
				"weekly_velocity": f"{float(row.get('weekly_vulnerability_velocity', 0) or 0):.1f}",
				"prediction": safe_text(row.get("predicted_days_below_80", "Unknown")),
			}
		)
	return rows


def weekly_velocity_rows(pd, features, week_count: int) -> list[dict[str, str]]:
	if features.empty:
		return []
	weekly = features.copy()
	weekly["snapshot_date"] = pd.to_datetime(weekly["snapshot_date"], errors="coerce")
	weekly = weekly.dropna(subset=["snapshot_date"])
	if weekly.empty:
		return []
	for column in ["new_open_stig_items", "new_open_patch_vulnerabilities"]:
		if column not in weekly.columns:
			weekly[column] = 0
		weekly[column] = pd.to_numeric(weekly[column], errors="coerce").fillna(0)
	weekly["week_period"] = weekly["snapshot_date"].dt.to_period("W-SAT")
	grouped = weekly.groupby("week_period", as_index=False).agg({"new_open_stig_items": "sum", "new_open_patch_vulnerabilities": "sum"})
	if grouped.empty:
		return []
	grouped = grouped.sort_values("week_period").tail(max(1, week_count))
	rows = []
	for _, row in grouped.iterrows():
		week_period = row["week_period"]
		stig_count = int(float(row.get("new_open_stig_items", 0) or 0))
		patch_count = int(float(row.get("new_open_patch_vulnerabilities", 0) or 0))
		rows.append(
			{
				"week_start": week_period.start_time.strftime("%Y-%m-%d"),
				"week_end": week_period.end_time.strftime("%Y-%m-%d"),
				"week_label": f"{week_period.start_time.strftime('%m/%d')}–{week_period.end_time.strftime('%m/%d')}",
				"new_open_stig": str(stig_count),
				"new_open_patch": str(patch_count),
				"total_new_open": str(stig_count + patch_count),
			}
		)
	return rows


def weekday_velocity_rows(pd, features) -> list[dict[str, str]]:
	if features.empty:
		return []
	daily = features.copy()
	daily["snapshot_date"] = pd.to_datetime(daily["snapshot_date"], errors="coerce")
	daily = daily.dropna(subset=["snapshot_date"])
	if daily.empty:
		return []
	for column in ["new_open_stig_items", "new_open_patch_vulnerabilities"]:
		if column not in daily.columns:
			daily[column] = 0
		daily[column] = pd.to_numeric(daily[column], errors="coerce").fillna(0)
	daily["week_period"] = daily["snapshot_date"].dt.to_period("W-SAT")
	latest_period = daily["week_period"].max()
	daily = daily[daily["week_period"] == latest_period].copy()
	daily["weekday_index"] = daily["snapshot_date"].dt.dayofweek.map({6: 0, 0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 6})
	grouped = daily.groupby("weekday_index", as_index=False).agg({"new_open_stig_items": "sum", "new_open_patch_vulnerabilities": "sum"})
	counts_by_day = {int(row["weekday_index"]): row for _, row in grouped.iterrows()}
	rows = []
	for index, weekday in enumerate(WEEKDAY_NAMES):
		row = counts_by_day.get(index)
		stig_count = int(float(row.get("new_open_stig_items", 0) if row is not None else 0))
		patch_count = int(float(row.get("new_open_patch_vulnerabilities", 0) if row is not None else 0))
		rows.append(
			{
				"weekday": weekday,
				"new_open_stig": str(stig_count),
				"new_open_patch": str(patch_count),
				"total_new_open": str(stig_count + patch_count),
			}
		)
	return rows


def build_report_data(system_key: str, options: dict[str, str], system_package, checklist_data, patch_data) -> dict[str, object]:
	pd = pandas_module()
	snapshot_time = generated_timestamp(options)
	checklist_record_list = checklist_records(checklist_data)
	patch_record_list = patch_records(patch_data)
	checklist_df = build_checklist_dataframe(pd, checklist_record_list)
	patch_df = build_patch_dataframe(pd, patch_record_list)
	current_df = build_current_snapshot(pd, checklist_df, patch_df, snapshot_time)
	snapshot_path = resolve_snapshot_path(options, system_key)
	history_df = load_history(pd, snapshot_path)
	combined_df = update_history(pd, snapshot_path, history_df, current_df)
	features = add_time_series_features(pd, combined_df)
	features, model_note = add_regression_predictions(pd, features, options)
	top_rows = max(1, optional_int(options, "topRows", DEFAULT_TOP_ROWS))
	weekly_graph_weeks = max(1, optional_int(options, "weeklyGraphWeeks", DEFAULT_WEEKLY_GRAPH_WEEKS))
	latest_rows = latest_asset_rows(features, top_rows)
	weekly_rows = weekly_velocity_rows(pd, features, weekly_graph_weeks)
	weekday_rows = weekday_velocity_rows(pd, features)
	latest = features.sort_values("snapshot_date").groupby("asset_key", as_index=False).tail(1) if not features.empty else pd.DataFrame()
	assets_below_threshold = int((latest["compliance_score"] < COMPLIANCE_THRESHOLD).sum()) if not latest.empty else 0
	average_compliance = float(latest["compliance_score"].mean()) if not latest.empty else 0.0
	total_weekly_velocity = float(latest["weekly_vulnerability_velocity"].sum()) if not latest.empty else 0.0
	system_title = first_json_value(system_package, {"title", "systemTitle", "name", "systemName"}) or system_key
	system_description = first_json_value(system_package, {"description", "systemDescription", "summary"}) or "Unknown"
	return {
		"report_title": f"{system_title} Compliance Drift Model",
		"generated_at": snapshot_time.isoformat(),
		"system_key": system_key,
		"system_title": system_title,
		"system_description": system_description,
		"snapshot_csv": str(snapshot_path),
		"analysis": {
			"checklist_record_count": len(checklist_record_list),
			"patch_record_count": len(patch_record_list),
			"asset_count": int(len(latest)) if not latest.empty else 0,
			"history_row_count": int(len(features)),
			"assets_below_threshold": assets_below_threshold,
			"average_compliance": f"{average_compliance:.1f}%",
			"total_weekly_velocity": f"{total_weekly_velocity:.1f}",
			"model_note": model_note,
			"weekly_rows": weekly_rows,
			"weekday_rows": weekday_rows,
			"latest_rows": latest_rows,
		},
	}


def pdf_table(rows, column_widths, styles, table_style):
	from reportlab.platypus import Paragraph, Table  # pyright: ignore[reportMissingModuleSource]
	wrapped_rows = []
	for row in rows:
		wrapped_rows.append([Paragraph(html.escape(safe_text(cell)), styles["BodyText"]) for cell in row])
	table = Table(wrapped_rows, colWidths=column_widths, repeatRows=1)
	table.setStyle(table_style)
	return table


def compact_pdf_table(rows, column_widths, styles, table_style):
	from reportlab.lib.enums import TA_CENTER  # pyright: ignore[reportMissingModuleSource]
	from reportlab.platypus import Paragraph, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]

	header_style = styles["BodyText"].clone("CenteredHeaderText")
	header_style.alignment = TA_CENTER
	wrapped_rows = []
	for row_index, row in enumerate(rows):
		wrapped_row = []
		for cell in row:
			cell_text = html.escape(safe_text(cell))
			wrapped_row.append(Paragraph(cell_text, header_style if row_index == 0 else styles["BodyText"]))
		wrapped_rows.append(wrapped_row)
	table = Table(wrapped_rows, colWidths=column_widths, repeatRows=1)
	table.setStyle(table_style)
	table.setStyle(
		TableStyle(
			[
				("ALIGN", (0, 0), (-1, 0), "CENTER"),
				("ALIGN", (1, 0), (-1, -1), "CENTER"),
				("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
			]
		)
	)
	return table


def weekly_velocity_chart(weekday_rows: list[dict[str, str]]):
	from reportlab.graphics.shapes import Drawing, Line, Rect, String  # pyright: ignore[reportMissingModuleSource]
	from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]

	width = 385
	height = 230
	left_margin = 42
	bottom_margin = 52
	chart_width = width - left_margin - 20
	chart_height = height - bottom_margin - 24
	drawing = Drawing(width, height)
	drawing.add(Line(left_margin, bottom_margin, left_margin + chart_width, bottom_margin, strokeColor=colors.grey, strokeWidth=0.6))
	drawing.add(Line(left_margin, bottom_margin, left_margin, bottom_margin + chart_height, strokeColor=colors.grey, strokeWidth=0.6))
	drawing.add(String(6, bottom_margin + chart_height / 2, "Count", fontSize=8, fillColor=colors.black))
	if not weekday_rows:
		drawing.add(String(left_margin + 40, bottom_margin + 75, "No weekly history available yet.", fontSize=10, fillColor=colors.grey))
		return drawing
	max_total = max(int(row.get("total_new_open", "0") or 0) for row in weekday_rows) or 1
	bar_group_width = chart_width / max(len(weekday_rows), 1)
	bar_width = min(18, max(6, (bar_group_width - 12) / 2))
	for index, row in enumerate(weekday_rows):
		stig_count = int(row.get("new_open_stig", "0") or 0)
		patch_count = int(row.get("new_open_patch", "0") or 0)
		x_origin = left_margin + index * bar_group_width + (bar_group_width - (bar_width * 2 + 4)) / 2
		stig_height = chart_height * (stig_count / max_total)
		patch_height = chart_height * (patch_count / max_total)
		drawing.add(Rect(x_origin, bottom_margin, bar_width, stig_height, fillColor=colors.HexColor("#4472C4"), strokeColor=colors.HexColor("#4472C4")))
		drawing.add(Rect(x_origin + bar_width + 4, bottom_margin, bar_width, patch_height, fillColor=colors.HexColor("#ED7D31"), strokeColor=colors.HexColor("#ED7D31")))
		label_center = x_origin + bar_width + 2
		drawing.add(String(label_center, bottom_margin - 14, safe_text(row.get("weekday", "")), fontSize=6, fillColor=colors.black, textAnchor="middle"))
		if stig_count:
			drawing.add(String(x_origin, bottom_margin + stig_height + 3, str(stig_count), fontSize=6, fillColor=colors.HexColor("#4472C4")))
		if patch_count:
			drawing.add(String(x_origin + bar_width + 4, bottom_margin + patch_height + 3, str(patch_count), fontSize=6, fillColor=colors.HexColor("#ED7D31")))
	drawing.add(String(8, bottom_margin + chart_height - 2, str(max_total), fontSize=7, fillColor=colors.grey))
	drawing.add(String(20, bottom_margin - 2, "0", fontSize=7, fillColor=colors.grey))
	return drawing


def weekly_velocity_chart_with_legend(weekday_rows: list[dict[str, str]], styles, table_style):
	from reportlab.platypus import Paragraph, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]

	legend_style = table_style
	legend_rows = [
		[Paragraph("Legend", styles["BodyText"])],
		[Paragraph('<font color="#4472C4">■</font> STIG items', styles["BodyText"])],
		[Paragraph('<font color="#ED7D31">■</font> Patch vulnerabilities', styles["BodyText"])],
	]
	legend_table = Table(legend_rows, colWidths=[120])
	legend_table.setStyle(legend_style)
	chart_table = Table([[weekly_velocity_chart(weekday_rows), legend_table]], colWidths=[385, 125])
	chart_table.setStyle(
		TableStyle(
			[
				("VALIGN", (0, 0), (-1, -1), "TOP"),
				("LEFTPADDING", (0, 0), (-1, -1), 0),
				("RIGHTPADDING", (0, 0), (-1, -1), 0),
				("TOPPADDING", (0, 0), (-1, -1), 0),
				("BOTTOMPADDING", (0, 0), (-1, -1), 0),
			]
		)
	)
	return chart_table


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, object]) -> bool:
	try:
		from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
		from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
		from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
	except ImportError:
		return False

	styles = getSampleStyleSheet()
	contents_link_style = styles["BodyText"].clone("ContentsLink")
	contents_link_style.textColor = colors.blue
	contents_link_style.fontSize = 10
	contents_link_style.leading = 12
	table_header_style = styles["BodyText"].clone("CenteredTableHeader")
	table_header_style.alignment = 1
	table_header_style.fontName = "Helvetica-Bold"
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
	analysis = report_data.get("analysis", {})
	if not isinstance(analysis, dict):
		analysis = {}

	def anchored_heading(title: str, anchor: str):
		return Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', styles["Heading2"])

	def contents_link(title: str, anchor: str):
		return Paragraph(f'<a href="#{html.escape(anchor, quote=True)}" color="blue">{html.escape(title)}</a>', contents_link_style)

	def build_report_links_table():
		links_rows = [
			[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)],
			[contents_link("Compliance Drift Summary", "compliance-drift-summary"), "2"],
			[contents_link("Open STIG Items and Patch Vulnerabilities by Week", "weekly-vulnerability-velocity"), "3"],
			[contents_link("Asset Velocity and Prediction", "asset-velocity-prediction"), "4"],
		]
		links_table = Table(links_rows, hAlign="LEFT", colWidths=[380, 80])
		links_table.setStyle(
			TableStyle(
				[
					("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
					("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
					("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
					("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
					("ALIGN", (1, 1), (1, -1), "CENTER"),
				]
			)
		)
		return links_table

	document = SimpleDocTemplate(str(output_path), pagesize=letter, leftMargin=36, rightMargin=36, title=safe_text(report_data["report_title"]), author="OpenRMF Professional External API Scripts")
	story = [
		Paragraph(html.escape(safe_text(report_data["report_title"])), styles["Title"]),
		Spacer(1, 18),
		Paragraph(f"Date Generated: {html.escape(safe_text(report_data['generated_at']))}", styles["Normal"]),
		Paragraph(f"System Title: {html.escape(safe_text(report_data['system_title']))}", styles["Normal"]),
		Paragraph(f"System Key: {html.escape(safe_text(report_data['system_key']))}", styles["Normal"]),
		Paragraph(f"Description: {html.escape(safe_text(report_data['system_description']))}", styles["Normal"]),
		Spacer(1, 24),
		build_report_links_table(),
		PageBreak(),
		anchored_heading("Compliance Drift Summary", "compliance-drift-summary"),
	]
	summary_rows = [
		["Metric", "Value"],
		["Assets Analyzed", analysis.get("asset_count", 0)],
		["Checklist Records", analysis.get("checklist_record_count", 0)],
		["Patch Records", analysis.get("patch_record_count", 0)],
		["History Rows", analysis.get("history_row_count", 0)],
		["Assets Below 80%", analysis.get("assets_below_threshold", 0)],
		["Average Compliance", analysis.get("average_compliance", "0.0%")],
		["Weekly Vulnerability Velocity", analysis.get("total_weekly_velocity", "0.0")],
	]
	story.extend([Spacer(1, 8), pdf_table(summary_rows, [260, 220], styles, table_style)])
	weekly_rows = analysis.get("weekly_rows", [])
	weekday_rows = analysis.get("weekday_rows", [])
	story.extend([PageBreak(), anchored_heading("Open STIG Items and Patch Vulnerabilities by Week", "weekly-vulnerability-velocity"), Spacer(1, 8)])
	if isinstance(weekday_rows, list) and weekday_rows:
		story.extend([weekly_velocity_chart_with_legend(weekday_rows, styles, table_style), Spacer(1, 8)])
	if isinstance(weekly_rows, list) and weekly_rows:
		weekly_table_rows = [["Week", "New Open STIG", "New Open Patch", "Total New Open"]]
		for row in weekly_rows:
			if isinstance(row, dict):
				weekly_table_rows.append([f"{row['week_start']} to {row['week_end']}", row["new_open_stig"], row["new_open_patch"], row["total_new_open"]])
		story.append(pdf_table(weekly_table_rows, [190, 95, 105, 100], styles, table_style))
	else:
		story.append(Paragraph("Run this report on multiple days to build enough snapshot history for weekly new-open counts.", styles["Normal"]))
	rows = [["Asset", "Compliance", "7-Run Avg", "Open STIG", "Open Patch", "Weekly Velocity", "Days until asset drops below 80%"]]
	for row in analysis.get("latest_rows", []):
		if isinstance(row, dict):
			rows.append([row["asset"], row["compliance"], row["rolling"], row["open_stig"], row["open_patch"], row["weekly_velocity"], row["prediction"]])
	story.extend([PageBreak(), anchored_heading("Asset Velocity and Prediction", "asset-velocity-prediction"), Spacer(1, 8)])
	if len(rows) > 1:
		story.append(compact_pdf_table(rows, [105, 80, 55, 55, 55, 70, 120], styles, table_style))
	else:
		story.append(Paragraph("No asset rows were available from checklist or patch data.", styles["Normal"]))
	document.build(story)
	return True


def escape_pdf_text(value: str) -> str:
	return safe_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 12) -> str:
	stream_lines = ["BT", f"/F1 {font_size} Tf", "72 720 Td"]
	for index, line in enumerate(lines):
		if index:
			stream_lines.append("0 -22 Td")
		stream_lines.append(f"({escape_pdf_text(line)}) Tj")
	stream_lines.append("ET")
	return "\n".join(stream_lines)


def write_minimal_pdf(output_path: Path, report_data: dict[str, object]) -> None:
	analysis = report_data.get("analysis", {})
	if not isinstance(analysis, dict):
		analysis = {}
	lines = [
		safe_text(report_data["report_title"]),
		"",
		f"Date Generated: {report_data['generated_at']}",
		f"System Title: {report_data['system_title']}",
		f"System Key: {report_data['system_key']}",
		"",
		"Report Links",
		"2 - Compliance Drift Summary",
		"3 - Open STIG Items and Patch Vulnerabilities by Week",
		"4 - Asset Velocity and Prediction",
		"",
		"Compliance Drift Summary",
		f"Assets Analyzed: {analysis.get('asset_count', 0)}",
		f"Assets Below 80%: {analysis.get('assets_below_threshold', 0)}",
		f"Average Compliance: {analysis.get('average_compliance', '0.0%')}",
		f"Weekly Vulnerability Velocity: {analysis.get('total_weekly_velocity', '0.0')}",
		"",
		"Open STIG Items and Patch Vulnerabilities by Week",
		"X-axis: Sunday-Saturday",
		"Y-axis: Count",
	]
	for row in analysis.get("weekday_rows", []):
		if isinstance(row, dict):
			lines.append(f"{row['weekday']}: STIG {row['new_open_stig']}, Patch {row['new_open_patch']}, Total {row['total_new_open']}")
	lines.append("")
	for row in analysis.get("weekly_rows", [])[:25]:
		if isinstance(row, dict):
			lines.append(f"{row['week_start']} to {row['week_end']}: STIG {row['new_open_stig']}, Patch {row['new_open_patch']}, Total {row['total_new_open']}")
	lines.extend(
		[
		"",
		"Asset Velocity and Prediction",
		]
	)
	for row in analysis.get("latest_rows", [])[:25]:
		if isinstance(row, dict):
			lines.append(f"{row['asset']}: compliance {row['compliance']}, weekly velocity {row['weekly_velocity']}, days <80% {row['prediction']}")
	page_chunks = [lines[index:index + 30] for index in range(0, len(lines), 30)] or [[safe_text(report_data["report_title"])]]
	objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
	page_object_numbers = []
	for chunk in page_chunks:
		page_object_number = len(objects) + 1
		content_object_number = len(objects) + 2
		page_object_numbers.append(page_object_number)
		objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>".encode("latin-1"))
		stream_bytes = make_text_page(chunk).encode("latin-1", errors="replace")
		objects.append(b"<< /Length " + str(len(stream_bytes)).encode("ascii") + b" >>\nstream\n" + stream_bytes + b"\nendstream")
	objects[1] = f"<< /Type /Pages /Kids [{' '.join(f'{page_number} 0 R' for page_number in page_object_numbers)}] /Count {len(page_object_numbers)} >>".encode("latin-1")
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
	checklist_data = parse_json_value_from_output(call_checklist_json_script(base_arguments, options))
	patch_data = parse_json_value_from_output(call_patch_data_json_script(base_arguments, options))
	report_data = build_report_data(system_key, options, system_package, checklist_data, patch_data)
	output_filename = optional_value(options, "outputFile") or f"OpenRMFPro-Compliance-Drift-{safe_filename_value(report_data['system_key'])}.pdf"
	output_path = Path(output_filename).expanduser()
	pdf_writer = write_pdf(output_path, report_data)
	print(f"Created PDF: {output_path}")
	if pdf_writer == "fallback":
		print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
	main()
