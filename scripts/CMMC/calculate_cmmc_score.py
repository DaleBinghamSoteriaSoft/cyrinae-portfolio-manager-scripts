#!/usr/bin/env python3

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

COMMON_DIR = Path(__file__).resolve().parent.parent / "common"
HTTP_STATUS_MODULE_PATH = COMMON_DIR / "http_status_meanings.py"
HTTP_STATUS_SPEC = importlib.util.spec_from_file_location("http_status_meanings", HTTP_STATUS_MODULE_PATH)
if HTTP_STATUS_SPEC is None or HTTP_STATUS_SPEC.loader is None:
    raise ImportError(f"Could not load http_status_meanings from {HTTP_STATUS_MODULE_PATH}")
HTTP_STATUS_MODULE = importlib.util.module_from_spec(HTTP_STATUS_SPEC)
HTTP_STATUS_SPEC.loader.exec_module(HTTP_STATUS_MODULE)
HTTP_STATUS_MEANINGS = HTTP_STATUS_MODULE.HTTP_STATUS_MEANINGS

REQUIRED_ARGUMENT_COUNT = 5
SYSTEMPACKAGE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
COMPLIANCE_SCRIPT_NAME = "get_systempackage_by_systemkey_compliance_json.py"
ALLCONTROLS_SCRIPT_NAME = "get_systempackage_by_systemkey_compliance_by_complianceid_allcontrolscore_json.py"
POAM_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"

VALID_CMMC_LEVELS = {"Level 1", "Level 2", "Level 3"}
CONTROL_STATUS_MET = "MET"
CONTROL_STATUS_OPEN = "OPEN"
CONTROL_STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"
CONTROL_STATUS_NOT_REVIEWED = "NOT_REVIEWED"
CONTROL_STATUS_UNKNOWN = "UNKNOWN"
LEVEL_THREE_PASS_FAIL_NOTE = "Approved implementation treats Level 3 as pass/fail only."

L2_FIVE_POINT_CONTROLS = {
    "AC.L1-3.1.1",
    "AC.L1-3.1.2",
    "AC.L2-3.1.12",
    "AC.L2-3.1.13",
    "AC.L2-3.1.16",
    "AC.L2-3.1.17",
    "AC.L2-3.1.18",
    "AU.L2-3.3.1",
    "AU.L2-3.3.2",
    "CM.L2-3.4.1",
    "CM.L2-3.4.2",
    "CM.L2-3.4.6",
    "CM.L2-3.4.7",
    "CM.L2-3.4.8",
    "IA.L1-3.5.1",
    "IA.L1-3.5.2",
    "IA.L2-3.5.3",
    "IR.L2-3.6.1",
    "IR.L2-3.6.2",
    "MA.L2-3.7.2",
    "MP.L2-3.8.1",
    "MP.L2-3.8.2",
    "MP.L1-3.8.3",
    "PE.L1-3.10.1",
    "PE.L1-3.10.3",
    "PE.L1-3.10.4",
    "PE.L1-3.10.5",
    "RA.L2-3.11.1",
    "CA.L2-3.12.1",
    "CA.L2-3.12.2",
    "CA.L2-3.12.3",
    "CA.L2-3.12.4",
    "SC.L1-3.13.1",
    "SC.L2-3.13.2",
    "SC.L1-3.13.5",
    "SC.L2-3.13.6",
    "SC.L2-3.13.15",
    "SI.L1-3.14.1",
    "SI.L1-3.14.2",
    "SI.L1-3.14.4",
    "SI.L1-3.14.5",
}

L2_THREE_POINT_CONTROLS = {
    "AC.L2-3.1.5",
    "AC.L2-3.1.19",
    "CM.L2-3.4.3",
    "IA.L2-3.5.10",
    "MP.L2-3.8.4",
    "MP.L2-3.8.5",
    "RA.L2-3.11.2",
    "SC.L2-3.13.11",
    "SC.L2-3.13.16",
    "SI.L2-3.14.3",
    "SI.L2-3.14.6",
    "SI.L2-3.14.7",
}

L2_FIVE_POINT_CONTROL_NUMBERS = {control_id.split("-", 1)[1] for control_id in L2_FIVE_POINT_CONTROLS}
L2_THREE_POINT_CONTROL_NUMBERS = {control_id.split("-", 1)[1] for control_id in L2_THREE_POINT_CONTROLS}
L2_NO_SCORE_CONTROLS = {"CA.L2-3.12.4"}
L2_NO_SCORE_CONTROL_NUMBERS = {control_id.split("-", 1)[1] for control_id in L2_NO_SCORE_CONTROLS}
L2_NON_POAM_ELIGIBLE_CONTROLS = set(L2_FIVE_POINT_CONTROLS) | {"RA.L2-3.11.2", "CA.L2-3.12.4"}
L2_NON_POAM_ELIGIBLE_CONTROL_NUMBERS = {
    control_id.split("-", 1)[1] for control_id in L2_NON_POAM_ELIGIBLE_CONTROLS
}

L3_FIVE_POINT_CONTROLS = {
    "AC.L3-3.1.3E",
    "CM.L3-3.4.1E",
    "CM.L3-3.4.2E",
    "IA.L3-3.5.1E",
    "IA.L3-3.5.2E",
    "IR.L3-3.6.1E",
    "RA.L3-3.11.1E",
    "RA.L3-3.11.2E",
    "RA.L3-3.11.4E",
    "RA.L3-3.11.5E",
    "SC.L3-3.13.1E",
    "SC.L3-3.13.2E",
    "SC.L3-3.13.3E",
    "SC.L3-3.13.4E",
    "SC.L3-3.13.11E",
    "SI.L3-3.14.1E",
    "SI.L3-3.14.3E",
    "SI.L3-3.14.6E",
    "SI.L3-3.14.7E",
}

L3_ONE_POINT_CONTROLS = {
    "AC.L3-3.1.2E",
    "AT.L3-3.2.1E",
    "SI.L3-3.14.2E",
    "SI.L3-3.14.4E",
    "SI.L3-3.14.5E",
}

L3_ALL_CONTROLS = L3_FIVE_POINT_CONTROLS | L3_ONE_POINT_CONTROLS
L3_SUFFIX_TO_CONTROL_ID = {control_id.split("L3-", 1)[1].upper(): control_id for control_id in L3_ALL_CONTROLS}
CONTROL_DISPLAY_PATTERN = re.compile(r"([A-Z]{2})[.\-]L([123])[.\-](\d+\.\d+\.\d+)([A-Z])?", flags=re.IGNORECASE)


def get_project_python_executable() -> str:
    project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
    if project_python.exists():
        return str(project_python)
    return sys.executable


def print_usage() -> None:
    print("ERROR: Missing required parameters.")
    print(
        "Usage: python3 "
        + Path(__file__).name
        + " <rootURL> <applicationKey> <authorizationToken> <systemKey>"
    )


def fatal_error(message: str, exit_code: int = 1, details: str | None = None) -> None:
    print(f"ERROR: {message}")
    if details:
        print(details)
    sys.exit(exit_code)


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def normalized_text(value) -> str:
    return re.sub(r"\s+", " ", safe_text(value).strip())


def string_key(value: str) -> str:
    return normalized_text(value).lower().replace("_", " ").replace("-", " ")


def format_http_status_hint(output: str) -> str:
    match = re.search(r"HTTP\s+(\d{3})", output)
    if not match:
        return ""

    status_code = int(match.group(1))
    meaning = HTTP_STATUS_MEANINGS.get(status_code)
    if not meaning:
        return ""
    return f" HTTP {status_code} - {meaning}"


def call_child_script(script_path: Path, arguments: list[str], failure_message: str) -> str:
    command = [get_project_python_executable(), str(script_path), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        combined_output = "\n".join(
            part.strip() for part in [result.stdout, result.stderr] if part and part.strip()
        )
        status_hint = format_http_status_hint(combined_output)
        fatal_error(f"{failure_message}.{status_hint}", result.returncode, combined_output or None)

    return result.stdout


def parse_json_from_output(output: str):
    decoder = json.JSONDecoder()
    for index, character in enumerate(output):
        if character not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(output[index:])
        except json.JSONDecodeError:
            continue
        return parsed
    fatal_error("Could not find JSON in child script output.", details=output.strip() or None)


def first_value(record: dict, keys: list[str]):
    for key in keys:
        if key not in record:
            continue
        value = record[key]
        if isinstance(value, (dict, list)):
            continue
        if safe_text(value).strip():
            return value
    return None


def nested_value(value, key_path: list[str]):
    current = value
    for key in key_path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def first_nested_value(record: dict, key_paths: list[list[str]]):
    for key_path in key_paths:
        value = nested_value(record, key_path)
        if isinstance(value, (dict, list)):
            continue
        if safe_text(value).strip():
            return value
    return None


def truthy(value) -> bool | None:
    if isinstance(value, bool):
        return value
    text = string_key(value)
    if text in {"true", "yes", "y", "1"}:
        return True
    if text in {"false", "no", "n", "0"}:
        return False
    return None


def collect_text_fragments(value, fragments: list[str], limit: int = 80) -> None:
    if len(fragments) >= limit:
        return
    if isinstance(value, dict):
        for item in value.values():
            collect_text_fragments(item, fragments, limit)
            if len(fragments) >= limit:
                return
        return
    if isinstance(value, list):
        for item in value:
            collect_text_fragments(item, fragments, limit)
            if len(fragments) >= limit:
                return
        return
    text = normalized_text(value)
    if text:
        fragments.append(text)


def record_text_blob(record: dict, limit: int = 80) -> str:
    fragments = []
    collect_text_fragments(record, fragments, limit)
    return " | ".join(fragments)


def iter_dicts(value):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from iter_dicts(nested)
    elif isinstance(value, list):
        for item in value:
            yield from iter_dicts(item)


def list_of_dicts(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def find_record_list(value, preferred_keys: list[str]) -> list[dict]:
    if isinstance(value, list):
        dict_items = list_of_dicts(value)
        if dict_items:
            return dict_items
        for item in value:
            found = find_record_list(item, preferred_keys)
            if found:
                return found
        return []

    if isinstance(value, dict):
        for key in preferred_keys:
            if key in value:
                found = find_record_list(value[key], preferred_keys)
                if found:
                    return found
        for nested in value.values():
            found = find_record_list(nested, preferred_keys)
            if found:
                return found
    return []


def build_framework_levels(package_framework: dict) -> list[dict[str, str]]:
    framework_levels = package_framework.get("frameworkLevels", [])
    if not isinstance(framework_levels, list):
        return []

    levels = []
    for level in framework_levels:
        if not isinstance(level, dict):
            continue
        category = normalized_text(level.get("levelCategory"))
        value = normalized_text(level.get("levelValue"))
        category_and_value = normalized_text(level.get("levelCategoryAndValue"))
        if category or value or category_and_value:
            levels.append(
                {
                    "category": category,
                    "value": value,
                    "categoryAndValue": category_and_value,
                }
            )
    return levels


def normalize_cmmc_level_value(value: str) -> str | None:
    value_text = string_key(value)
    if not value_text:
        return None

    for level_number in (1, 2, 3):
        if value_text == str(level_number):
            return f"Level {level_number}"
        if value_text == f"level {level_number}":
            return f"Level {level_number}"
        if value_text.endswith(f" level {level_number}"):
            return f"Level {level_number}"
        if value_text.startswith(f"level {level_number} "):
            return f"Level {level_number}"
        if f"cmmc level {level_number}" in value_text:
            return f"Level {level_number}"
    return None


def control_number_key(value: str) -> str:
    raw_text = normalized_text(value)
    if not raw_text:
        return ""

    display_match = CONTROL_DISPLAY_PATTERN.search(raw_text)
    if display_match:
        number = display_match.group(3)
        suffix = (display_match.group(4) or "").upper()
        return f"{number}{suffix}"

    upper_text = raw_text.upper()
    suffix_match = re.search(r"(\d+\.\d+\.\d+[A-Z])", upper_text)
    if suffix_match:
        return suffix_match.group(1)

    numeric_match = re.search(r"(\d+\.\d+\.\d+)", raw_text)
    if numeric_match:
        return numeric_match.group(1)
    return raw_text


def resolve_cmmc_level(system_package: dict) -> str:
    package_framework = system_package.get("packageFramework", {})
    if not isinstance(package_framework, dict):
        fatal_error("The system package did not include packageFramework metadata.")

    framework_identity_texts = []
    for key in [
        "frameworkAcronym",
        "frameworkTitle",
        "frameworkWithAcronym",
        "frameworkAcronymWithVersion",
        "name",
        "title",
        "shortName",
        "description",
    ]:
        value = normalized_text(package_framework.get(key))
        if value:
            framework_identity_texts.append(value)

    framework_levels = build_framework_levels(package_framework)
    level_candidates = []
    for level in framework_levels:
        level_candidates.append(level.get("category", ""))
        level_candidates.append(level.get("value", ""))
        level_candidates.append(level.get("categoryAndValue", ""))
        level_candidates.append(f"{level.get('category', '')} {level.get('value', '')}".strip())

    resolved_levels = []
    framework_acronym = normalized_text(package_framework.get("frameworkAcronym"))
    is_cmmc_framework = framework_acronym.upper() == "CMMC" or any(
        "cmmc" in text.lower() for text in framework_identity_texts if text
    )
    for candidate in level_candidates:
        normalized_level = normalize_cmmc_level_value(candidate)
        if normalized_level:
            resolved_levels.append(normalized_level)

    unique_levels = sorted(set(level for level in resolved_levels if level in VALID_CMMC_LEVELS))
    if not is_cmmc_framework or not unique_levels:
        fatal_error("The system package is not a CMMC Level 1, 2, or 3 package.")
    if len(unique_levels) != 1:
        fatal_error(
            "The system package returned ambiguous CMMC framework levels.",
            details=json.dumps(framework_levels, indent=2, sort_keys=False),
        )
    return unique_levels[0]


def canonicalize_control_id(value: str) -> str:
    raw_text = normalized_text(value)
    if not raw_text:
        return ""

    display_match = CONTROL_DISPLAY_PATTERN.search(raw_text)
    if display_match:
        family = display_match.group(1).upper()
        level = display_match.group(2)
        control_number = display_match.group(3)
        suffix = (display_match.group(4) or "").upper()
        standardized = f"{family}.L{level}-{control_number}{suffix}"
        if level == "3" and suffix:
            return L3_SUFFIX_TO_CONTROL_ID.get(f"{control_number}{suffix}", standardized)
        return standardized

    upper_text = raw_text.upper()
    suffix_match = re.search(r"(\d+\.\d+\.\d+[A-Z])", upper_text)
    if suffix_match:
        suffix = suffix_match.group(1)
        return L3_SUFFIX_TO_CONTROL_ID.get(suffix, suffix)

    numeric_match = re.search(r"(\d+\.\d+\.\d+)", raw_text)
    if numeric_match:
        return numeric_match.group(1)

    return raw_text


def extract_all_control_ids_from_text(value: str) -> set[str]:
    identifiers = set()
    raw_text = normalized_text(value)
    if not raw_text:
        return identifiers

    for match in CONTROL_DISPLAY_PATTERN.finditer(raw_text):
        identifiers.add(canonicalize_control_id(match.group(0)))
    for match in re.findall(r"[A-Z]{2}\.L3-\d+\.\d+\.\d+[A-Za-z]", raw_text, flags=re.IGNORECASE):
        identifiers.add(canonicalize_control_id(match))
    for match in re.findall(r"[A-Z]{2}\.L[12]-\d+\.\d+\.\d+", raw_text, flags=re.IGNORECASE):
        identifiers.add(canonicalize_control_id(match))
    for match in re.findall(r"\d+\.\d+\.\d+[A-Za-z]", raw_text):
        identifiers.add(canonicalize_control_id(match))
    for match in re.findall(r"\d+\.\d+\.\d+", raw_text):
        identifiers.add(canonicalize_control_id(match))
    return {identifier for identifier in identifiers if identifier}


def extract_compliance_id(record: dict) -> str:
    direct = first_value(record, ["internalIdString", "complianceId", "complianceID", "systemComplianceId", "id"])
    if direct is not None:
        return normalized_text(direct)
    nested = first_nested_value(
        record,
        [
            ["compliance", "internalIdString"],
            ["compliance", "complianceId"],
            ["compliance", "id"],
            ["data", "internalIdString"],
            ["data", "complianceId"],
            ["data", "id"],
        ],
    )
    return normalized_text(nested)


def compliance_total_records(record: dict) -> int:
    total_records_value = first_value(record, ["totalRecords", "recordCount", "total", "count"])
    if total_records_value is None:
        return 0
    try:
        return int(str(total_records_value).strip())
    except (TypeError, ValueError):
        return 0


def completion_state_from_record(record: dict) -> bool | None:
    for key in ["completed", "isCompleted", "complete", "isComplete", "closed", "isClosed", "final"]:
        if key in record:
            parsed = truthy(record.get(key))
            if parsed is not None:
                return parsed

    for key in ["completedDate", "completionDate", "closedDate", "finalizedDate"]:
        if normalized_text(record.get(key)):
            return True

    status_text = normalized_text(
        first_value(
            record,
            [
                "status",
                "statusString",
                "statusName",
                "complianceStatus",
                "complianceStatusName",
                "state",
                "recordStatus",
            ],
        )
        or first_nested_value(
            record,
            [["status", "name"], ["complianceStatus", "name"], ["workflow", "status"], ["state", "name"]],
        )
    )
    status_key = string_key(status_text)
    if status_key in {"completed", "complete", "closed", "final", "certified"}:
        return True
    if status_key in {"open", "ongoing", "active", "draft", "in progress", "pending"}:
        return False
    return None


def compliance_candidate_score(record: dict, target_level: str) -> int:
    score = 0
    compliance_id = extract_compliance_id(record)
    if compliance_id:
        score += 10

    completion_state = completion_state_from_record(record)
    if completion_state is not None:
        score += 3

    text_blob = record_text_blob(record).lower()
    if "cmmc" in text_blob:
        score += 4
    if target_level.lower() in text_blob:
        score += 2
    if "compliance" in " ".join(record.keys()).lower():
        score += 1
    return score


def select_compliance_record(payload, target_level: str) -> dict | None:
    candidates = []
    if isinstance(payload, dict):
        candidates.append(payload)
    candidates.extend(find_record_list(payload, ["records", "items", "data", "results", "compliances", "complianceList"]))
    candidates.extend(iter_dicts(payload))

    best_record = None
    best_score = -1
    seen_ids = set()
    for candidate in candidates:
        candidate_id = id(candidate)
        if candidate_id in seen_ids:
            continue
        seen_ids.add(candidate_id)

        score = compliance_candidate_score(candidate, target_level)
        if score > best_score:
            best_record = candidate
            best_score = score

    if best_record and extract_compliance_id(best_record):
        return best_record
    return None


def control_status_from_value(value) -> str:
    if isinstance(value, bool):
        return CONTROL_STATUS_MET if value else CONTROL_STATUS_OPEN

    status_key = string_key(value)
    if not status_key:
        return CONTROL_STATUS_UNKNOWN
    if status_key in {"met", "implemented", "not a finding", "pass", "passed", "complete", "completed", "closed", "compliant"}:
        return CONTROL_STATUS_MET
    if status_key in {"not applicable", "n/a", "na"}:
        return CONTROL_STATUS_NOT_APPLICABLE
    if status_key in {"not reviewed", "unreviewed", "pending review"}:
        return CONTROL_STATUS_NOT_REVIEWED
    if status_key in {"open", "not met", "ongoing", "active", "in progress", "failed", "fail", "non compliant", "incomplete"}:
        return CONTROL_STATUS_OPEN
    if "not applicable" in status_key:
        return CONTROL_STATUS_NOT_APPLICABLE
    if "not reviewed" in status_key:
        return CONTROL_STATUS_NOT_REVIEWED
    if "not a finding" in status_key:
        return CONTROL_STATUS_MET
    if "not met" in status_key:
        return CONTROL_STATUS_OPEN
    return CONTROL_STATUS_UNKNOWN


def is_unmet_control(status_normalized: str) -> bool:
    return status_normalized in {CONTROL_STATUS_OPEN, CONTROL_STATUS_NOT_REVIEWED, CONTROL_STATUS_UNKNOWN}


def normalize_poam_status(value: str) -> str:
    value_text = string_key(value)
    if value_text in {"completed", "complete", "closed"}:
        return "Completed"
    if value_text in {"accepted", "risk accepted", "risk acceptance"}:
        return "Accepted"
    if value_text in {"ongoing", "on going", "in progress", "active"}:
        return "Ongoing"
    if value_text in {"open", "new"}:
        return "Open"
    return normalized_text(value) or "Other"


def poam_status(record: dict) -> str:
    status = first_value(
        record,
        ["status", "statusString", "poamStatus", "poamStatusString", "poamStatusName", "workflowStatus", "state"],
    )
    if status is None:
        status = first_nested_value(record, [["status", "name"], ["poamStatus", "name"], ["workflow", "status"]])
    return normalize_poam_status(status)


def poam_records(payload) -> list[dict]:
    return find_record_list(payload, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


def extract_control_identifier(record: dict) -> str:
    direct_value = first_value(
        record,
        [
            "controlDisplay",
            "controlIdentifier",
            "controlId",
            "control",
            "controlNumber",
            "controlCode",
            "controlKey",
            "identifier",
            "securityCheck",
            "name",
            "title",
        ],
    )
    if direct_value is not None:
        identifier = canonicalize_control_id(direct_value)
        if identifier:
            return identifier

    nested_candidate = first_nested_value(
        record,
        [
            ["control", "controlDisplay"],
            ["control", "controlIdentifier"],
            ["control", "controlId"],
            ["control", "controlNumber"],
            ["control", "identifier"],
            ["control", "name"],
            ["securityCheck", "controlDisplay"],
            ["securityCheck", "name"],
            ["securityCheck", "identifier"],
        ],
    )
    if nested_candidate is not None:
        identifier = canonicalize_control_id(nested_candidate)
        if identifier:
            return identifier

    for identifier in extract_all_control_ids_from_text(record_text_blob(record)):
        return identifier
    return ""


def raw_control_identifier(record: dict) -> str:
    direct_value = first_value(
        record,
        [
            "controlDisplay",
            "controlIdentifier",
            "controlId",
            "control",
            "controlNumber",
            "controlCode",
            "controlKey",
            "identifier",
            "securityCheck",
            "name",
            "title",
        ],
    )
    if direct_value is not None:
        return normalized_text(direct_value)

    nested_candidate = first_nested_value(
        record,
        [
            ["control", "controlDisplay"],
            ["control", "controlIdentifier"],
            ["control", "controlId"],
            ["control", "controlNumber"],
            ["control", "identifier"],
            ["control", "name"],
            ["securityCheck", "controlDisplay"],
            ["securityCheck", "name"],
            ["securityCheck", "identifier"],
        ],
    )
    if nested_candidate is not None:
        return normalized_text(nested_candidate)
    return ""


def extract_control_title(record: dict) -> str:
    title = first_value(record, ["title", "controlTitle", "name", "description", "statement"])
    if title is None:
        title = first_nested_value(record, [["control", "title"], ["control", "name"], ["control", "description"]])
    return normalized_text(title)


def extract_control_status_raw(record: dict):
    value = first_value(
        record,
        [
            "status",
            "statusString",
            "statusName",
            "assessmentStatus",
            "assessmentStatusString",
            "assessmentStatusName",
            "result",
            "resultString",
            "complianceStatus",
            "state",
            "scoreStatus",
        ],
    )
    if value is not None:
        return value

    nested = first_nested_value(
        record,
        [
            ["status", "name"],
            ["assessmentStatus", "name"],
            ["result", "name"],
            ["complianceStatus", "name"],
            ["state", "name"],
        ],
    )
    if nested is not None:
        return nested

    for key in ["met", "implemented", "isImplemented"]:
        if key in record:
            return record[key]

    completion_value = extract_percentage_complete(record)
    if completion_value is not None:
        return "Completed" if completion_value >= 100 else "Incomplete"
    return None


def extract_percentage_complete(record: dict) -> float | None:
    percentage_complete = first_value(record, ["percentageComplete", "percentComplete", "completionPercentage"])
    if percentage_complete is None:
        percentage_complete = first_nested_value(
            record,
            [
                ["score", "percentageComplete"],
                ["score", "percentComplete"],
                ["score", "completionPercentage"],
            ],
        )
    if percentage_complete is None:
        return None
    try:
        return float(str(percentage_complete).strip())
    except (TypeError, ValueError):
        return None


def extract_source_record_id(record: dict) -> str:
    direct = first_value(record, ["id", "recordId", "controlScoreId", "scoreId", "uuid"])
    if direct is None:
        direct = first_nested_value(record, [["control", "id"], ["record", "id"]])
    return normalized_text(direct)


def infer_control_level(raw_identifier: str, canonical_identifier: str, target_level: str) -> str:
    raw_upper = raw_identifier.upper()
    if ".L3-" in raw_upper or canonical_identifier in L3_ALL_CONTROLS:
        return "Level 3"
    if re.search(r"[.\-]L[12][.\-]", raw_upper):
        if target_level == "Level 1":
            return "Level 1"
        return "Level 2"
    if re.fullmatch(r"\d+\.\d+\.\d+[A-Za-z]", canonical_identifier):
        return "Level 3"
    if re.fullmatch(r"\d+\.\d+\.\d+", canonical_identifier):
        if target_level == "Level 1":
            return "Level 1"
        return "Level 2"
    return target_level


def infer_control_family(raw_identifier: str) -> str:
    family_match = CONTROL_DISPLAY_PATTERN.search(raw_identifier)
    if family_match:
        return family_match.group(1).upper()
    return ""


def level_two_point_value(canonical_identifier: str) -> int | None:
    if not canonical_identifier:
        return None
    control_number = control_number_key(canonical_identifier)
    if canonical_identifier in L2_FIVE_POINT_CONTROLS or control_number in L2_FIVE_POINT_CONTROL_NUMBERS:
        return 5
    if canonical_identifier in L2_THREE_POINT_CONTROLS or control_number in L2_THREE_POINT_CONTROL_NUMBERS:
        return 3
    if re.fullmatch(r"\d+\.\d+\.\d+", control_number):
        return 1
    return None


def level_three_point_value(canonical_identifier: str) -> int | None:
    if canonical_identifier in L3_FIVE_POINT_CONTROLS:
        return 5
    if canonical_identifier in L3_ONE_POINT_CONTROLS:
        return 1
    return None


def poam_eligible(level: str, canonical_identifier: str, point_value: int | None) -> bool:
    control_number = control_number_key(canonical_identifier)
    if level == "Level 1":
        return False
    if level == "Level 2":
        if (
            canonical_identifier in L2_NON_POAM_ELIGIBLE_CONTROLS
            or control_number in L2_NON_POAM_ELIGIBLE_CONTROL_NUMBERS
        ):
            return False
        return point_value in {1, 3}
    if level == "Level 3":
        return point_value == 1
    return False


def special_deduction_for_level_two(control_model: dict, point_value: int) -> tuple[int, str | None]:
    canonical_identifier = control_model["canonicalControlId"]
    control_number = control_number_key(canonical_identifier)
    text_blob = control_model["textBlob"].lower()
    status_raw = control_model["statusRaw"].lower()
    combined = f"{status_raw} | {text_blob}"

    if control_number == "3.5.3":
        if "partial" in combined or ("remote" in combined and "privileged" in combined and "local" in combined):
            return 3, "Applied partial MFA deduction based on source data wording."
    if control_number == "3.13.11":
        if "not fips" in combined or "non fips" in combined or "fips validated" in combined:
            return 3, "Applied FIPS validation deduction based on source data wording."
    return point_value, None


def control_models_from_records(records: list[dict], target_level: str, poam_index: dict[str, list[dict]]) -> list[dict]:
    control_models = []
    for record in records:
        raw_identifier = raw_control_identifier(record)
        canonical_identifier = extract_control_identifier(record)
        if not canonical_identifier:
            continue

        status_raw_value = extract_control_status_raw(record)
        status_raw = normalized_text(status_raw_value)
        status_normalized = control_status_from_value(status_raw_value)
        inferred_level = infer_control_level(raw_identifier, canonical_identifier, target_level)
        level_point_value = None
        if inferred_level == "Level 2":
            level_point_value = level_two_point_value(canonical_identifier)
        elif inferred_level == "Level 3":
            level_point_value = level_three_point_value(canonical_identifier)

        control_models.append(
            {
                "canonicalControlId": canonical_identifier,
                "rawControlId": raw_identifier or canonical_identifier,
                "title": extract_control_title(record),
                "family": infer_control_family(raw_identifier),
                "statusRaw": status_raw,
                "statusNormalized": status_normalized,
                "percentageComplete": extract_percentage_complete(record),
                "sourceRecordId": extract_source_record_id(record),
                "level": inferred_level,
                "basePointValue": level_point_value,
                "poamLinked": canonical_identifier in poam_index,
                "poamCount": len(poam_index.get(canonical_identifier, [])),
                "poamRecords": poam_index.get(canonical_identifier, []),
                "textBlob": record_text_blob(record),
            }
        )
    return control_models


def build_poam_index(records: list[dict]) -> dict[str, list[dict]]:
    index = {}
    for record in records:
        status = poam_status(record)
        if status not in {"Ongoing", "Open"}:
            continue
        identifiers = extract_all_control_ids_from_text(record_text_blob(record))
        for identifier in identifiers:
            index.setdefault(identifier, []).append(record)
    return index


def counts_by_status(results: list[dict]) -> dict[str, int]:
    counts = {
        "met": 0,
        "open": 0,
        "notApplicable": 0,
        "notReviewed": 0,
        "unknown": 0,
    }
    for result in results:
        status = result["statusNormalized"]
        if status == CONTROL_STATUS_MET:
            counts["met"] += 1
        elif status == CONTROL_STATUS_OPEN:
            counts["open"] += 1
        elif status == CONTROL_STATUS_NOT_APPLICABLE:
            counts["notApplicable"] += 1
        elif status == CONTROL_STATUS_NOT_REVIEWED:
            counts["notReviewed"] += 1
        else:
            counts["unknown"] += 1
    counts["total"] = len(results)
    return counts


def attach_result_fields(control_model: dict, scope: str, point_value: int | None, deduction_applied: int, exception_reason: str | None, level: str) -> dict:
    control_number = control_number_key(control_model["canonicalControlId"])
    return {
        "controlId": control_model["canonicalControlId"],
        "rawControlId": control_model["rawControlId"],
        "scope": scope,
        "level": level,
        "family": control_model["family"],
        "title": control_model["title"],
        "statusRaw": control_model["statusRaw"],
        "statusNormalized": control_model["statusNormalized"],
        "percentageComplete": control_model.get("percentageComplete"),
        "pointValue": point_value,
        "deductionApplied": deduction_applied,
        "poamEligible": poam_eligible(level, control_model["canonicalControlId"], point_value),
        "poamLinked": control_model["poamLinked"],
        "poamCount": control_model["poamCount"],
        "exceptionReason": exception_reason or "",
        "isNoScoreControl": control_model["canonicalControlId"] in L2_NO_SCORE_CONTROLS
        or control_number in L2_NO_SCORE_CONTROL_NUMBERS,
        "sourceRecordId": control_model["sourceRecordId"],
    }


def sort_results(results: list[dict]) -> list[dict]:
    scope_order = {
        "Level 1 assessment": 1,
        "Level 2 assessment": 2,
        "Level 2 prerequisite": 3,
        "Level 3 assessment": 4,
    }
    return sorted(results, key=lambda item: (scope_order.get(item["scope"], 99), item["controlId"], item["rawControlId"]))


def score_level_one(control_models: list[dict]) -> tuple[dict, list[dict]]:
    scoped_controls = [control for control in control_models if control["level"] == "Level 1"]
    if not scoped_controls:
        scoped_controls = control_models
    if not scoped_controls:
        fatal_error("Could not find any Level 1 controls to score.")

    results = [attach_result_fields(control, "Level 1 assessment", None, 0, None, "Level 1") for control in scoped_controls]
    counts = counts_by_status(results)
    unmet_controls = [result for result in results if is_unmet_control(result["statusNormalized"])]
    reasons = []
    if unmet_controls:
        reasons.append("Level 1 requires every in-scope control to be MET.")

    summary = {
        "baseline": None,
        "deductionTotal": None,
        "computedScore": None,
        "finalStatus": "Passed" if not unmet_controls else "Failed",
        "counts": counts,
        "gating": {
            "hasNoScoreTrigger": False,
            "hasOpenFivePointControl": False,
            "hasOpenNonPoamEligibleControl": bool(unmet_controls),
        },
        "reasons": reasons,
    }
    return summary, sort_results(results)


def score_level_two(control_models: list[dict], scope_label: str = "Level 2 assessment") -> tuple[dict, list[dict]]:
    scoped_controls = [control for control in control_models if control["level"] == "Level 2"]
    if not scoped_controls:
        scoped_controls = [control for control in control_models if control["level"] != "Level 3"]
    if not scoped_controls:
        fatal_error("Could not find any Level 2 controls to score.")

    results = []
    deduction_total = 0
    has_no_score_trigger = False
    has_open_five_point_control = False
    has_open_non_poam_eligible_control = False
    unmet_controls = []

    for control in scoped_controls:
        point_value = control["basePointValue"] if control["basePointValue"] is not None else level_two_point_value(control["canonicalControlId"])
        control_number = control_number_key(control["canonicalControlId"])
        deduction_applied = 0
        exception_reason = None
        if is_unmet_control(control["statusNormalized"]):
            unmet_controls.append(control)
            if point_value is not None:
                deduction_applied, exception_reason = special_deduction_for_level_two(control, point_value)
            if (
                control["canonicalControlId"] in L2_NO_SCORE_CONTROLS
                or control_number in L2_NO_SCORE_CONTROL_NUMBERS
            ):
                has_no_score_trigger = True
            if point_value == 5:
                has_open_five_point_control = True
            if not poam_eligible("Level 2", control["canonicalControlId"], point_value):
                has_open_non_poam_eligible_control = True
        deduction_total += deduction_applied
        results.append(attach_result_fields(control, scope_label, point_value, deduction_applied, exception_reason, "Level 2"))

    counts = counts_by_status(results)
    computed_score = 110 - deduction_total
    reasons = []
    open_results = [result for result in results if is_unmet_control(result["statusNormalized"])]
    poam_missing = [result["controlId"] for result in open_results if result["poamEligible"] and not result["poamLinked"]]

    if has_no_score_trigger:
        reasons.append("Control 3.12.4 is open or not met, which results in No Score.")
    if has_open_five_point_control:
        reasons.append("At least one open 5-point Level 2 control blocks conditional status.")
    if has_open_non_poam_eligible_control:
        reasons.append("At least one open Level 2 control is not eligible for a POA&M.")
    if poam_missing:
        reasons.append("Open POA&M-eligible controls must have an ongoing POA&M linkage for conditional status.")

    if has_no_score_trigger:
        final_status = "No Score"
    elif not open_results:
        final_status = "Final"
    elif computed_score >= 88 and not has_open_five_point_control and not has_open_non_poam_eligible_control and not poam_missing:
        final_status = "Conditional"
    else:
        final_status = "Fail"

    summary = {
        "baseline": 110,
        "deductionTotal": deduction_total,
        "computedScore": computed_score,
        "finalStatus": final_status,
        "counts": counts,
        "gating": {
            "hasNoScoreTrigger": has_no_score_trigger,
            "hasOpenFivePointControl": has_open_five_point_control,
            "hasOpenNonPoamEligibleControl": has_open_non_poam_eligible_control,
        },
        "reasons": reasons,
    }
    return summary, sort_results(results)


def score_level_three(control_models: list[dict]) -> tuple[dict, list[dict]]:
    level_two_controls = [control for control in control_models if control["level"] == "Level 2"]
    if not level_two_controls:
        level_two_controls = [control for control in control_models if re.fullmatch(r"\d+\.\d+\.\d+", control["canonicalControlId"])]
    level_three_controls = [control for control in control_models if control["level"] == "Level 3" or control["canonicalControlId"] in L3_ALL_CONTROLS]

    prerequisite_summary = None
    prerequisite_results = []
    prerequisite_met = False
    reasons = [LEVEL_THREE_PASS_FAIL_NOTE]

    if level_two_controls:
        prerequisite_summary, prerequisite_results = score_level_two(level_two_controls, scope_label="Level 2 prerequisite")
        prerequisite_met = prerequisite_summary["finalStatus"] == "Final"
    else:
        reasons.append("Could not verify the Level 2 prerequisite from the returned controls.")

    if not level_three_controls:
        reasons.append("Could not find any Level 3 advanced controls to score.")

    level_three_results = []
    deduction_total = 0
    has_open_five_point_control = False
    for control in level_three_controls:
        point_value = control["basePointValue"] if control["basePointValue"] is not None else level_three_point_value(control["canonicalControlId"])
        deduction_applied = point_value if is_unmet_control(control["statusNormalized"]) and point_value is not None else 0
        if is_unmet_control(control["statusNormalized"]) and point_value == 5:
            has_open_five_point_control = True
        deduction_total += deduction_applied
        level_three_results.append(attach_result_fields(control, "Level 3 assessment", point_value, deduction_applied, None, "Level 3"))

    counts = counts_by_status(level_three_results)
    unmet_level_three = [result for result in level_three_results if is_unmet_control(result["statusNormalized"])]
    if not prerequisite_met:
        reasons.append("Level 3 scoring requires a Final Level 2 result with no open prerequisite controls.")
    if has_open_five_point_control:
        reasons.append("At least one open 5-point Level 3 control blocks passing status.")
    if unmet_level_three and not has_open_five_point_control:
        reasons.append("Level 3 is implemented as pass/fail only in this approved script.")

    if not prerequisite_met or not level_three_controls:
        final_status = "Ineligible"
    elif unmet_level_three:
        final_status = "Failed"
    else:
        final_status = "Passed"

    summary = {
        "baseline": 24,
        "deductionTotal": deduction_total,
        "computedScore": 24 - deduction_total,
        "finalStatus": final_status,
        "counts": counts,
        "gating": {
            "hasNoScoreTrigger": False,
            "hasOpenFivePointControl": has_open_five_point_control,
            "hasOpenNonPoamEligibleControl": has_open_five_point_control,
        },
        "prerequisite": {
            "l2FinalRequired": True,
            "l2PrereqMet": prerequisite_met,
            "l2PrereqStatus": prerequisite_summary["finalStatus"] if prerequisite_summary else "Unavailable",
        },
        "reasons": reasons,
    }
    combined_results = prerequisite_results + level_three_results
    return summary, sort_results(combined_results)


def load_system_package(arguments: list[str]) -> tuple[dict, str]:
    systempackage_script = Path(__file__).resolve().parents[1] / "system-package" / SYSTEMPACKAGE_SCRIPT_NAME
    system_package_output = call_child_script(systempackage_script, arguments, "The system package JSON script failed")
    system_package = parse_json_from_output(system_package_output)
    if not isinstance(system_package, dict):
        fatal_error("The system package JSON script did not return a JSON object.")
    return system_package, resolve_cmmc_level(system_package)


def load_compliance(arguments: list[str], target_level: str) -> dict:
    compliance_script = Path(__file__).resolve().parents[1] / "compliance" / COMPLIANCE_SCRIPT_NAME

    compliance_payload = parse_json_from_output(
        call_child_script(compliance_script, arguments, "The compliance JSON script failed")
    )
    if not isinstance(compliance_payload, dict):
        fatal_error("The compliance JSON script did not return a JSON object.")

    framework_level = resolve_cmmc_level(compliance_payload)
    if framework_level != target_level:
        fatal_error(
            "The compliance record did not match the selected CMMC package level.",
            details=json.dumps(
                {
                    "packageLevel": target_level,
                    "complianceLevel": framework_level,
                },
                indent=2,
                sort_keys=False,
            ),
        )

    if completion_state_from_record(compliance_payload) is not True:
        fatal_error("A completed compliance record is required before calculating a CMMC score.")

    total_records = compliance_total_records(compliance_payload)
    if total_records <= 0:
        fatal_error("The compliance record must report totalRecords greater than zero before scoring.")

    if not extract_compliance_id(compliance_payload):
        fatal_error("The compliance record did not contain an internalIdString complianceId.")

    return compliance_payload


def load_control_records(arguments: list[str], compliance_id: str) -> list[dict]:
    allcontrols_script = Path(__file__).resolve().parents[1] / "compliance" / ALLCONTROLS_SCRIPT_NAME
    payload = parse_json_from_output(
        call_child_script(
            allcontrols_script,
            [*arguments, compliance_id],
            "The all-controls JSON script failed",
        )
    )
    records = find_record_list(payload, ["records", "items", "data", "results", "controls", "allControls", "controlScores"])
    if not records and isinstance(payload, dict):
        records = [payload]
    if not records:
        fatal_error("Could not find any control records in the all-controls response.")
    return records


def load_poam_records(arguments: list[str]) -> list[dict]:
    poam_script = Path(__file__).resolve().parents[1] / "poam" / POAM_SCRIPT_NAME
    grouped_payload = parse_json_from_output(
        call_child_script(
            poam_script,
            [*arguments, "status=Ongoing", "grouped=true", "showCompliance=true"],
            "The POA&M JSON script failed",
        )
    )
    records = poam_records(grouped_payload)
    if records:
        return records

    detailed_payload = parse_json_from_output(
        call_child_script(
            poam_script,
            [*arguments, "status=Ongoing", "grouped=false", "showCompliance=true"],
            "The POA&M JSON script failed",
        )
    )
    return poam_records(detailed_payload)


def build_output(system_package: dict, target_level: str, compliance_record: dict, summary: dict, results: list[dict]) -> dict:
    return {
        "summary": {
            "systemKey": normalized_text(system_package.get("systemKey")) or normalized_text(system_package.get("key")),
            "systemPackageTitle": normalized_text(system_package.get("title")),
            "targetLevel": target_level,
            "complianceId": extract_compliance_id(compliance_record),
            "baseline": summary["baseline"],
            "deductionTotal": summary["deductionTotal"],
            "computedScore": summary["computedScore"],
            "finalStatus": summary["finalStatus"],
            "counts": summary["counts"],
            "gating": summary["gating"],
            "prerequisite": summary.get("prerequisite", {}),
            "reasons": summary["reasons"],
        },
        "results": results,
    }


def main() -> None:
    if len(sys.argv) < REQUIRED_ARGUMENT_COUNT:
        print_usage()
        sys.exit(1)

    root_url = sys.argv[1]
    application_key = sys.argv[2]
    authorization_token = sys.argv[3]
    system_key = sys.argv[4]
    child_arguments = [root_url, application_key, authorization_token, system_key]

    system_package, target_level = load_system_package(child_arguments)
    compliance_record = load_compliance(child_arguments, target_level)
    compliance_id = extract_compliance_id(compliance_record)
    if not compliance_id:
        fatal_error("The selected compliance record did not contain a complianceId.")

    control_records = load_control_records(child_arguments, compliance_id)
    poam_records_payload = load_poam_records(child_arguments)
    poam_index = build_poam_index(poam_records_payload)
    control_models = control_models_from_records(control_records, target_level, poam_index)
    if not control_models:
        fatal_error("Could not build any control scoring records from the all-controls response.")

    if target_level == "Level 1":
        summary, results = score_level_one(control_models)
    elif target_level == "Level 2":
        summary, results = score_level_two(control_models)
    else:
        summary, results = score_level_three(control_models)

    print(json.dumps(build_output(system_package, target_level, compliance_record, summary, results), indent=2, sort_keys=False))


if __name__ == "__main__":
    main()