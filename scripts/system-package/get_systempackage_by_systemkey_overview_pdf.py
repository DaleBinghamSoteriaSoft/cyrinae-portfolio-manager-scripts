#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional External API - Systempackage Overview PDF
# API Path   : GET /systempackage/{systemKey}
# Description: Calls get_systempackage_by_systemkey_json.py and creates a PDF overview report with the system package title, description, and checklist count.
#
# Required Parameters:
#   1) rootURL            - The base server URL passed to get_systempackage_by_systemkey_json.py.
#   2) applicationKey     - The application key passed to get_systempackage_by_systemkey_json.py.
#   3) authorizationToken - The bearer token passed to get_systempackage_by_systemkey_json.py.
#   4) systemKey          - Required path parameter passed to get_systempackage_by_systemkey_json.py.
#
# Optional Parameters:
#   None
#
# Command Line Example:
#   python3 get_systempackage_by_systemkey_overview_pdf.py \
#       https://example.openrmfpro.local \
#       my-application-key \
#       my-authorization-token \
#       <systemKey>
# ============================================================

import html
import json
import re
import subprocess
import sys
import textwrap
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SOURCE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
PATCH_DATA_SCRIPT_NAME = "get_systempackage_by_systemkey_patchdata_json.py"
HARDWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_hardware_json.py"
SOFTWARE_SCRIPT_NAME = "get_systempackage_by_systemkey_software_json.py"
PPSM_SCRIPT_NAME = "get_systempackage_by_systemkey_ppsm_json.py"
POAM_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
REPORT_SECTIONS = [
    {"title": "Checklist Information", "anchor": "checklist-information", "page_number": "2"},
    {"title": "Patch Vulnerability Information", "anchor": "patch", "page_number": "3"},
    {"title": "Hardware Inventory", "anchor": "hardware", "page_number": "5"},
    {"title": "Software Inventory by Device", "anchor": "software", "page_number": "6"},
    {"title": "Ports, Protocols, and Services by Boundary", "anchor": "ports-protocols-services", "page_number": "13"},
    {"title": "POAM Information", "anchor": "poam", "page_number": "22"},
]


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


def call_systempackage_json_script(arguments: list[str]) -> str:
    source_script = Path(__file__).resolve().parent / SOURCE_SCRIPT_NAME
    command = [get_project_python_executable(), str(source_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("ERROR: The system package JSON script failed.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        sys.exit(result.returncode)

    return result.stdout


def call_patchdata_json_script(arguments: list[str]) -> str:
    patchdata_script = Path(__file__).resolve().parents[1] / "patch-vulnerability" / PATCH_DATA_SCRIPT_NAME
    command = [get_project_python_executable(), str(patchdata_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("WARNING: The patch data JSON script failed. Continuing without patch vulnerability details.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        return ""

    return result.stdout


def call_hardware_json_script(arguments: list[str]) -> str:
    hardware_script = Path(__file__).resolve().parents[1] / "hardware" / HARDWARE_SCRIPT_NAME
    command = [get_project_python_executable(), str(hardware_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("WARNING: The hardware JSON script failed. Continuing without hardware details.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        return ""

    return result.stdout


def call_software_json_script(arguments: list[str]) -> str:
    software_script = Path(__file__).resolve().parents[1] / "software" / SOFTWARE_SCRIPT_NAME
    command = [get_project_python_executable(), str(software_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("WARNING: The software JSON script failed. Continuing without software details.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        return ""

    return result.stdout


def call_ppsm_json_script(arguments: list[str]) -> str:
    ppsm_script = Path(__file__).resolve().parents[1] / "ports-protocols-services" / PPSM_SCRIPT_NAME
    command = [get_project_python_executable(), str(ppsm_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("WARNING: The ports/protocols/services JSON script failed. Continuing without PPSM details.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        return ""

    return result.stdout


def call_poam_json_script(arguments: list[str]) -> str:
    poam_script = Path(__file__).resolve().parents[1] / "poam" / POAM_SCRIPT_NAME
    command = [get_project_python_executable(), str(poam_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("WARNING: The POAM JSON script failed. Continuing without POAM details.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        return ""

    return result.stdout


def parse_json_from_output(output: str) -> dict:
    decoder = json.JSONDecoder()
    for index, character in enumerate(output):
        if character not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(output[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    print("ERROR: Could not find a JSON object in the system package JSON script output.")
    print(output)
    sys.exit(1)


def parse_json_value_from_output(output: str):
    decoder = json.JSONDecoder()
    for index, character in enumerate(output):
        if character not in "[{":
            continue
        try:
            parsed, _ = decoder.raw_decode(output[index:])
        except json.JSONDecodeError:
            continue
        return parsed
    return None


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def safe_filename_value(value: str) -> str:
    safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe_value.strip(".-") or "unknown-system"


def report_title_for_system(title: str) -> str:
    return f"{safe_text(title).strip() or 'Unknown'} System Package Overview"


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


def build_score_rows(system_package: dict) -> list[dict[str, str]]:
    score = system_package.get("score", {})
    if not isinstance(score, dict):
        score = {}

    return [
        {
            "category": "CAT I",
            "open": safe_text(score.get("totalCat1Open", 0)),
            "not_a_finding": safe_text(score.get("totalCat1NotAFinding", 0)),
            "not_applicable": safe_text(score.get("totalCat1NotApplicable", 0)),
            "not_reviewed": safe_text(score.get("totalCat1NotReviewed", 0)),
        },
        {
            "category": "CAT II",
            "open": safe_text(score.get("totalCat2Open", 0)),
            "not_a_finding": safe_text(score.get("totalCat2NotAFinding", 0)),
            "not_applicable": safe_text(score.get("totalCat2NotApplicable", 0)),
            "not_reviewed": safe_text(score.get("totalCat2NotReviewed", 0)),
        },
        {
            "category": "CAT III",
            "open": safe_text(score.get("totalCat3Open", 0)),
            "not_a_finding": safe_text(score.get("totalCat3NotAFinding", 0)),
            "not_applicable": safe_text(score.get("totalCat3NotApplicable", 0)),
            "not_reviewed": safe_text(score.get("totalCat3NotReviewed", 0)),
        },
        {
            "category": "Total",
            "open": safe_text(score.get("totalOpen", 0)),
            "not_a_finding": safe_text(score.get("totalNotAFinding", 0)),
            "not_applicable": safe_text(score.get("totalNotApplicable", 0)),
            "not_reviewed": safe_text(score.get("totalNotReviewed", 0)),
        },
    ]


def build_category_total_score_rows(system_package: dict) -> list[dict[str, str]]:
    score = system_package.get("score", {})
    if not isinstance(score, dict):
        score = {}

    return [
        {"category": "CAT I", "total_score": safe_text(score.get("totalCat1", 0))},
        {"category": "CAT II", "total_score": safe_text(score.get("totalCat2", 0))},
        {"category": "CAT III", "total_score": safe_text(score.get("totalCat3", 0))},
    ]


def build_total_status_rows(system_package: dict) -> list[dict[str, str]]:
    score = system_package.get("score", {})
    if not isinstance(score, dict):
        score = {}

    return [
        {"status": "Open", "total": safe_text(score.get("totalOpen", 0))},
        {"status": "Not a Finding", "total": safe_text(score.get("totalNotAFinding", 0))},
        {"status": "Not Applicable", "total": safe_text(score.get("totalNotApplicable", 0))},
        {"status": "Not Reviewed", "total": safe_text(score.get("totalNotReviewed", 0))},
    ]


def build_patch_rows(system_package: dict) -> list[dict[str, str]]:
    patch_score = system_package.get("patchScore", {})
    if not isinstance(patch_score, dict):
        patch_score = {}

    return [
        {"metric": "Critical Open", "value": safe_text(patch_score.get("totalCriticalOpen", 0))},
        {"metric": "High Open", "value": safe_text(patch_score.get("totalHighOpen", 0))},
        {"metric": "Medium Open", "value": safe_text(patch_score.get("totalMediumOpen", 0))},
        {"metric": "Low Open", "value": safe_text(patch_score.get("totalLowOpen", 0))},
        {"metric": "Version", "value": safe_text(patch_score.get("version", 0))},
    ]


def build_table_of_contents_rows() -> list[dict[str, str]]:
    return [
        {"title": section["title"], "anchor": section["anchor"], "page_number": section["page_number"]}
        for section in REPORT_SECTIONS
    ]


def first_value(record: dict, keys: list[str]) -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return safe_text(value)
    return ""


def first_raw_value(record: dict, keys: list[str]):
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


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


def numeric_sort_value(value: str) -> float:
    try:
        return float(str(value).strip())
    except ValueError:
        return 0.0


def severity_number_from_value(value: str) -> int:
    value_text = safe_text(value).strip().lower()
    if value_text in {"4", "critical"}:
        return 4
    if value_text in {"3", "high"}:
        return 3
    try:
        return int(float(value_text))
    except ValueError:
        return 0


def severity_name_from_number(severity_number: int) -> str:
    if severity_number == 4:
        return "Critical"
    if severity_number == 3:
        return "High"
    return "Unknown"


def normalize_raw_severity(value: str) -> str:
    value_text = safe_text(value).strip().lower()
    if value_text in {"4", "critical", "cat i", "cat 1", "i"}:
        return "Critical"
    if value_text in {"3", "high", "cat ii", "cat 2", "ii"}:
        return "High"
    if value_text in {"2", "medium", "moderate", "cat iii", "cat 3", "iii"}:
        return "Medium"
    if value_text in {"1", "low"}:
        return "Low"
    return ""


def normalize_resulting_risk(value: str) -> str:
    value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
    if not value_text:
        return "N / A"
    if value_text in {"very high", "veryhigh"}:
        return "Very High"
    if value_text == "high":
        return "High"
    if value_text in {"moderate", "medium"}:
        return "Moderate"
    if value_text == "low":
        return "Low"
    if value_text in {"very low", "verylow"}:
        return "Very low"
    return safe_text(value).strip()


def parse_date_value(value):
    value_text = safe_text(value).strip()
    if not value_text:
        return None

    normalized_value = value_text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized_value).astimezone()
    except ValueError:
        pass

    for date_format in ("%m/%d/%Y %I:%M %p", "%m/%d/%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value_text, date_format).astimezone()
        except ValueError:
            continue
    return None


def is_within_next_30_days(value) -> bool:
    parsed_date = parse_date_value(value)
    if parsed_date is None:
        return False
    now = datetime.now().astimezone()
    return now <= parsed_date <= now + timedelta(days=30)


def find_patch_record_list(patchdata) -> list[dict]:
    if isinstance(patchdata, list):
        return [record for record in patchdata if isinstance(record, dict)]
    if not isinstance(patchdata, dict):
        return []

    candidate_keys = ["records", "items", "data", "results", "patchData", "patchdata", "vulnerabilities", "findings"]
    for key in candidate_keys:
        value = patchdata.get(key)
        if isinstance(value, list):
            return [record for record in value if isinstance(record, dict)]

    for value in patchdata.values():
        if isinstance(value, list) and all(isinstance(record, dict) for record in value):
            return value
    return []


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


def format_ip_address_list(value) -> str:
    if isinstance(value, list):
        formatted_values = []
        for item in value:
            if isinstance(item, dict):
                ip_value = first_value(item, ["ipAddress", "ip", "address", "value"])
                if ip_value:
                    formatted_values.append(ip_value)
            elif item not in (None, ""):
                formatted_values.append(safe_text(item))
        return ", ".join(formatted_values)
    if isinstance(value, dict):
        return first_value(value, ["ipAddress", "ip", "address", "value"])
    return safe_text(value)


def bool_value(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, (list, dict)):
        return len(value) > 0
    value_text = safe_text(value).strip().lower()
    return value_text in {"true", "yes", "y", "1", "enabled", "complete", "completed"}


def build_hardware_rows(hardwaredata) -> list[dict[str, str]]:
    rows = []
    records = find_record_list(hardwaredata, ["records", "items", "data", "results", "hardware", "devices", "assets"])
    for record in records:
        hostname = first_value(record, ["hostname", "hostName", "deviceName", "name", "assetName", "computerName", "machineName"])
        operating_system = first_value(record, ["operatingSystem", "operatingSystemName", "os", "osName", "platform"])
        ip_addresses = first_raw_value(record, ["ipAddressList", "ipAddresses", "ipAddress", "ip", "ips", "networkAddresses"])
        patch_scan = first_raw_value(record, ["patchscan", "patchScanEnabled", "hasPatchScan", "patchScanning", "patchScanAvailable"])
        checklists = first_raw_value(record, ["checklists", "hasChecklists", "checklist", "hasChecklist", "checklistAvailable"])

        if not hostname:
            hostname = first_nested_value(record, [["asset", "hostname"], ["asset", "hostName"], ["device", "hostname"]])
        if not operating_system:
            operating_system = first_nested_value(record, [["operatingSystem", "name"], ["os", "name"], ["asset", "operatingSystem"]])
        if ip_addresses in (None, ""):
            ip_addresses = first_nested_value(record, [["network", "ipAddress"], ["asset", "ipAddress"]])

        if any([hostname, operating_system, ip_addresses, patch_scan, checklists]):
            rows.append(
                {
                    "hostname": hostname or "Unknown",
                    "operating_system": operating_system or "Unknown",
                    "ip_address_list": format_ip_address_list(ip_addresses) or "Unknown",
                    "patch_scan": bool_value(patch_scan),
                    "checklists": bool_value(checklists),
                }
            )
    return sorted(rows, key=lambda row: row["hostname"].lower(), reverse=True)


def build_software_rows(softwaredata) -> list[dict[str, str]]:
    grouped_software: dict[tuple[str, str, str], set[str]] = {}
    records = find_record_list(softwaredata, ["records", "items", "data", "results", "software", "applications"])
    for record in records:
        software_name = first_value(record, ["softwareName", "name", "applicationName", "productName", "title"])
        version = first_value(record, ["version", "softwareVersion", "productVersion", "release"])
        asset_type_string = first_value(record, ["assetTypeString", "assetType", "asset_type_string", "typeString", "deviceTypeString"])
        hostname = first_value(record, ["hostname", "hostName", "deviceName", "assetName", "computerName", "machineName"])

        if not software_name:
            software_name = first_nested_value(record, [["software", "name"], ["application", "name"], ["product", "name"]])
        if not version:
            version = first_nested_value(record, [["software", "version"], ["application", "version"], ["product", "version"]])
        if not asset_type_string:
            asset_type_string = first_nested_value(record, [["asset", "assetTypeString"], ["device", "assetTypeString"]])
        if not hostname:
            hostname = first_nested_value(record, [["asset", "hostname"], ["asset", "hostName"], ["device", "hostname"]])

        if not any([software_name, version, asset_type_string, hostname]):
            continue

        group_key = (
            software_name or "Unknown",
            version or "Unknown",
            asset_type_string or "Unknown",
        )
        grouped_software.setdefault(group_key, set())
        if hostname:
            grouped_software[group_key].add(hostname)

    rows = []
    for (software_name, version, asset_type_string), hostnames in grouped_software.items():
        sorted_hostnames = sorted(hostnames, key=str.lower)
        rows.append(
            {
                "software_name": software_name,
                "version": version,
                "asset_type_string": asset_type_string,
                "device_count": safe_text(len(sorted_hostnames)),
                "hostnames": ", ".join(sorted_hostnames) or "Unknown",
            }
        )

    return sorted(rows, key=lambda row: (row["software_name"].lower(), row["version"].lower()))


def ppsm_boundary_value(record: dict, boundary_number: int, direction: str) -> bool:
    direction_lower = direction.lower()
    direction_title = direction.title()
    keys = [
        f"boundary{boundary_number}{direction_title}",
        f"boundary{boundary_number}{direction_lower}",
        f"boundary{boundary_number}_{direction_lower}",
        f"boundary_{boundary_number}_{direction_lower}",
        f"boundary{boundary_number}{direction_title}Field",
        f"boundary{boundary_number}_{direction_lower}_field",
        f"boundary{boundary_number}{direction_title}Value",
        f"boundary{boundary_number}_{direction_lower}_value",
    ]
    return bool_value(first_raw_value(record, keys))


def ppsm_boundaries_crossed(boundary_signature: tuple[bool, ...]) -> str:
    labels = []
    for boundary_index in range(8):
        if boundary_signature[boundary_index * 2]:
            labels.append(f"{boundary_index + 1} In")
        if boundary_signature[(boundary_index * 2) + 1]:
            labels.append(f"{boundary_index + 1} Out")
    return ", ".join(labels) or "None"


def build_ppsm_rows(ppsmdata) -> list[dict[str, str]]:
    grouped_ppsm: dict[tuple[str, str, str, tuple[bool, ...]], set[str]] = {}
    records = find_record_list(ppsmdata, ["records", "items", "data", "results", "ppsm", "portsProtocolsServices"])
    for record in records:
        port = first_value(record, ["lowPortNumber", "port", "portNumber", "lowPort", "fromPort"])
        protocol = first_value(record, ["protocol", "protocolName", "proto"])
        service = first_value(record, ["svc_name", "service", "serviceName", "svcName", "name"])
        hostname = first_value(record, ["hostname", "hostName", "deviceName", "assetName", "computerName", "machineName"])

        if not hostname:
            hostname = first_nested_value(record, [["asset", "hostname"], ["asset", "hostName"], ["device", "hostname"]])
        if not service:
            service = first_nested_value(record, [["service", "name"], ["svc", "name"]])

        boundary_signature = tuple(
            ppsm_boundary_value(record, boundary_number, direction)
            for boundary_number in range(1, 9)
            for direction in ("In", "Out")
        )

        if not any([port, protocol, service, hostname]) and not any(boundary_signature):
            continue

        group_key = (port or "Unknown", protocol or "Unknown", service or "Unknown", boundary_signature)
        grouped_ppsm.setdefault(group_key, set())
        if hostname:
            grouped_ppsm[group_key].add(hostname)

    rows = []
    for (port, protocol, service, boundary_signature), hostnames in grouped_ppsm.items():
        sorted_hostnames = sorted(hostnames, key=str.lower)
        rows.append(
            {
                "port": port,
                "protocol": protocol,
                "service": service,
                "device_count": safe_text(len(sorted_hostnames)),
                "hostnames": ", ".join(sorted_hostnames) or "Unknown",
                "boundaries_crossed": ppsm_boundaries_crossed(boundary_signature),
                "port_sort": safe_text(numeric_sort_value(port)),
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            numeric_sort_value(row["port_sort"]),
            row["protocol"].lower(),
            row["service"].lower(),
        ),
    )


def normalize_poam_status(value: str) -> str:
    value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
    if value_text in {"completed", "complete", "closed"}:
        return "Completed"
    if value_text in {"accepted", "risk accepted", "risk acceptance"}:
        return "Accepted"
    if value_text in {"ongoing", "on going", "in progress", "active"}:
        return "Ongoing"
    if value_text in {"open", "new"}:
        return "Open"
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
    return normalize_poam_status(status)


def poam_raw_severity(record: dict) -> str:
    raw_severity = first_value(
        record,
        [
            "rawSeverity",
            "rawSeverityString",
            "rawSeverityLevel",
            "rawSeverityName",
            "rawSeverityValue",
            "severity",
            "severityName",
            "severityString",
            "cat",
            "category",
            "categoryCode",
        ],
    )
    if not raw_severity:
        raw_severity = first_nested_value(
            record,
            [["rawSeverity", "name"], ["severity", "name"], ["risk", "rawSeverity"], ["finding", "severity"]],
        )
    return normalize_raw_severity(raw_severity) or "Unknown"


def poam_scheduled_completion(record: dict) -> str:
    scheduled_completion = first_value(
        record,
        [
            "scheduledCompletionDate",
            "scheduledCompletionDateString",
            "scheduledCompletion",
            "scheduledCompletionString",
            "scheduledCompletionDt",
            "milestoneScheduledCompletionDate",
            "milestoneCompletionDate",
            "completionDate",
        ],
    )
    if not scheduled_completion:
        scheduled_completion = first_nested_value(
            record,
            [["scheduledCompletion", "date"], ["milestone", "scheduledCompletionDate"], ["milestone", "completionDate"]],
        )
    return scheduled_completion


def poam_resulting_risk(record: dict) -> str:
    resulting_risk = first_value(
        record,
        [
            "residualRiskLevelMitigations",
            "residualRiskLevelMitigation",
            "resultingRisk",
            "resultingRiskLevel",
            "residualRisk",
            "residualRiskLevel",
        ],
    )
    if not resulting_risk:
        resulting_risk = first_nested_value(record, [["risk", "residualRiskLevelMitigations"], ["risk", "resultingRisk"]])
    return normalize_resulting_risk(resulting_risk)


def poam_records(poamdata) -> list[dict]:
    return find_record_list(poamdata, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


def empty_poam_counts() -> dict[str, int]:
    return {"Ongoing": 0, "Open": 0, "Accepted": 0, "Other": 0}


def increment_poam_counts(grouped_counts: dict[str, dict[str, int]], group_name: str, status: str) -> None:
    grouped_counts.setdefault(group_name, empty_poam_counts())
    status_key = status if status in {"Ongoing", "Open", "Accepted"} else "Other"
    grouped_counts[group_name][status_key] += 1


def poam_count_rows(grouped_counts: dict[str, dict[str, int]], ordered_names: list[str], label_key: str) -> list[dict[str, str]]:
    rows = []
    for name in ordered_names:
        counts = grouped_counts.get(name, empty_poam_counts())
        total = sum(counts.values())
        rows.append(
            {
                label_key: name,
                "ongoing": safe_text(counts["Ongoing"]),
                "open": safe_text(counts["Open"]),
                "accepted": safe_text(counts["Accepted"]),
                "other": safe_text(counts["Other"]),
                "total": safe_text(total),
            }
        )
    return rows


def build_poam_raw_severity_rows(poamdata) -> list[dict[str, str]]:
    grouped_counts: dict[str, dict[str, int]] = {}
    for record in poam_records(poamdata):
        status = poam_status(record)
        if status == "Completed":
            continue
        increment_poam_counts(grouped_counts, poam_raw_severity(record), status)
    return poam_count_rows(grouped_counts, ["Critical", "High", "Medium", "Low", "Unknown"], "severity")


def build_poam_scheduled_completion_rows(poamdata) -> list[dict[str, str]]:
    grouped_counts: dict[str, dict[str, int]] = {}
    for record in poam_records(poamdata):
        status = poam_status(record)
        if status == "Completed" or not is_within_next_30_days(poam_scheduled_completion(record)):
            continue
        increment_poam_counts(grouped_counts, poam_raw_severity(record), status)
    return poam_count_rows(grouped_counts, ["Critical", "High", "Medium", "Low", "Unknown"], "severity")


def build_poam_resulting_risk_rows(poamdata) -> list[dict[str, str]]:
    grouped_counts: dict[str, dict[str, int]] = {}
    for record in poam_records(poamdata):
        status = poam_status(record)
        if status == "Completed":
            continue
        increment_poam_counts(grouped_counts, poam_resulting_risk(record), status)
    return poam_count_rows(grouped_counts, ["Very High", "High", "Moderate", "Low", "Very low", "N / A"], "risk")


def build_patch_vulnerability_rows(patchdata) -> list[dict[str, str]]:
    rows = []
    for record in find_patch_record_list(patchdata):
        hostname = first_value(record, ["hostname", "hostName", "host", "assetName", "computerName", "dnsName", "machineName"])
        plugin_id = first_value(record, ["pluginId", "pluginID", "plugin_id", "plugin", "pluginIDString"])
        plugin_name = first_value(record, ["pluginName", "plugin_name", "pluginTitle", "vulnerabilityName", "name", "title"])
        severity = first_value(record, ["severity", "severityNumber", "severityValue", "severityId", "severityID"])
        severity_name = first_value(record, ["severityName", "severityString", "riskFactor", "risk"])
        cvss_score = first_value(record, ["cvssScore", "cvss", "cvssBaseScore", "cvss3BaseScore", "cvssV3BaseScore", "score"])

        if not hostname:
            hostname = first_nested_value(record, [["asset", "hostname"], ["asset", "hostName"], ["host", "name"]])
        if not plugin_id:
            plugin_id = first_nested_value(record, [["plugin", "id"], ["plugin", "pluginId"]])
        if not plugin_name:
            plugin_name = first_nested_value(record, [["plugin", "name"], ["plugin", "title"], ["vulnerability", "name"]])
        if not severity:
            severity = first_nested_value(
                record,
                [["plugin", "severity"], ["plugin", "severityNumber"], ["vulnerability", "severity"]],
            )
        if not severity_name:
            severity_name = first_nested_value(
                record,
                [["plugin", "severityName"], ["plugin", "severityString"], ["vulnerability", "severityName"]],
            )
        if not cvss_score:
            cvss_score = first_nested_value(record, [["plugin", "cvssScore"], ["vulnerability", "cvssScore"], ["cvss", "score"]])

        severity_number = severity_number_from_value(severity or severity_name)
        if severity_number not in {4, 3}:
            continue

        if any([hostname, plugin_id, plugin_name, severity_name, cvss_score]):
            rows.append(
                {
                    "hostname": hostname or "Unknown",
                    "plugin_id": plugin_id or "Unknown",
                    "plugin_name": plugin_name or "Unknown",
                    "severity_number": safe_text(severity_number),
                    "severity_name": severity_name or severity_name_from_number(severity_number),
                    "cvss_score": cvss_score or "Unknown",
                    "cvss_sort": safe_text(numeric_sort_value(cvss_score)),
                }
            )
    return sorted(
        rows,
        key=lambda row: (
            -int(row["severity_number"]),
            -numeric_sort_value(row["cvss_sort"]),
            row["hostname"].lower(),
        ),
    )


def build_report_data(system_package: dict, patchdata=None, hardwaredata=None, softwaredata=None, ppsmdata=None, poamdata=None) -> dict[str, str]:
    system_key = safe_text(system_package.get("systemKey")).strip()
    if not system_key:
        print("ERROR: The returned system package JSON did not include systemKey.")
        sys.exit(1)

    package_framework = system_package.get("packageFramework", {})
    if not isinstance(package_framework, dict):
        package_framework = {}

    return {
        "system_key": system_key,
        "title": safe_text(system_package.get("title")).strip() or "Unknown",
        "report_title": report_title_for_system(system_package.get("title")),
        "description": safe_text(system_package.get("description")).strip() or "No description returned.",
        "number_of_checklists": safe_text(system_package.get("numberOfChecklists")).strip() or "0",
        "framework_title": safe_text(package_framework.get("frameworkTitle")).strip() or "Unknown",
        "framework_acronym": safe_text(package_framework.get("frameworkAcronym")).strip() or "Unknown",
        "framework_version": safe_text(package_framework.get("frameworkVersion")).strip() or "Unknown",
        "framework_levels": build_framework_levels(package_framework),
        "score_rows": build_score_rows(system_package),
        "category_total_score_rows": build_category_total_score_rows(system_package),
        "total_status_rows": build_total_status_rows(system_package),
        "patch_rows": build_patch_rows(system_package),
        "table_of_contents_rows": build_table_of_contents_rows(),
        "patch_vulnerability_rows": build_patch_vulnerability_rows(patchdata),
        "hardware_rows": build_hardware_rows(hardwaredata),
        "software_rows": build_software_rows(softwaredata),
        "ppsm_rows": build_ppsm_rows(ppsmdata),
        "poam_raw_severity_rows": build_poam_raw_severity_rows(poamdata),
        "poam_scheduled_completion_rows": build_poam_scheduled_completion_rows(poamdata),
        "poam_resulting_risk_rows": build_poam_resulting_risk_rows(poamdata),
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
    }


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, str]) -> bool:
    try:
        from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
        from reportlab.graphics.shapes import Drawing, Rect, String  # pyright: ignore[reportMissingModuleSource]
    except ImportError:
        return False

    class SectionPageNumberDocTemplate(SimpleDocTemplate):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.section_page_numbers: dict[str, int] = {}

        def afterFlowable(self, flowable) -> None:
            anchor = getattr(flowable, "_toc_anchor", None)
            if anchor and anchor not in self.section_page_numbers:
                self.section_page_numbers[anchor] = self.page

    def draw_page_number(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 18, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    styles = getSampleStyleSheet()
    table_header_style = styles["BodyText"].clone("CenteredTableHeader")
    table_header_style.alignment = 1
    table_header_style.fontName = "Helvetica-Bold"
    contents_link_style = styles["BodyText"].clone("ContentsLink")
    contents_link_style.fontSize = 9
    contents_link_style.leading = 11
    contents_link_style.textColor = colors.blue
    bright_yellow = colors.Color(1.0, 0.95, 0.05)
    cat_row_backgrounds = [colors.lightcoral, colors.orange, bright_yellow, colors.white]
    status_row_backgrounds = [colors.white, colors.lightgreen, colors.lightgrey, colors.grey]
    patch_row_backgrounds = [colors.Color(0.9, 0.25, 0.35), colors.salmon, colors.orange, bright_yellow, colors.white]
    poam_severity_backgrounds = {
        "Critical": colors.Color(0.9, 0.25, 0.35),
        "High": colors.salmon,
        "Medium": colors.orange,
        "Low": bright_yellow,
    }
    poam_risk_backgrounds = {
        "Very High": colors.crimson,
        "High": colors.red,
        "Moderate": bright_yellow,
        "Low": colors.lightgreen,
        "Very low": colors.darkgreen,
    }

    def status_paragraph(value: bool) -> object:
        if value:
            return Paragraph('<font color="green">✓</font>', styles["BodyText"])
        return Paragraph('<font color="red">✕</font>', styles["BodyText"])

    def anchored_heading(title: str, anchor: str):
        paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', styles["Heading1"])
        paragraph._toc_anchor = anchor
        return paragraph

    def anchored_normal(text: str, anchor: str):
        paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{text}', styles["Normal"])
        paragraph._toc_anchor = anchor
        return paragraph

    def contents_link(title: str, anchor: str):
        return Paragraph(f'<a href="#{html.escape(anchor, quote=True)}" color="blue">{html.escape(title)}</a>', contents_link_style)

    def numeric_value(value) -> float:
        return max(numeric_sort_value(safe_text(value)), 0.0)

    def checklist_findings_bar_graph(rows: list[dict[str, str]]) -> object:
        drawing_width = 470
        drawing_height = 240
        chart_left = 42
        chart_bottom = 55
        chart_width = 320
        chart_height = 125
        bar_width = 12
        bar_gap = 3
        group_gap = 26
        series = [
            ("Open", "open", None),
            ("NAF", "not_a_finding", colors.lightgreen),
            ("N/A", "not_applicable", colors.lightgrey),
            ("NR", "not_reviewed", colors.white),
        ]
        graph_rows = rows[:4]
        max_value = max(
            [numeric_value(row[key]) for row in graph_rows for _, key, _ in series] or [0]
        )
        drawing = Drawing(drawing_width, drawing_height)
        drawing.add(String(0, 220, "Checklist Findings by CAT", fontSize=12, fontName="Helvetica-Bold"))
        drawing.add(Rect(chart_left, chart_bottom, chart_width, chart_height, strokeColor=colors.grey, fillColor=None, strokeWidth=0.5))
        drawing.add(String(6, chart_bottom + chart_height - 4, safe_text(int(max_value)), fontSize=8))
        drawing.add(String(24, chart_bottom - 2, "0", fontSize=8))
        if max_value <= 0:
            return drawing

        group_width = (bar_width * len(series)) + (bar_gap * (len(series) - 1))
        for group_index, row in enumerate(graph_rows):
            group_x = chart_left + 20 + (group_index * (group_width + group_gap))
            for series_index, (_, key, fill_color) in enumerate(series):
                value = numeric_value(row[key])
                bar_height = chart_height * value / max_value if value else 0
                bar_x = group_x + (series_index * (bar_width + bar_gap))
                bar_color = cat_row_backgrounds[group_index] if key == "open" else fill_color
                drawing.add(Rect(bar_x, chart_bottom, bar_width, bar_height, strokeColor=colors.grey, fillColor=bar_color, strokeWidth=0.25))
                if value > 0:
                    drawing.add(String(bar_x - 2, chart_bottom + bar_height + 4, safe_text(int(value)), fontSize=7))
            drawing.add(String(group_x, 34, row["category"], fontSize=8))

        legend_y = 175
        for label, _, fill_color in series:
            if label == "Open":
                for color_index, open_color in enumerate(cat_row_backgrounds[:3]):
                    drawing.add(Rect(382 + (color_index * 12), legend_y - 2, 10, 10, strokeColor=colors.grey, fillColor=open_color, strokeWidth=0.25))
                drawing.add(String(422, legend_y, label, fontSize=8))
            else:
                drawing.add(Rect(382, legend_y - 2, 10, 10, strokeColor=colors.grey, fillColor=fill_color, strokeWidth=0.25))
                drawing.add(String(398, legend_y, label, fontSize=8))
            legend_y -= 18
        drawing.add(String(382, legend_y, "Open follows CAT colors", fontSize=6))
        return drawing

    def build_contents_table():
        contents_rows = report_data["table_of_contents_rows"]
        contents_table_rows = [[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)]]
        contents_table_rows.extend(
            [
                contents_link(row["title"], row["anchor"]),
                row["page_number"],
            ]
            for row in contents_rows
        )
        table = Table(contents_table_rows, hAlign="LEFT", colWidths=[380, 90])
        table.setStyle(
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
        return table

    document_options = {
        "pagesize": letter,
        "title": report_data["report_title"],
        "author": "OpenRMF Professional External API Scripts",
    }
    contents_table = build_contents_table()
    story = [
        Paragraph(report_data["report_title"], styles["Title"]),
        Spacer(1, 4),
        Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
        Spacer(1, 2),
        anchored_normal(f"Title: {html.escape(report_data['title'])}", "overview"),
        Spacer(1, 2),
        Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
        Spacer(1, 2),
        Paragraph(f"Description: {html.escape(report_data['description'])}", styles["Normal"]),
        Spacer(1, 2),
        Paragraph(
            f"Number of Checklists: {html.escape(report_data['number_of_checklists'])}",
            styles["Normal"],
        ),
        Spacer(1, 2),
        Paragraph(f"Framework Title: {html.escape(report_data['framework_title'])}", styles["Normal"]),
        Spacer(1, 2),
        Paragraph(f"Framework Acronym: {html.escape(report_data['framework_acronym'])}", styles["Normal"]),
        Spacer(1, 2),
        Paragraph(f"Framework Version: {html.escape(report_data['framework_version'])}", styles["Normal"]),
        Spacer(1, 2),
        Paragraph("Framework Levels:", styles["Normal"]),
    ]
    if report_data["framework_levels"]:
        for level in report_data["framework_levels"]:
            story.append(
                Paragraph(
                    html.escape(format_framework_level(level)),
                    styles["Normal"],
                )
            )
    else:
        story.append(Paragraph("None returned.", styles["Normal"]))
    story.extend(
        [
            Spacer(1, 14),
            contents_table,
        ]
    )
    checklist_findings_table = Table(
        [
            [
                Paragraph("Category", table_header_style),
                Paragraph("Open", table_header_style),
                Paragraph("Not a<br/>Finding", table_header_style),
                Paragraph("Not<br/>Applicable", table_header_style),
                Paragraph("Not<br/>Reviewed", table_header_style),
            ],
            *[
                [
                    row["category"],
                    row["open"],
                    row["not_a_finding"],
                    row["not_applicable"],
                    row["not_reviewed"],
                ]
                for row in report_data["score_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[70, 60, 95, 105, 90],
    )
    checklist_findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (1, row_index), (1, row_index), background_color)
                    for row_index, background_color in enumerate(cat_row_backgrounds, start=1)
                ],
                ("BACKGROUND", (2, 1), (2, -1), colors.lightgreen),
                ("BACKGROUND", (3, 1), (3, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    checklist_findings_chart = checklist_findings_bar_graph(report_data["score_rows"])

    category_total_table = Table(
        [
            [Paragraph("Category", table_header_style), Paragraph("Total<br/>Score", table_header_style)],
            *[[row["category"], row["total_score"]] for row in report_data["category_total_score_rows"]],
        ],
        hAlign="LEFT",
        colWidths=[80, 85],
    )
    category_total_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (0, row_index), (-1, row_index), background_color)
                    for row_index, background_color in enumerate(cat_row_backgrounds[:3], start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    status_totals_table = Table(
        [
            [Paragraph("Status", table_header_style), Paragraph("Total", table_header_style)],
            *[[row["status"], row["total"]] for row in report_data["total_status_rows"]],
        ],
        hAlign="LEFT",
        colWidths=[95, 65],
    )
    status_totals_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (0, row_index), (-1, row_index), background_color)
                    for row_index, background_color in enumerate(status_row_backgrounds, start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    patch_totals_table = Table(
        [
            [Paragraph("Status", table_header_style), Paragraph("Total", table_header_style)],
            *[[row["metric"], row["value"]] for row in report_data["patch_rows"]],
        ],
        hAlign="LEFT",
        colWidths=[95, 65],
    )
    patch_totals_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (0, row_index), (-1, row_index), background_color)
                    for row_index, background_color in enumerate(patch_row_backgrounds, start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    checklist_summary_tables = Table(
        [
            [Paragraph("Category Total Scores", styles["Heading2"]), Paragraph("Status Totals", styles["Heading2"])],
            [category_total_table, status_totals_table],
        ],
        hAlign="LEFT",
        colWidths=[210, 210],
    )
    checklist_summary_tables.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 18),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.extend(
        [
            PageBreak(),
            anchored_heading("Checklist Information", "checklist-information"),
            Spacer(1, 12),
            checklist_findings_table,
            Spacer(1, 16),
            checklist_findings_chart,
            Spacer(1, 18),
            checklist_summary_tables,
        ]
    )
    story.extend(
        [
            PageBreak(),
            anchored_heading("Patch Vulnerability Information", "patch"),
            Spacer(1, 12),
            Paragraph("Patch Vulnerability Totals", styles["Heading2"]),
            Spacer(1, 8),
            patch_totals_table,
        ]
    )
    patch_vulnerability_table_rows = [
        ["Hostname", "SeverityName", "Plugin Id", "Plugin Name", "CVSS Score"],
        *[
            [
                Paragraph(html.escape(row["hostname"]), styles["BodyText"]),
                Paragraph(html.escape(row["severity_name"]), styles["BodyText"]),
                Paragraph(html.escape(row["plugin_id"]), styles["BodyText"]),
                Paragraph(html.escape(row["plugin_name"]), styles["BodyText"]),
                Paragraph(html.escape(row["cvss_score"]), styles["BodyText"]),
            ]
            for row in report_data["patch_vulnerability_rows"]
        ],
    ]
    if len(patch_vulnerability_table_rows) == 1:
        patch_vulnerability_table_rows.append(["No patch vulnerability details returned.", "", "", "", ""])

    story.extend(
        [
            Spacer(1, 24),
            Paragraph("Patch Vulnerability Details", styles["Heading2"]),
            Spacer(1, 8),
            Table(
                patch_vulnerability_table_rows,
                hAlign="LEFT",
                repeatRows=1,
                colWidths=[90, 75, 65, 200, 65],
            ),
        ]
    )
    patch_vulnerability_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("ALIGN", (2, 1), (2, -1), "RIGHT"),
        ("ALIGN", (4, 1), (4, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for row_index, row in enumerate(report_data["patch_vulnerability_rows"], start=1):
        severity_color = colors.Color(0.9, 0.25, 0.35) if row["severity_number"] == "4" else colors.salmon
        patch_vulnerability_styles.append(("BACKGROUND", (1, row_index), (1, row_index), severity_color))

    story[-1].setStyle(
        TableStyle(patch_vulnerability_styles)
    )
    hardware_table_rows = [
        ["Hostname", "Operating System", "IP Address List", "Patch Scan", "Checklists"],
        *[
            [
                Paragraph(html.escape(row["hostname"]), styles["BodyText"]),
                Paragraph(html.escape(row["operating_system"]), styles["BodyText"]),
                Paragraph(html.escape(row["ip_address_list"]), styles["BodyText"]),
                status_paragraph(row["patch_scan"]),
                status_paragraph(row["checklists"]),
            ]
            for row in report_data["hardware_rows"]
        ],
    ]
    if len(hardware_table_rows) == 1:
        hardware_table_rows.append(["No hardware details returned.", "", "", "", ""])

    story.extend(
        [
            PageBreak(),
            anchored_heading("Hardware Inventory", "hardware"),
            Spacer(1, 12),
            Table(
                hardware_table_rows,
                hAlign="LEFT",
                repeatRows=1,
                colWidths=[88, 120, 120, 70, 67],
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (3, 1), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    software_table_rows = [
        ["Software Name", "Version", "Asset Type String", "# Devices", "Hostname"],
        *[
            [
                Paragraph(html.escape(row["software_name"]), styles["BodyText"]),
                Paragraph(html.escape(row["version"]), styles["BodyText"]),
                Paragraph(html.escape(row["asset_type_string"]), styles["BodyText"]),
                Paragraph(html.escape(row["device_count"]), styles["BodyText"]),
                Paragraph(html.escape(row["hostnames"]), styles["BodyText"]),
            ]
            for row in report_data["software_rows"]
        ],
    ]
    if len(software_table_rows) == 1:
        software_table_rows.append(["No software details returned.", "", "", "", ""])

    story.extend(
        [
            PageBreak(),
            anchored_heading("Software Inventory by Device", "software"),
            Spacer(1, 12),
            Table(
                software_table_rows,
                hAlign="LEFT",
                repeatRows=1,
                colWidths=[125, 60, 110, 55, 115],
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (3, 1), (3, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    ppsm_table_rows = [
        ["Port", "Protocol", "Service", "# Devices", "Hostname", Paragraph("Boundaries<br/>Crossed", table_header_style)],
        *[
            [
                Paragraph(html.escape(row["port"]), styles["BodyText"]),
                Paragraph(html.escape(row["protocol"]), styles["BodyText"]),
                Paragraph(html.escape(row["service"]), styles["BodyText"]),
                Paragraph(html.escape(row["device_count"]), styles["BodyText"]),
                Paragraph(html.escape(row["hostnames"]), styles["BodyText"]),
                Paragraph(html.escape(row["boundaries_crossed"]), styles["BodyText"]),
            ]
            for row in report_data["ppsm_rows"]
        ],
    ]
    if len(ppsm_table_rows) == 1:
        ppsm_table_rows.append(["No ports/protocols/services details returned.", "", "", "", "", ""])

    story.extend(
        [
            PageBreak(),
            anchored_heading("Ports, Protocols, and Services by Boundary", "ports-protocols-services"),
            Spacer(1, 12),
            Table(
                ppsm_table_rows,
                hAlign="LEFT",
                repeatRows=1,
                colWidths=[40, 50, 95, 52, 115, 113],
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (0, 1), (0, -1), "RIGHT"),
                ("ALIGN", (3, 1), (3, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    poam_raw_severity_table_rows = [
        ["Severity", "Ongoing", "Open", "Accepted", "Other", "Total"],
        *[
            [row["severity"], row["ongoing"], row["open"], row["accepted"], row["other"], row["total"]]
            for row in report_data["poam_raw_severity_rows"]
        ],
    ]
    poam_scheduled_completion_table_rows = [
        ["Severity", "Ongoing", "Open", "Accepted", "Other", "Total"],
        *[
            [row["severity"], row["ongoing"], row["open"], row["accepted"], row["other"], row["total"]]
            for row in report_data["poam_scheduled_completion_rows"]
        ],
    ]
    poam_resulting_risk_table_rows = [
        ["Resulting Risk", "Ongoing", "Open", "Accepted", "Other", "Total"],
        *[
            [row["risk"], row["ongoing"], row["open"], row["accepted"], row["other"], row["total"]]
            for row in report_data["poam_resulting_risk_rows"]
        ],
    ]

    def poam_table_style(rows: list[dict[str, str]], label_key: str, background_map: dict) -> TableStyle:
        table_styles = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        for row_index, row in enumerate(rows, start=1):
            background_color = background_map.get(row[label_key])
            if background_color:
                table_styles.append(("BACKGROUND", (0, row_index), (-1, row_index), background_color))
                if row[label_key] == "Very low":
                    table_styles.append(("TEXTCOLOR", (0, row_index), (-1, row_index), colors.white))
        return TableStyle(table_styles)

    story.extend(
        [
            PageBreak(),
            anchored_heading("POAM Information", "poam"),
            Spacer(1, 12),
            Paragraph("Raw Severity Numbers", styles["Heading2"]),
            Spacer(1, 8),
            Table(poam_raw_severity_table_rows, hAlign="LEFT"),
        ]
    )
    story[-1].setStyle(poam_table_style(report_data["poam_raw_severity_rows"], "severity", poam_severity_backgrounds))
    story.extend(
        [
            Spacer(1, 24),
            Paragraph("Scheduled Completion by Raw Severity Numbers", styles["Heading2"]),
            Spacer(1, 8),
            Table(poam_scheduled_completion_table_rows, hAlign="LEFT"),
        ]
    )
    story[-1].setStyle(poam_table_style(report_data["poam_scheduled_completion_rows"], "severity", poam_severity_backgrounds))
    story.extend(
        [
            Spacer(1, 24),
            Paragraph("Resulting Risk Numbers", styles["Heading2"]),
            Spacer(1, 8),
            Table(poam_resulting_risk_table_rows, hAlign="LEFT"),
        ]
    )
    story[-1].setStyle(poam_table_style(report_data["poam_resulting_risk_rows"], "risk", poam_risk_backgrounds))
    measurement_document = SectionPageNumberDocTemplate(BytesIO(), **document_options)
    measurement_document.build(list(story), onFirstPage=draw_page_number, onLaterPages=draw_page_number)
    for row in report_data["table_of_contents_rows"]:
        page_number = measurement_document.section_page_numbers.get(row["anchor"])
        if page_number:
            row["page_number"] = safe_text(page_number)
    updated_contents_table = build_contents_table()
    for story_index, flowable in enumerate(story):
        if flowable is contents_table:
            story[story_index] = updated_contents_table
            break
    document = SectionPageNumberDocTemplate(str(output_path), **document_options)
    document.build(story, onFirstPage=draw_page_number, onLaterPages=draw_page_number)
    return True


def escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 12, line_backgrounds: dict[int, tuple[float, float, float]] | None = None) -> str:
    y_position = 740
    content = ["BT", f"/F1 {font_size} Tf"]
    for line_index, line in enumerate(lines):
        background_color = (line_backgrounds or {}).get(line_index)
        if background_color:
            red, green, blue = background_color
            content.append("ET")
            content.append(f"q {red} {green} {blue} rg 66 {y_position - 4} 480 16 re f Q")
            content.append("BT")
            content.append(f"/F1 {font_size} Tf")
        content.append(f"1 0 0 1 72 {y_position} Tm ({escape_pdf_text(line)}) Tj")
        y_position -= 18
    content.append("ET")
    return "\n".join(content)


def add_page_number_to_page_stream(page_stream: str, page_number: int, page_width: int) -> str:
    return (
        page_stream
        + "\nBT\n"
        + "/F1 9 Tf\n"
        + f"1 0 0 1 {page_width - 72} 18 Tm ({escape_pdf_text(f'Page {page_number}')}) Tj\n"
        + "ET"
    )


def make_text_pages(
    lines: list[str],
    font_size: int = 12,
    max_lines: int = 36,
    line_backgrounds: dict[int, tuple[float, float, float]] | None = None,
) -> list[str]:
    pages = []
    for start_index in range(0, len(lines), max_lines):
        page_backgrounds = {
            line_index - start_index: background_color
            for line_index, background_color in (line_backgrounds or {}).items()
            if start_index <= line_index < start_index + max_lines
        }
        pages.append(
            make_text_page(
                lines[start_index : start_index + max_lines],
                font_size=font_size,
                line_backgrounds=page_backgrounds,
            )
        )
    return [add_page_number_to_page_stream(page_stream, page_number, 612) for page_number, page_stream in enumerate(pages, start=1)]


def build_fallback_pages(report_data: dict[str, str]) -> list[str]:
    def text_number(value) -> float:
        return max(numeric_sort_value(safe_text(value)), 0.0)

    def text_stacked_histogram(values: list[tuple[float, str]], maximum_value: float, width: int = 12) -> str:
        if maximum_value <= 0:
            return "-" * width
        segments = []
        for value, character in values:
            segment_width = round(width * text_number(value) / maximum_value)
            if segment_width > 0:
                segments.append(character * segment_width)
        histogram = "".join(segments)[:width]
        return histogram + "-" * max(0, width - len(histogram))

    score_row_totals = [
        sum(text_number(row[key]) for key in ("open", "not_a_finding", "not_applicable", "not_reviewed"))
        for row in report_data["score_rows"]
    ]
    max_score_total = max(score_row_totals or [0])

    title_lines = [
        report_data["report_title"],
        "",
        f"Date Generated: {report_data['generated_at']}",
    ]
    contents_lines = ["Page Title                                      Page Number", "--------------------------------------------  -----------"]
    contents_lines.extend([f"{row['title']:<44}  {row['page_number']:>11}" for row in report_data["table_of_contents_rows"]])

    detail_lines = [f"Title: {report_data['title']}", f"System Key: {report_data['system_key']}", "Description:"]
    detail_lines.extend(textwrap.wrap(report_data["description"], width=78) or [""])
    detail_lines.extend(
        [
            "",
            f"Number of Checklists: {report_data['number_of_checklists']}",
            "",
            f"Framework Title: {report_data['framework_title']}",
            f"Framework Acronym: {report_data['framework_acronym']}",
            f"Framework Version: {report_data['framework_version']}",
            "",
            "Framework Levels:",
        ]
    )
    if report_data["framework_levels"]:
        for level in report_data["framework_levels"]:
            detail_lines.append(f"- {format_framework_level(level)}")
    else:
        detail_lines.append("None returned.")
    title_lines.extend([*detail_lines, "", *contents_lines])

    checklist_lines = [
        "Checklist Information",
        "",
        "Category      Open       Not a Finding  Not Applicable  Not Reviewed",
        "------------  ---------  -------------  --------------  ------------",
    ]
    for row in report_data["score_rows"]:
        checklist_lines.append(
            f"{row['category']:<12}  {row['open']:>9}  {row['not_a_finding']:>13}  {row['not_applicable']:>14}  {row['not_reviewed']:>12}"
        )
    checklist_lines.extend(["", "Bar Graph - Checklist Findings by CAT", "Legend: O=Open F=Not a Finding A=Not Applicable R=Not Reviewed"])
    for row in report_data["score_rows"]:
        histogram = text_stacked_histogram(
            [
                (text_number(row["open"]), "O"),
                (text_number(row["not_a_finding"]), "F"),
                (text_number(row["not_applicable"]), "A"),
                (text_number(row["not_reviewed"]), "R"),
            ],
            max_score_total,
        )
        checklist_lines.append(f"{row['category']:<12}  {histogram}")
    checklist_lines.extend(["", "Category Total Scores", "Category      Total Score", "------------  -----------"])
    for row in report_data["category_total_score_rows"]:
        checklist_lines.append(f"{row['category']:<12}  {row['total_score']:>11}")
    checklist_lines.extend(["", "Status Totals", "Status          Total", "--------------  ---------"])
    for row in report_data["total_status_rows"]:
        checklist_lines.append(f"{row['status']:<14}  {row['total']:>9}")

    checklist_line_backgrounds = {
        4: (0.94, 0.5, 0.5),
        5: (1.0, 0.65, 0.0),
        6: (1.0, 0.95, 0.05),
        18: (0.56, 0.93, 0.56),
        19: (0.83, 0.83, 0.83),
        20: (0.5, 0.5, 0.5),
    }

    patch_lines = [
        "Patch Vulnerability Information",
        "",
        "Patch Vulnerability Totals",
        "",
        "Status         Total",
        "-------------  ---------",
    ]
    for row in report_data["patch_rows"]:
        patch_lines.append(f"{row['metric']:<13}  {row['value']:>9}")

    patch_line_backgrounds = {
        6: (0.9, 0.25, 0.35),
        7: (0.98, 0.5, 0.45),
        8: (1.0, 0.65, 0.0),
        9: (1.0, 0.95, 0.05),
        10: (1.0, 1.0, 1.0),
    }

    patch_vulnerability_lines = [
        "Patch Vulnerability Details",
        "",
        "Hostname              SeverityName  Plugin ID  Plugin Name                    CVSS",
        "--------------------  ------------  ---------  -----------------------------  -----",
    ]
    patch_vulnerability_line_backgrounds = {}
    if report_data["patch_vulnerability_rows"]:
        for row in report_data["patch_vulnerability_rows"]:
            hostname = row["hostname"][:20]
            severity_name = row["severity_name"][:12]
            plugin_id = row["plugin_id"][:9]
            plugin_name = row["plugin_name"][:29]
            cvss_score = row["cvss_score"][:5]
            line_index = len(patch_vulnerability_lines)
            patch_vulnerability_line_backgrounds[line_index] = (
                (0.9, 0.25, 0.35) if row["severity_number"] == "4" else (0.98, 0.5, 0.45)
            )
            patch_vulnerability_lines.append(
                f"{hostname:<20}  {severity_name:<12}  {plugin_id:>9}  {plugin_name:<29}  {cvss_score:>5}"
            )
    else:
        patch_vulnerability_lines.append("No patch vulnerability details returned.")

    hardware_lines = [
        "Hardware Inventory",
        "",
        "Hostname              Operating System      IP Address List       Patch Scan  Checklists",
        "--------------------  --------------------  --------------------  ----------  ----------",
    ]
    if report_data["hardware_rows"]:
        for row in report_data["hardware_rows"]:
            hostname = row["hostname"][:20]
            operating_system = row["operating_system"][:20]
            ip_address_list = row["ip_address_list"][:20]
            patch_scan = "Y" if row["patch_scan"] else "X"
            checklists = "Y" if row["checklists"] else "X"
            hardware_lines.append(
                f"{hostname:<20}  {operating_system:<20}  {ip_address_list:<20}  {patch_scan:^10}  {checklists:^10}"
            )
    else:
        hardware_lines.append("No hardware details returned.")

    software_lines = [
        "Software Inventory by Device",
        "",
        "Software Name         Version    Asset Type       # Devices  Hostname",
        "--------------------  ---------  ---------------  ---------  --------------------",
    ]
    if report_data["software_rows"]:
        for row in report_data["software_rows"]:
            software_name = row["software_name"][:20]
            version = row["version"][:9]
            asset_type_string = row["asset_type_string"][:15]
            device_count = row["device_count"][:9]
            hostnames = row["hostnames"][:20]
            software_lines.append(
                f"{software_name:<20}  {version:<9}  {asset_type_string:<15}  {device_count:>9}  {hostnames}"
            )
    else:
        software_lines.append("No software details returned.")

    ppsm_lines = [
        "Ports, Protocols, and Services by Boundary",
        "",
        "Port   Protocol  Service              # Devices  Hostname              Boundaries Crossed",
        "-----  --------  -------------------  ---------  --------------------  ------------------",
    ]
    if report_data["ppsm_rows"]:
        for row in report_data["ppsm_rows"]:
            port = row["port"][:5]
            protocol = row["protocol"][:8]
            service = row["service"][:19]
            device_count = row["device_count"][:9]
            hostnames = row["hostnames"][:20]
            boundaries_crossed = row["boundaries_crossed"][:18]
            ppsm_lines.append(
                f"{port:>5}  {protocol:<8}  {service:<19}  {device_count:>9}  {hostnames:<20}  {boundaries_crossed}"
            )
    else:
        ppsm_lines.append("No ports/protocols/services details returned.")

    poam_lines = [
        "POAM Information",
        "",
        "Raw Severity Numbers",
        "",
        "Severity    Ongoing  Open  Accepted  Other  Total",
        "----------  -------  ----  --------  -----  -----",
    ]
    for row in report_data["poam_raw_severity_rows"]:
        poam_lines.append(
            f"{row['severity']:<10}  {row['ongoing']:>7}  {row['open']:>4}  {row['accepted']:>8}  {row['other']:>5}  {row['total']:>5}"
        )
    poam_lines.extend(
        [
            "",
            "Scheduled Completion by Raw Severity Numbers",
            "",
            "Severity    Ongoing  Open  Accepted  Other  Total",
            "----------  -------  ----  --------  -----  -----",
        ]
    )
    for row in report_data["poam_scheduled_completion_rows"]:
        poam_lines.append(
            f"{row['severity']:<10}  {row['ongoing']:>7}  {row['open']:>4}  {row['accepted']:>8}  {row['other']:>5}  {row['total']:>5}"
        )
    poam_lines.extend(
        [
            "",
            "Resulting Risk Numbers",
            "",
            "Resulting Risk  Ongoing  Open  Accepted  Other  Total",
            "--------------  -------  ----  --------  -----  -----",
        ]
    )
    for row in report_data["poam_resulting_risk_rows"]:
        poam_lines.append(
            f"{row['risk']:<14}  {row['ongoing']:>7}  {row['open']:>4}  {row['accepted']:>8}  {row['other']:>5}  {row['total']:>5}"
        )

    poam_line_backgrounds = {
        6: (0.9, 0.25, 0.35),
        7: (0.98, 0.5, 0.45),
        8: (1.0, 0.65, 0.0),
        9: (1.0, 0.95, 0.05),
        16: (0.9, 0.25, 0.35),
        17: (0.98, 0.5, 0.45),
        18: (1.0, 0.65, 0.0),
        19: (1.0, 0.95, 0.05),
        27: (0.86, 0.08, 0.24),
        28: (1.0, 0.0, 0.0),
        29: (1.0, 1.0, 0.0),
        30: (0.56, 0.93, 0.56),
        31: (0.0, 0.39, 0.0),
    }

    pages = make_text_pages(title_lines)
    pages.append(make_text_page(checklist_lines, line_backgrounds=checklist_line_backgrounds))
    pages.append(make_text_page(patch_lines, line_backgrounds=patch_line_backgrounds))
    pages.extend(
        make_text_pages(
            patch_vulnerability_lines,
            line_backgrounds=patch_vulnerability_line_backgrounds,
        )
    )
    pages.extend(make_text_pages(hardware_lines))
    pages.extend(make_text_pages(software_lines))
    pages.extend(make_text_pages(ppsm_lines))
    pages.extend(make_text_pages(poam_lines, line_backgrounds=poam_line_backgrounds))
    return pages


def write_minimal_pdf(output_path: Path, report_data: dict[str, str]) -> None:
    page_streams = build_fallback_pages(report_data)
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
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>".encode(
                "latin-1"
            )
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
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    output_path.write_bytes(pdf)


def write_pdf(output_path: Path, report_data: dict[str, str]) -> str:
    if write_pdf_with_reportlab(output_path, report_data):
        return "reportlab"
    write_minimal_pdf(output_path, report_data)
    return "fallback"


if len(sys.argv) != REQUIRED_ARGUMENT_COUNT:
    print_usage()
    sys.exit(1)

json_output = call_systempackage_json_script(sys.argv[1:])
system_package_data = parse_json_from_output(json_output)
patchdata_output = call_patchdata_json_script(sys.argv[1:])
patchdata = parse_json_value_from_output(patchdata_output) if patchdata_output else None
hardware_output = call_hardware_json_script(sys.argv[1:])
hardwaredata = parse_json_value_from_output(hardware_output) if hardware_output else None
software_output = call_software_json_script(sys.argv[1:])
softwaredata = parse_json_value_from_output(software_output) if software_output else None
ppsm_output = call_ppsm_json_script(sys.argv[1:])
ppsmdata = parse_json_value_from_output(ppsm_output) if ppsm_output else None
poam_output = call_poam_json_script(sys.argv[1:])
poamdata = parse_json_value_from_output(poam_output) if poam_output else None
report_data = build_report_data(system_package_data, patchdata, hardwaredata, softwaredata, ppsmdata, poamdata)
output_filename = f"OpenRMFPro-System-Package-Overview-{safe_filename_value(report_data['system_key'])}.pdf"
output_path = Path(output_filename)
pdf_writer = write_pdf(output_path, report_data)

print(f"Created PDF: {output_path}")
if pdf_writer == "fallback":
    print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")
