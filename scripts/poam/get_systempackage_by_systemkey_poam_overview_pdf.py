#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional External API - Systempackage POAM Overview PDF
# API Path   : GET /systempackage/{systemKey}/poam
# Description: Calls get_systempackage_by_systemkey_poam_json.py and creates a PDF overview report with POAM status totals.
#
# Required Parameters:
#   1) rootURL            - The base server URL passed to get_systempackage_by_systemkey_poam_json.py.
#   2) applicationKey     - The application key passed to get_systempackage_by_systemkey_poam_json.py.
#   3) authorizationToken - The bearer token passed to get_systempackage_by_systemkey_poam_json.py.
#   4) systemKey          - Required path parameter passed to get_systempackage_by_systemkey_poam_json.py.
#
# Optional Parameters:
#   - days=VALUE
#   - devicename=VALUE
#
# Command Line Example:
#   python3 get_systempackage_by_systemkey_poam_overview_pdf.py \
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
from datetime import datetime
from io import BytesIO
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SOURCE_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
REPORT_TITLE = "OpenRMF Professional POAM Overview"
STATUS_COLUMNS = ["Ongoing", "Completed", "Accepted"]
RISK_COLUMNS = ["Very High", "High", "Moderate", "Low", "Very Low"]
POAM_TYPE_CONTEXTS = {
    "default": {
        "order": ["artifactId", "patchScanId", "statementId", "inheritedControlId", "vulnScanId"],
        "labels": {
            "artifactId": "Checklist Vulnerability",
            "patchScanId": "Patch Vulnerability",
            "statementId": "Compliance Statement",
            "inheritedControlId": "Inherited Controls",
            "vulnScanId": "Technology Vulnerability",
        },
        "manual_label": "Manually Added / Deleted Items",
    },
    "raw_severity": {
        "order": ["artifactId", "patchScanId", "vulnScanId", "statementId", "inheritedControlId"],
        "labels": {
            "artifactId": "Checklist",
            "patchScanId": "Patch Scan",
            "vulnScanId": "Other Technology Scan",
            "statementId": "Compliance Statement",
            "inheritedControlId": "Inherited Control",
        },
        "manual_label": "Manual/Deleted",
    },
}
POAM_RISK_DEFINITIONS = [
    ("Raw Severity", ["rawSeverity", "rawSeverityString", "rawSeverityValue"]),
    ("Severity", ["severity", "severityString", "severityName"]),
    ("Relevance of Threat", ["relevanceOfThreat", "relevanceOfThreatString", "threatRelevance"]),
    ("Likelihood", ["likelihood", "likelihoodString", "likelihoodValue"]),
    ("Impact", ["impact", "impactString", "impactValue"]),
    ("Residual Risk", ["residualRiskLevel", "residualRisk", "resultingRiskLevel"]),
    (
        "Resulting Residual Risk",
        ["residualRiskLevelMitigations", "residualRiskLevelMitigation", "resultingRisk"],
    ),
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
        + " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
    )


def call_poam_json_script(arguments: list[str]) -> str:
    source_script = Path(__file__).resolve().parent / SOURCE_SCRIPT_NAME
    command = [get_project_python_executable(), str(source_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("ERROR: The POAM JSON script failed.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        sys.exit(result.returncode)

    return result.stdout


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

    print("ERROR: Could not find JSON in the POAM JSON script output.")
    print(output)
    sys.exit(1)


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def safe_filename_value(value: str) -> str:
    safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe_value.strip(".-") or "unknown-system"


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


def poam_records(poamdata) -> list[dict]:
    return find_record_list(poamdata, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


def build_status_totals(records: list[dict]) -> dict[str, int]:
    totals = {status: 0 for status in STATUS_COLUMNS}
    for record in records:
        status = poam_status(record)
        if status in totals:
            totals[status] += 1
    return totals


def has_poam_type_value(record: dict, key: str) -> bool:
    value = record.get(key)
    return safe_text(value).strip().lower() not in {"", "none", "null"}


def poam_type_labels(context_name: str) -> list[str]:
    context = POAM_TYPE_CONTEXTS[context_name]
    return [context["labels"][key] for key in context["order"]] + [context["manual_label"]]


def poam_type_label(record: dict, context_name: str) -> str:
    context = POAM_TYPE_CONTEXTS[context_name]
    for key in context["order"]:
        if has_poam_type_value(record, key):
            return context["labels"][key]
    return context["manual_label"]


def poam_type(record: dict) -> str:
    return poam_type_label(record, "default")


def raw_severity_poam_type(record: dict) -> str:
    return poam_type_label(record, "raw_severity")


def build_type_status_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels_list = poam_type_labels("default")
    grouped_totals = {
        label: {status: 0 for status in STATUS_COLUMNS}
        for label in poam_type_labels_list
    }
    for record in records:
        status = poam_status(record)
        if status not in STATUS_COLUMNS:
            continue
        grouped_totals[poam_type(record)][status] += 1

    return [
        {
            "poam_type": label,
            "ongoing": safe_text(grouped_totals[label]["Ongoing"]),
            "completed": safe_text(grouped_totals[label]["Completed"]),
            "accepted": safe_text(grouped_totals[label]["Accepted"]),
        }
        for label in poam_type_labels_list
    ]


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


def has_scheduled_completion_date(record: dict) -> bool:
    return parse_date_value(scheduled_completion_value(record)) is not None


def is_past_due_ongoing(record: dict) -> bool:
    scheduled_date = parse_date_value(scheduled_completion_value(record))
    return scheduled_date is not None and scheduled_date < datetime.now().astimezone().date() and poam_status(record) == "Ongoing"


def build_scheduled_completion_type_status_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels_list = poam_type_labels("default")
    grouped_totals = {
        label: {status: 0 for status in STATUS_COLUMNS}
        for label in poam_type_labels_list
    }
    past_due_ongoing_totals = {label: 0 for label in poam_type_labels_list}
    for record in records:
        if not has_scheduled_completion_date(record):
            continue
        status = poam_status(record)
        if status in STATUS_COLUMNS:
            grouped_totals[poam_type(record)][status] += 1
        if is_past_due_ongoing(record):
            past_due_ongoing_totals[poam_type(record)] += 1

    return [
        {
            "poam_type": label,
            "ongoing": safe_text(grouped_totals[label]["Ongoing"]),
            "completed": safe_text(grouped_totals[label]["Completed"]),
            "accepted": safe_text(grouped_totals[label]["Accepted"]),
            "past_due_ongoing": safe_text(past_due_ongoing_totals[label]),
        }
        for label in poam_type_labels_list
    ]


def build_ongoing_no_scheduled_completion_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels_list = poam_type_labels("default")
    grouped_totals = {label: 0 for label in poam_type_labels_list}
    for record in records:
        if poam_status(record) == "Ongoing" and not has_scheduled_completion_date(record):
            grouped_totals[poam_type(record)] += 1

    return [
        {
            "poam_type": label,
            "ongoing_no_scheduled_completion": safe_text(grouped_totals[label]),
        }
        for label in poam_type_labels_list
    ]


def bool_value(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    value_text = safe_text(value).strip().lower()
    return value_text in {"true", "yes", "y", "1"}


def build_false_positive_type_status_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels_list = poam_type_labels("default")
    grouped_totals = {
        label: {status: 0 for status in STATUS_COLUMNS}
        for label in poam_type_labels_list
    }
    for record in records:
        if not bool_value(record.get("falsePositive")):
            continue
        status = poam_status(record)
        if status in STATUS_COLUMNS:
            grouped_totals[poam_type(record)][status] += 1

    return [
        {
            "poam_type": label,
            "ongoing": safe_text(grouped_totals[label]["Ongoing"]),
            "completed": safe_text(grouped_totals[label]["Completed"]),
            "accepted": safe_text(grouped_totals[label]["Accepted"]),
        }
        for label in poam_type_labels_list
    ]


def normalize_risk_value(value: str) -> str:
    value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
    if not value_text:
        return ""
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
    return ""


def build_risk_rows(records: list[dict]) -> list[dict[str, str]]:
    rows = []
    for label, keys in POAM_RISK_DEFINITIONS:
        totals = {risk: 0 for risk in RISK_COLUMNS}
        for record in records:
            risk = normalize_risk_value(first_value(record, keys))
            if risk in totals:
                totals[risk] += 1
        rows.append(
            {
                "risk_type": label,
                "very_high": safe_text(totals["Very High"]),
                "high": safe_text(totals["High"]),
                "moderate": safe_text(totals["Moderate"]),
                "low": safe_text(totals["Low"]),
                "very_low": safe_text(totals["Very Low"]),
            }
        )
    return rows


def poam_raw_severity_risk(record: dict) -> str:
    raw_severity = first_value(record, ["rawSeverity", "rawSeverityString", "rawSeverityValue"])
    raw_severity_text = safe_text(raw_severity).strip().lower()
    if raw_severity_text in {"4", "critical", "cat i", "cat 1", "i"}:
        return "Very High"
    if raw_severity_text in {"3", "high", "cat ii", "cat 2", "ii"}:
        return "High"
    if raw_severity_text in {"2", "medium", "moderate", "cat iii", "cat 3", "iii"}:
        return "Moderate"
    if raw_severity_text in {"1", "low"}:
        return "Low"
    return normalize_risk_value(raw_severity)


def normalize_raw_severity_value(value) -> str:
    raw_severity_text = safe_text(value).strip()
    normalized_text = raw_severity_text.lower().replace("_", " ").replace("-", " ")
    if not normalized_text:
        return ""
    if normalized_text in {"4", "critical", "cat i", "cat 1", "i"}:
        return "Critical"
    if normalized_text in {"3", "high", "cat ii", "cat 2", "ii"}:
        return "High"
    if normalized_text in {"2", "medium", "moderate", "cat iii", "cat 3", "iii"}:
        return "Medium"
    if normalized_text in {"1", "low"}:
        return "Low"
    return raw_severity_text


def raw_severity_sort_key(value: str) -> tuple[int, str]:
    normalized_value = value.lower()
    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "": 99,
    }
    return (severity_order.get(normalized_value, 50), normalized_value)


def raw_severity_background_color(colors_module, severity: str):
    severity_key = severity.strip().lower()
    if severity_key == "critical":
        return colors_module.HexColor("#8B0000")
    if severity_key == "high":
        return colors_module.red
    if severity_key == "medium":
        return colors_module.orange
    if severity_key == "low":
        return colors_module.yellow
    return colors_module.white


def raw_severity_background_rgb(severity: str) -> tuple[float, float, float]:
    severity_key = severity.strip().lower()
    if severity_key == "critical":
        return (0.545, 0.0, 0.0)
    if severity_key == "high":
        return (1.0, 0.0, 0.0)
    if severity_key == "medium":
        return (1.0, 0.647, 0.0)
    if severity_key == "low":
        return (1.0, 1.0, 0.0)
    return (1.0, 1.0, 1.0)


def build_raw_severity_type_matrix(records: list[dict]) -> dict[str, list]:
    poam_type_labels_list = poam_type_labels("raw_severity")
    severity_labels = sorted(
        {
            normalize_raw_severity_value(first_value(record, ["rawSeverity", "rawSeverityString", "rawSeverityValue"]))
            for record in records
        },
        key=raw_severity_sort_key,
    )
    if not severity_labels:
        severity_labels = [""]

    grouped_totals = {
        poam_type_label: {severity_label: 0 for severity_label in severity_labels}
        for poam_type_label in poam_type_labels_list
    }
    for record in records:
        severity_label = normalize_raw_severity_value(first_value(record, ["rawSeverity", "rawSeverityString", "rawSeverityValue"]))
        if severity_label not in grouped_totals[poam_type_labels_list[0]]:
            continue
        grouped_totals[raw_severity_poam_type(record)][severity_label] += 1

    rows = []
    for poam_type_label in poam_type_labels_list:
        row = {"poam_type": poam_type_label}
        for severity_label in severity_labels:
            row[severity_label] = safe_text(grouped_totals[poam_type_label][severity_label])
        rows.append(row)

    return {
        "severity_labels": severity_labels,
        "rows": rows,
    }


def build_raw_severity_histogram_points(records: list[dict]) -> list[dict[str, str]]:
    return [
        {
            "poam_type": raw_severity_poam_type(record),
            "severity": normalize_raw_severity_value(
                first_value(record, ["rawSeverity", "rawSeverityString", "rawSeverityValue"])
            ),
        }
        for record in records
    ]


def build_type_risk_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels_list = poam_type_labels("default")
    grouped_totals = {
        label: {risk: 0 for risk in RISK_COLUMNS}
        for label in poam_type_labels_list
    }
    for record in records:
        risk = poam_raw_severity_risk(record)
        if risk in RISK_COLUMNS:
            grouped_totals[poam_type(record)][risk] += 1

    return [
        {
            "poam_type": label,
            "very_high": safe_text(grouped_totals[label]["Very High"]),
            "high": safe_text(grouped_totals[label]["High"]),
            "moderate": safe_text(grouped_totals[label]["Moderate"]),
            "low": safe_text(grouped_totals[label]["Low"]),
            "very_low": safe_text(grouped_totals[label]["Very Low"]),
        }
        for label in poam_type_labels_list
    ]


def poam_residual_risk_mitigations_risk(record: dict) -> str:
    residual_risk = first_value(
        record,
        ["residualRiskLevelMitigations", "residualRiskLevelMitigation", "resultingRisk"],
    )
    return normalize_risk_value(residual_risk)


def build_type_residual_risk_mitigations_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels_list = poam_type_labels("default")
    grouped_totals = {
        label: {risk: 0 for risk in RISK_COLUMNS}
        for label in poam_type_labels_list
    }
    for record in records:
        risk = poam_residual_risk_mitigations_risk(record)
        if risk in RISK_COLUMNS:
            grouped_totals[poam_type(record)][risk] += 1

    return [
        {
            "poam_type": label,
            "very_high": safe_text(grouped_totals[label]["Very High"]),
            "high": safe_text(grouped_totals[label]["High"]),
            "moderate": safe_text(grouped_totals[label]["Moderate"]),
            "low": safe_text(grouped_totals[label]["Low"]),
            "very_low": safe_text(grouped_totals[label]["Very Low"]),
        }
        for label in poam_type_labels_list
    ]


def build_residual_risk_mitigations_histogram_points(records: list[dict]) -> list[dict[str, str]]:
    points = []
    for record in records:
        residual_risk_text = safe_text(record.get("residualRiskLevelMitigations")).strip()
        if not residual_risk_text:
            continue
        normalized_risk = normalize_risk_value(residual_risk_text)
        if normalized_risk not in RISK_COLUMNS:
            continue
        points.append(
            {
                "poam_type": poam_type(record),
                "risk": normalized_risk,
            }
        )
    return points


def build_report_data(poamdata, system_key: str) -> dict:
    records = poam_records(poamdata)
    system_title = ""
    for record in records:
        system_title = first_value(record, ["systemTitle", "title", "systemName"])
        if system_title:
            break

    raw_severity_type_matrix = build_raw_severity_type_matrix(records)

    return {
        "system_key": system_key,
        "system_title": system_title or "Unknown",
        "status_totals": build_status_totals(records),
        "type_status_rows": build_type_status_rows(records),
        "scheduled_completion_type_status_rows": build_scheduled_completion_type_status_rows(records),
        "ongoing_no_scheduled_completion_rows": build_ongoing_no_scheduled_completion_rows(records),
        "false_positive_type_status_rows": build_false_positive_type_status_rows(records),
        "raw_severity_type_rows": raw_severity_type_matrix["rows"],
        "raw_severity_labels": raw_severity_type_matrix["severity_labels"],
        "raw_severity_histogram_points": build_raw_severity_histogram_points(records),
        "type_residual_risk_mitigations_rows": build_type_residual_risk_mitigations_rows(records),
        "residual_risk_mitigations_histogram_points": build_residual_risk_mitigations_histogram_points(records),
        "poam_count": len(records),
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
    }


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
    try:
        from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
        from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
    except ImportError:
        return False

    styles = getSampleStyleSheet()
    table_header_style = styles["BodyText"].clone("CenteredTableHeader")
    table_header_style.alignment = 1
    table_header_style.fontName = "Helvetica-Bold"
    status_column_backgrounds = [colors.lightblue, colors.lightgreen, colors.lightgrey]
    risk_column_backgrounds = [colors.red, colors.salmon, colors.white, colors.yellow, colors.lightgreen]

    status_table = Table(
        [
            [Paragraph(status, table_header_style) for status in STATUS_COLUMNS],
            [safe_text(report_data["status_totals"][status]) for status in STATUS_COLUMNS],
        ],
        hAlign="LEFT",
        colWidths=[120, 120, 120],
    )
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (column_index, 1), (column_index, 1), background_color)
                    for column_index, background_color in enumerate(status_column_backgrounds)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (0, 1), (-1, 1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    type_status_table = Table(
        [
            ["POAM Type", *[Paragraph(status, table_header_style) for status in STATUS_COLUMNS]],
            *[
                [row["poam_type"], row["ongoing"], row["completed"], row["accepted"]]
                for row in report_data["type_status_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[150, 90, 90, 90],
    )
    type_status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (column_index, 1), (column_index, -1), background_color)
                    for column_index, background_color in enumerate(status_column_backgrounds, start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    raw_severity_labels = report_data["raw_severity_labels"]
    raw_severity_table_headers = [
        "POAM Item Type",
        *[
            Paragraph((severity or "Blank").replace(" ", "<br/>"), table_header_style)
            for severity in raw_severity_labels
        ],
    ]
    raw_severity_table_width = letter[0] - 144
    raw_severity_label_column_width = max(120, min(160, raw_severity_table_width * 0.3))
    raw_severity_value_column_width = (raw_severity_table_width - raw_severity_label_column_width) / max(len(raw_severity_labels), 1)
    type_risk_table = Table(
        [
            raw_severity_table_headers,
            *[
                [row["poam_type"], *[row[severity_label] for severity_label in raw_severity_labels]]
                for row in report_data["raw_severity_type_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[raw_severity_label_column_width, *([raw_severity_value_column_width] * len(raw_severity_labels))],
    )
    type_risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (column_index, 1), (column_index, -1), raw_severity_background_color(colors, severity_label))
                    for column_index, severity_label in enumerate(raw_severity_labels, start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                *[
                    ("TEXTCOLOR", (column_index, 1), (column_index, -1), colors.white)
                    for column_index, severity_label in enumerate(raw_severity_labels, start=1)
                    if severity_label.strip().lower() in {"critical", "high"}
                ],
            ]
        )
    )

    residual_risk_mitigations_type_table = Table(
        [
            ["POAM Type", *[Paragraph(risk.replace(" ", "<br/>"), table_header_style) for risk in RISK_COLUMNS]],
            *[
                [row["poam_type"], row["very_high"], row["high"], row["moderate"], row["low"], row["very_low"]]
                for row in report_data["type_residual_risk_mitigations_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[175, 65, 65, 65, 65, 65],
    )
    residual_risk_mitigations_type_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (column_index, 1), (column_index, -1), background_color)
                    for column_index, background_color in enumerate(risk_column_backgrounds, start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    scheduled_completion_type_status_table = Table(
        [
            ["POAM Type", *[Paragraph(status, table_header_style) for status in STATUS_COLUMNS]],
            *[
                [row["poam_type"], row["ongoing"], row["completed"], row["accepted"]]
                for row in report_data["scheduled_completion_type_status_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[150, 90, 90, 90],
    )
    scheduled_completion_type_status_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        *[
            ("BACKGROUND", (column_index, 1), (column_index, -1), background_color)
            for column_index, background_color in enumerate(status_column_backgrounds, start=1)
        ],
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for row_index, row in enumerate(report_data["scheduled_completion_type_status_rows"], start=1):
        if int(row["past_due_ongoing"]):
            scheduled_completion_type_status_styles.append(("BACKGROUND", (1, row_index), (1, row_index), colors.red))
            scheduled_completion_type_status_styles.append(("TEXTCOLOR", (1, row_index), (1, row_index), colors.white))
    scheduled_completion_type_status_table.setStyle(TableStyle(scheduled_completion_type_status_styles))

    ongoing_no_scheduled_completion_table = Table(
        [
            ["POAM Type", Paragraph("Ongoing with No Scheduled<br/>Completion Date", table_header_style)],
            *[
                [row["poam_type"], row["ongoing_no_scheduled_completion"]]
                for row in report_data["ongoing_no_scheduled_completion_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[190, 155],
    )
    ongoing_no_scheduled_completion_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("BACKGROUND", (1, 1), (1, -1), colors.lightblue),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    false_positive_type_status_table = Table(
        [
            ["POAM Type", *[Paragraph(status, table_header_style) for status in STATUS_COLUMNS]],
            *[
                [row["poam_type"], row["ongoing"], row["completed"], row["accepted"]]
                for row in report_data["false_positive_type_status_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[150, 90, 90, 90],
    )
    false_positive_type_status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                *[
                    ("BACKGROUND", (column_index, 1), (column_index, -1), background_color)
                    for column_index, background_color in enumerate(status_column_backgrounds, start=1)
                ],
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    def build_risk_histogram(points: list[dict[str, str]], title: str) -> BytesIO | None:
        try:
            import matplotlib  # pyright: ignore[reportMissingModuleSource]

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt  # pyright: ignore[reportMissingModuleSource]
        except ImportError:
            return None

        row_labels = poam_type_labels("default")
        risk_index = {risk_label: index for index, risk_label in enumerate(RISK_COLUMNS)}
        type_index = {poam_type_label: index for index, poam_type_label in enumerate(row_labels)}

        x_values = []
        y_values = []
        for point in points:
            risk_label = point["risk"]
            poam_type_label = point["poam_type"]
            if risk_label not in risk_index or poam_type_label not in type_index:
                continue
            x_values.append(risk_index[risk_label] + 0.5)
            y_values.append(type_index[poam_type_label] + 0.5)

        if not x_values:
            return None

        figure_height = max(3.0, 0.45 * len(row_labels) + 1.6)
        figure, axis = plt.subplots(figsize=(7.4, figure_height), dpi=150)
        histogram, _, _, histogram_image = axis.hist2d(
            x_values,
            y_values,
            bins=[list(range(len(RISK_COLUMNS) + 1)), list(range(len(row_labels) + 1))],
            cmap="YlOrRd",
        )
        axis.set_xticks([index + 0.5 for index in range(len(RISK_COLUMNS))], labels=RISK_COLUMNS, rotation=30, ha="right")
        axis.set_yticks([index + 0.5 for index in range(len(row_labels))], labels=row_labels)
        axis.set_xlim(0, len(RISK_COLUMNS))
        axis.set_ylim(0, len(row_labels))
        axis.invert_yaxis()
        axis.set_title(title)
        max_count = int(histogram.max()) if histogram.size else 0
        for risk_label, column_index in risk_index.items():
            for poam_type_label, row_index in type_index.items():
                value = int(histogram[column_index][row_index])
                text_color = "white" if max_count and value >= max(1, round(max_count * 0.45)) else "black"
                if value == 0:
                    text_color = "dimgray"
                axis.text(column_index + 0.5, row_index + 0.5, safe_text(value), ha="center", va="center", color=text_color, fontsize=8)
        axis.set_xticks(list(range(len(RISK_COLUMNS) + 1)), minor=True)
        axis.set_yticks(list(range(len(row_labels) + 1)), minor=True)
        axis.grid(which="minor", color="white", linestyle="-", linewidth=1.2)
        axis.tick_params(which="minor", bottom=False, left=False)
        colorbar = figure.colorbar(histogram_image, ax=axis)
        colorbar.set_label("POAM Count")
        figure.tight_layout()

        image_buffer = BytesIO()
        figure.savefig(image_buffer, format="png", bbox_inches="tight")
        plt.close(figure)
        image_buffer.seek(0)
        return image_buffer

    def build_raw_severity_histogram(points: list[dict[str, str]], severity_labels: list[str], title: str) -> BytesIO | None:
        try:
            import matplotlib  # pyright: ignore[reportMissingModuleSource]

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt  # pyright: ignore[reportMissingModuleSource]
        except ImportError:
            return None

        row_labels = poam_type_labels("raw_severity")
        severity_index = {severity_label: index for index, severity_label in enumerate(severity_labels)}
        type_index = {poam_type_label: index for index, poam_type_label in enumerate(row_labels)}

        x_values = []
        y_values = []
        for point in points:
            severity_label = point["severity"]
            poam_type_label = point["poam_type"]
            if severity_label not in severity_index or poam_type_label not in type_index:
                continue
            x_values.append(severity_index[severity_label] + 0.5)
            y_values.append(type_index[poam_type_label] + 0.5)

        if not x_values:
            return None

        figure_width = max(7.4, 1.9 + (1.05 * len(severity_labels)))
        figure_height = max(3.0, 0.5 * len(row_labels) + 1.6)
        figure, axis = plt.subplots(figsize=(figure_width, figure_height), dpi=150)
        histogram, _, _, histogram_image = axis.hist2d(
            x_values,
            y_values,
            bins=[list(range(len(severity_labels) + 1)), list(range(len(row_labels) + 1))],
            cmap="YlOrRd",
        )
        axis.set_xticks([index + 0.5 for index in range(len(severity_labels))], labels=[severity or "Blank" for severity in severity_labels], rotation=30, ha="right")
        axis.set_yticks([index + 0.5 for index in range(len(row_labels))], labels=row_labels)
        axis.set_xlim(0, len(severity_labels))
        axis.set_ylim(0, len(row_labels))
        axis.invert_yaxis()
        axis.set_title(title)
        max_count = int(histogram.max()) if histogram.size else 0
        for severity_label, column_index in severity_index.items():
            for poam_type_label, row_index in type_index.items():
                value = int(histogram[column_index][row_index])
                text_color = "white" if max_count and value >= max(1, round(max_count * 0.45)) else "black"
                if value == 0:
                    text_color = "dimgray"
                axis.text(column_index + 0.5, row_index + 0.5, safe_text(value), ha="center", va="center", color=text_color, fontsize=8)
        axis.set_xticks(list(range(len(severity_labels) + 1)), minor=True)
        axis.set_yticks(list(range(len(row_labels) + 1)), minor=True)
        axis.grid(which="minor", color="white", linestyle="-", linewidth=1.2)
        axis.tick_params(which="minor", bottom=False, left=False)
        colorbar = figure.colorbar(histogram_image, ax=axis)
        colorbar.set_label("POAM Count")
        figure.tight_layout()

        image_buffer = BytesIO()
        figure.savefig(image_buffer, format="png", bbox_inches="tight")
        plt.close(figure)
        image_buffer.seek(0)
        return image_buffer

    type_risk_heatmap_image = build_raw_severity_histogram(
        report_data["raw_severity_histogram_points"],
        report_data["raw_severity_labels"],
        "POAM Raw Severity Totals by POAM Item Type 2D Histogram",
    )
    residual_risk_mitigations_type_heatmap_image = build_risk_histogram(
        report_data["residual_risk_mitigations_histogram_points"],
        "POAM Residual Risk Mitigations Totals by POAM Type 2D Histogram",
    )

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        title=REPORT_TITLE,
        author="OpenRMF Professional External API Scripts",
    )
    story = [
        Paragraph(REPORT_TITLE, styles["Title"]),
        Spacer(1, 24),
        Paragraph("POAM Overview", styles["Heading1"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
        Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
        Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
        Paragraph(f"Source Script: {SOURCE_SCRIPT_NAME}", styles["Normal"]),
        PageBreak(),
        Paragraph("POAM Status", styles["Heading1"]),
        Spacer(1, 12),
        Paragraph("Status Totals", styles["Heading2"]),
        Spacer(1, 8),
        status_table,
        Spacer(1, 12),
        Paragraph(f"Total POAM Records Counted: {report_data['poam_count']}", styles["Normal"]),
        Spacer(1, 24),
        Paragraph("Status Totals by POAM Type", styles["Heading2"]),
        Spacer(1, 8),
        type_status_table,
        PageBreak(),
    ]
    story.extend(
        [
            Paragraph("POAM Raw Severity Totals by POAM Item Type", styles["Heading1"]),
            Spacer(1, 12),
            type_risk_table,
            Spacer(1, 18),
            Paragraph("POAM Raw Severity Totals by POAM Item Type 2D Histogram", styles["Heading2"]),
            Spacer(1, 8),
        ]
    )
    if type_risk_heatmap_image:
        story.append(Image(type_risk_heatmap_image, width=500, height=240))
    else:
        story.append(Paragraph("POAM Raw Severity Totals by POAM Item Type 2D Histogram unavailable. Install matplotlib to render it.", styles["Normal"]))
    story.extend(
        [
            PageBreak(),
            Paragraph("POAM Residual Risk Mitigations Totals by POAM Type", styles["Heading1"]),
            Spacer(1, 12),
            residual_risk_mitigations_type_table,
            Spacer(1, 18),
            Paragraph("POAM Residual Risk Mitigations Totals by POAM Type 2D Histogram", styles["Heading2"]),
            Spacer(1, 8),
        ]
    )
    if residual_risk_mitigations_type_heatmap_image:
        story.append(Image(residual_risk_mitigations_type_heatmap_image, width=500, height=240))
    else:
        story.append(Paragraph("POAM Residual Risk Mitigations Totals by POAM Type 2D Histogram unavailable. Install matplotlib to render it.", styles["Normal"]))
    story.extend(
        [
            PageBreak(),
            Paragraph("Scheduled Completion by POAM Status and Type", styles["Heading1"]),
            Spacer(1, 12),
            Paragraph("Count of items by POAM status and POAM type that have a scheduled completion date.", styles["Normal"]),
            Spacer(1, 8),
            Paragraph("Ongoing cells highlighted red include items past today that are still Ongoing.", styles["Normal"]),
            Spacer(1, 12),
            scheduled_completion_type_status_table,
            Spacer(1, 24),
            Paragraph("Ongoing POAM Items with No Scheduled Completion Date", styles["Heading2"]),
            Spacer(1, 8),
            ongoing_no_scheduled_completion_table,
        ]
    )
    story.extend(
        [
            PageBreak(),
            Paragraph("False Positive by POAM Status and Type", styles["Heading1"]),
            Spacer(1, 12),
            Paragraph('Count of items marked true for "falsePositive" by POAM status and POAM type.', styles["Normal"]),
            Spacer(1, 12),
            false_positive_type_status_table,
        ]
    )
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
    status_totals = report_data["status_totals"]
    status_lines = [
        "POAM Status",
        "",
        "Status Totals",
        "",
        "Ongoing    Completed  Accepted",
        "---------  ---------  --------",
        f"{status_totals['Ongoing']:>9}  {status_totals['Completed']:>9}  {status_totals['Accepted']:>8}",
        "",
        f"Total POAM Records Counted: {report_data['poam_count']}",
        "",
        "Status Totals by POAM Type",
        "",
        "POAM Type           Ongoing  Completed  Accepted",
        "------------------  -------  ---------  --------",
    ]
    for row in report_data["type_status_rows"]:
        status_lines.append(
            f"{row['poam_type']:<18}  {row['ongoing']:>7}  {row['completed']:>9}  {row['accepted']:>8}"
        )
    raw_severity_headers = [severity or "Blank" for severity in report_data["raw_severity_labels"]]
    raw_severity_type_lines = [
        "POAM Raw Severity Totals by POAM Item Type",
        "",
        "POAM Item Type            " + "  ".join(f"{header[:12]:>12}" for header in raw_severity_headers),
        "------------------------  " + "  ".join(["------------" for _ in raw_severity_headers]),
    ]
    for row in report_data["raw_severity_type_rows"]:
        raw_severity_type_lines.append(
            f"{row['poam_type']:<24}  " + "  ".join(f"{row[severity_label]:>12}" for severity_label in report_data["raw_severity_labels"])
        )
    raw_severity_type_lines.extend(["", "POAM Raw Severity Totals by POAM Item Type 2D Histogram unavailable in fallback PDF output."])
    residual_risk_mitigations_type_lines = [
        "POAM Residual Risk Mitigations Totals by POAM Type",
        "",
        "POAM Type                  Very High  High  Moderate  Low  Very Low",
        "-------------------------  ---------  ----  --------  ---  --------",
    ]
    for row in report_data["type_residual_risk_mitigations_rows"]:
        residual_risk_mitigations_type_lines.append(
            f"{row['poam_type']:<25}  {row['very_high']:>9}  {row['high']:>4}  {row['moderate']:>8}  {row['low']:>3}  {row['very_low']:>8}"
        )
    residual_risk_mitigations_type_lines.extend(
        ["", "POAM Residual Risk Mitigations Totals by POAM Type 2D Histogram unavailable in fallback PDF output."]
    )
    scheduled_completion_lines = [
        "Scheduled Completion by POAM Status and Type",
        "",
        "Count of items by POAM status and POAM type that have a scheduled completion date.",
        "Ongoing counts marked with * include items past today that are still Ongoing.",
        "",
        "POAM Type           Ongoing  Completed  Accepted",
        "------------------  -------  ---------  --------",
    ]
    for row in report_data["scheduled_completion_type_status_rows"]:
        ongoing_value = row["ongoing"] + ("*" if int(row["past_due_ongoing"]) else "")
        scheduled_completion_lines.append(
            f"{row['poam_type']:<18}  {ongoing_value:>7}  {row['completed']:>9}  {row['accepted']:>8}"
        )
    scheduled_completion_lines.extend(
        [
            "",
            "Ongoing POAM Items with No Scheduled Completion Date",
            "",
            "POAM Type           Ongoing No Date",
            "------------------  ---------------",
        ]
    )
    for row in report_data["ongoing_no_scheduled_completion_rows"]:
        scheduled_completion_lines.append(
            f"{row['poam_type']:<18}  {row['ongoing_no_scheduled_completion']:>15}"
        )
    false_positive_lines = [
        "False Positive by POAM Status and Type",
        "",
        'Count of items marked true for "falsePositive" by POAM status and POAM type.',
        "",
        "POAM Type           Ongoing  Completed  Accepted",
        "------------------  -------  ---------  --------",
    ]
    for row in report_data["false_positive_type_status_rows"]:
        false_positive_lines.append(
            f"{row['poam_type']:<18}  {row['ongoing']:>7}  {row['completed']:>9}  {row['accepted']:>8}"
        )
    page_streams = [
        make_text_page(
            [
                REPORT_TITLE,
                "",
                "POAM Overview",
                "",
                f"Generated: {report_data['generated_at']}",
                f"System Key: {report_data['system_key']}",
                f"System Title: {report_data['system_title']}",
                f"Source Script: {SOURCE_SCRIPT_NAME}",
            ],
            font_size=14,
        ),
        make_text_page(
            status_lines
        ),
        make_text_page(raw_severity_type_lines),
        make_text_page(residual_risk_mitigations_type_lines),
        make_text_page(scheduled_completion_lines),
        make_text_page(false_positive_lines),
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


def write_pdf(output_path: Path, report_data: dict) -> str:
    if write_pdf_with_reportlab(output_path, report_data):
        return "reportlab"
    write_minimal_pdf(output_path, report_data)
    return "fallback"


if len(sys.argv) < REQUIRED_ARGUMENT_COUNT:
    print_usage()
    sys.exit(1)

system_key = sys.argv[4]
poam_output = call_poam_json_script(sys.argv[1:])
poamdata = parse_json_value_from_output(poam_output)
report_data = build_report_data(poamdata, system_key)
output_filename = f"OpenRMFPro-POAM-Overview-{safe_filename_value(report_data['system_key'])}.pdf"
output_path = Path(output_filename)
pdf_writer = write_pdf(output_path, report_data)

print(f"Created PDF: {output_path}")
if pdf_writer == "fallback":
    print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")

"""
Legacy JSON script content below is intentionally disabled after converting this file into a PDF generator.
#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional External API - Systempackage Poam
# API Path   : GET /systempackage/{systemKey}/poam
# Description: Retrieves data from the /systempackage/{systemKey}/poam endpoint. The response is parsed as JSON and printed with standard indentation.
#
# Required Parameters:
#   1) rootURL            - The base server URL. The script validates it, trims any trailing slash, and appends /api/external automatically.
#   2) applicationKey     - The application key appended to the request URL as the applicationKey query parameter.
#   3) authorizationToken - The bearer token sent as the Authorization request header.
#   4) systemKey          - Required path parameter.
#
# Optional Parameters:
#    - days (query), type: integer, default: 0
#    - devicename (query), type: string, default:
#
# Command Line Example:
#   python3 get_systempackage_by_systemkey_poam_json.py \
#       https://example.openrmfpro.local \
#       my-application-key \
#       my-authorization-token \
#       <systemKey> \
#       KEY=VALUE
# ============================================================

import json
import re
import sys
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit
import requests
from requests.structures import CaseInsensitiveDict

COMMON_DIR = Path(__file__).resolve().parent.parent / "common"
if str(COMMON_DIR) not in sys.path:
    sys.path.insert(0, str(COMMON_DIR))

from http_status_meanings import HTTP_STATUS_MEANINGS

PATH_TEMPLATE = '/systempackage/{systemKey}/poam'
HTTP_METHOD = 'GET'
REQUIRED_POSITIONAL_ARGUMENTS = [
    'systemKey',
]
PATH_PARAMETER_NAMES = [
    'systemKey',
]
REQUIRED_QUERY_PARAMETER_NAMES = []
OPTIONAL_QUERY_PARAMETER_NAMES = [
    'days',
    'devicename',
]
REQUIRED_BODY_PARAMETER_NAMES = []
OPTIONAL_BODY_PARAMETER_NAMES = []
BINARY_BODY_PARAMETER_NAMES = []
KNOWN_OPTIONAL_NAMES = [
    'days',
    'devicename',
]
FILE_EXTENSION_HINT = None
ACCEPT_HEADER = 'application/json'

# -------------------------------------------------------
# Validate the root URL and normalize it for external API calls
# -------------------------------------------------------
def normalize_root_url(root_url: str) -> str:
    candidate = root_url.rstrip("/")
    parsed = urlsplit(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(f"ERROR: rootURL must be a valid HTTP or HTTPS URL. Provided: {root_url}")
        sys.exit(1)
    if candidate.endswith("/api/external"):
        return candidate
    return f"{candidate}/api/external"

# -------------------------------------------------------
# Replace path parameters and append query parameters to the URL
# -------------------------------------------------------
def build_url(api_root: str, path_values: dict[str, str], query_values: dict[str, str]) -> str:
    rendered_path = PATH_TEMPLATE
    for name in PATH_PARAMETER_NAMES:
        rendered_path = rendered_path.replace("{" + name + "}", quote(str(path_values[name]), safe=""))
    query_string = urlencode(query_values)
    return f"{api_root}{rendered_path}?{query_string}" if query_string else f"{api_root}{rendered_path}"

# -------------------------------------------------------
# Parse KEY=VALUE optional arguments after the required positional args
# -------------------------------------------------------
def parse_optional_arguments(arguments: list[str]) -> dict[str, str]:
    parsed = {}
    for argument in arguments:
        if "=" not in argument:
            print(f"ERROR: Optional arguments must use KEY=VALUE format. Invalid value: {argument}")
            sys.exit(1)
        key, value = argument.split("=", 1)
        parsed[key] = value
    return parsed

# -------------------------------------------------------
# Format nested JSON values safely for table output
# -------------------------------------------------------
def stringify_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, sort_keys=True)
    return "" if value is None else str(value)

# -------------------------------------------------------
# Resolve an output file path for download endpoints
# -------------------------------------------------------
def determine_output_path(response, options: dict[str, str]) -> Path:
    if "outputFile" in options and options["outputFile"].strip():
        return Path(options["outputFile"]).expanduser()

    content_disposition = response.headers.get("Content-Disposition", "")
    filename_match = re.search(r'filename="?([^";]+)"?', content_disposition)
    if filename_match:
        return Path(filename_match.group(1))

    final_segment = [segment for segment in PATH_TEMPLATE.split("/") if segment and not segment.startswith("{")][-1]
    if "format" in options and options["format"].strip():
        extension = options["format"].strip().lstrip(".")
    elif FILE_EXTENSION_HINT:
        extension = FILE_EXTENSION_HINT.lstrip(".")
    else:
        extension = "bin"
    return Path(f"{final_segment}.{extension}")

# -------------------------------------------------------
# Validate required arguments and map them to API parameters
# -------------------------------------------------------
minimum_argument_count = 4 + 1
if len(sys.argv) < minimum_argument_count:
    print("ERROR: Missing required parameters.")
    print("Usage: python3 " + Path(__file__).name + " <rootURL> <applicationKey> <authorizationToken>" + (" " + " ".join(f"<{name}>" for name in REQUIRED_POSITIONAL_ARGUMENTS) if REQUIRED_POSITIONAL_ARGUMENTS else "") + (" [KEY=VALUE ...]" if KNOWN_OPTIONAL_NAMES or OPTIONAL_QUERY_PARAMETER_NAMES or OPTIONAL_BODY_PARAMETER_NAMES else ""))
    sys.exit(1)

root_url = sys.argv[1]
application_key = sys.argv[2]
authorization_token = sys.argv[3]
positional_values = sys.argv[4:4 + 1]
optional_values = sys.argv[4 + 1:]

api_root = normalize_root_url(root_url)

path_values = {}
required_query_values = {}
required_body_values = {}

cursor = 0
for name in PATH_PARAMETER_NAMES:
    path_values[name] = positional_values[cursor]
    cursor += 1
for name in REQUIRED_QUERY_PARAMETER_NAMES:
    required_query_values[name] = positional_values[cursor]
    cursor += 1
for name in REQUIRED_BODY_PARAMETER_NAMES:
    required_body_values[name] = positional_values[cursor]
    cursor += 1

optional_arguments = parse_optional_arguments(optional_values)
unknown_optional = sorted(set(optional_arguments) - set(KNOWN_OPTIONAL_NAMES) - set(OPTIONAL_QUERY_PARAMETER_NAMES) - set(OPTIONAL_BODY_PARAMETER_NAMES))
if unknown_optional:
    print("WARNING: Ignoring unrecognized optional parameters: " + ", ".join(unknown_optional))

query_values = {"applicationKey": application_key}
query_values.update(required_query_values)
for name in OPTIONAL_QUERY_PARAMETER_NAMES:
    if name in optional_arguments:
        query_values[name] = optional_arguments[name]

form_data = {}
form_data.update(required_body_values)
for name in OPTIONAL_BODY_PARAMETER_NAMES:
    if name in optional_arguments:
        form_data[name] = optional_arguments[name]

try:
    url = build_url(api_root, path_values, query_values)

    # -------------------------------------------------------
    # Build the Authorization header and any endpoint-specific headers
    # -------------------------------------------------------
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Bearer {authorization_token}"
    if ACCEPT_HEADER:
        headers["Accept"] = ACCEPT_HEADER

    request_kwargs = {"headers": headers}
    if form_data:
        request_kwargs["data"] = form_data

    # -------------------------------------------------------
    # Execute the HTTP request
    # -------------------------------------------------------
    print(f"Calling {HTTP_METHOD} {url} ...")
    response = requests.request(HTTP_METHOD, url, **request_kwargs)
except requests.exceptions.RequestException as exc:
    print(f"ERROR: The request failed before a response was received. Details: {exc}")
    sys.exit(1)

# -------------------------------------------------------
# Debug output for troubleshooting non-status responses
# -------------------------------------------------------
# print(f"Response Status Code: {response.status_code}")
# print(f"Response Text: {response.text}")

# -------------------------------------------------------
# Parse and print the response as formatted JSON
# -------------------------------------------------------
if 200 <= response.status_code < 300:
    try:
        print(json.dumps(response.json(), indent=2, sort_keys=False))
    except ValueError:
        print("ERROR: The endpoint did not return valid JSON.")
        print(response.text)
        sys.exit(1)
else:
    meaning = HTTP_STATUS_MEANINGS.get(response.status_code, "Unexpected status code returned by the server.")
    print(f"ERROR: HTTP {response.status_code} - {meaning}")
    print(response.text)
    sys.exit(1)
"""