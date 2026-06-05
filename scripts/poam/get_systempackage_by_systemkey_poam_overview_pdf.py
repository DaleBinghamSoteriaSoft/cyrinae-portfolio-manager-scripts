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
STATUS_COLUMNS = ["Ongoing", "Completed", "Accepted"]
RISK_COLUMNS = ["Very High", "High", "Moderate", "Low", "Very Low"]
POAM_TYPE_DEFINITIONS = [
    ("artifactId", "Checklist Vulnerability"),
    ("patchScanId", "Patch Vulnerability"),
    ("statementId", "Compliance Statement"),
    ("inheritedControlId", "Inherited Controls"),
    ("vulnScanId", "Technology Vulnerability"),
]
MANUAL_POAM_TYPE = "Manually Added / Deleted Items"
RAW_SEVERITY_ITEM_TYPE_DEFINITIONS = [
    ("checklist", "Checklist", "artifactId"),
    ("patch_scan", "Patch Scan", "patchScanId"),
    ("other_technology_scan", "Other Technology Scan", "vulnScanId"),
    ("compliance_statement", "Compliance Statement", "statementId"),
    ("inherited_control", "Inherited Control", "inheritedControlId"),
]
RAW_SEVERITY_MANUAL_TYPE_KEY = "manual_deleted"
RAW_SEVERITY_MANUAL_TYPE_LABEL = "Manual/Deleted"
RAW_SEVERITY_FIELD_KEYS = ["rawSeverity", "rawSeverityString", "rawSeverityValue"]
RAW_SEVERITY_BLANK_LABEL = "Blank"
RAW_SEVERITY_COLUMNS = ["Critical", "High", "Medium", "Low"]
REPORT_SECTIONS = [
    {"title": "POAM Status", "anchor": "poam-status", "page_number": "2"},
    {"title": "POAM Raw Severity by POAM Item Type", "anchor": "poam-raw-severity-by-poam-item-type", "page_number": "3"},
    {"title": "Total by POAM Residual Risk Mitigations by POAM Type", "anchor": "poam-residual-risk-mitigations-by-type", "page_number": "4"},
    {"title": "Scheduled Completion by POAM Status and Type", "anchor": "scheduled-completion-by-poam-status-and-type", "page_number": "5"},
    {"title": "False Positive by POAM Status and Type", "anchor": "false-positive-by-poam-status-and-type", "page_number": "6"},
]


def build_table_of_contents_rows() -> list[dict[str, str]]:
    return [
        {"title": section["title"], "anchor": section["anchor"], "page_number": section["page_number"]}
        for section in REPORT_SECTIONS
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
    raise ValueError("Could not find JSON in the POAM JSON script output.")


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def safe_filename_value(value: str) -> str:
    safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe_value.strip(".-") or "unknown-system"


def report_title_for_system(system_key: str, system_title: str) -> str:
    system_title_text = safe_text(system_title).strip()
    if system_title_text:
        return f"{system_title_text} POAM Overview"

    system_key_text = safe_text(system_key).strip()
    normalized_system_key = re.sub(r"[^a-z0-9]+", "", system_key_text.lower())
    if normalized_system_key == "soteriainfra":
        return "Soteria Infrastructure POAM Overview"
    return f"{system_key_text or 'Unknown System'} POAM Overview"


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


def poam_type(record: dict) -> str:
    for key, label in POAM_TYPE_DEFINITIONS:
        if has_poam_type_value(record, key):
            return label
    return MANUAL_POAM_TYPE


def build_type_status_rows(records: list[dict]) -> list[dict[str, str]]:
    grouped_totals = {
        label: {status: 0 for status in STATUS_COLUMNS}
        for _, label in POAM_TYPE_DEFINITIONS
    }
    grouped_totals[MANUAL_POAM_TYPE] = {status: 0 for status in STATUS_COLUMNS}
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
        for label in [*[label for _, label in POAM_TYPE_DEFINITIONS], MANUAL_POAM_TYPE]
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
    poam_type_labels = [*[label for _, label in POAM_TYPE_DEFINITIONS], MANUAL_POAM_TYPE]
    grouped_totals = {
        label: {status: 0 for status in STATUS_COLUMNS}
        for label in poam_type_labels
    }
    past_due_ongoing_totals = {label: 0 for label in poam_type_labels}
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
        for label in poam_type_labels
    ]


def build_ongoing_no_scheduled_completion_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels = [*[label for _, label in POAM_TYPE_DEFINITIONS], MANUAL_POAM_TYPE]
    grouped_totals = {label: 0 for label in poam_type_labels}
    for record in records:
        if poam_status(record) == "Ongoing" and not has_scheduled_completion_date(record):
            grouped_totals[poam_type(record)] += 1

    return [
        {
            "poam_type": label,
            "ongoing_no_scheduled_completion": safe_text(grouped_totals[label]),
        }
        for label in poam_type_labels
    ]


def bool_value(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    value_text = safe_text(value).strip().lower()
    return value_text in {"true", "yes", "y", "1"}


def build_false_positive_type_status_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels = [*[label for _, label in POAM_TYPE_DEFINITIONS], MANUAL_POAM_TYPE]
    grouped_totals = {
        label: {status: 0 for status in STATUS_COLUMNS}
        for label in poam_type_labels
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
        for label in poam_type_labels
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


def raw_severity_value(record: dict) -> str:
    return first_value(record, RAW_SEVERITY_FIELD_KEYS).strip()


def raw_severity_color_key(value: str) -> str:
    value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
    if value_text in {"", RAW_SEVERITY_BLANK_LABEL.lower(), "none", "null"}:
        return "blank"
    if value_text in {"critical", "very high", "veryhigh", "cat i", "cat 1", "i", "4", "5"}:
        return "critical"
    if value_text in {"high", "cat ii", "cat 2", "ii", "3"}:
        return "high"
    if value_text in {"medium", "moderate", "cat iii", "cat 3", "iii", "2"}:
        return "medium"
    if value_text in {"low", "1"}:
        return "low"
    return "blank"


def raw_severity_column_key(value: str) -> str:
    color_key = raw_severity_color_key(value)
    if color_key == "critical":
        return "critical"
    if color_key == "high":
        return "high"
    if color_key == "medium":
        return "medium"
    if color_key == "low":
        return "low"
    return ""


def raw_severity_item_type_key(record: dict) -> str:
    for type_key, _, field_key in RAW_SEVERITY_ITEM_TYPE_DEFINITIONS:
        if has_poam_type_value(record, field_key):
            return type_key
    return RAW_SEVERITY_MANUAL_TYPE_KEY


def raw_severity_item_type_columns() -> list[tuple[str, str]]:
    return [
        *[(type_key, label) for type_key, label, _ in RAW_SEVERITY_ITEM_TYPE_DEFINITIONS],
        (RAW_SEVERITY_MANUAL_TYPE_KEY, RAW_SEVERITY_MANUAL_TYPE_LABEL),
    ]


def build_raw_severity_item_type_rows(records: list[dict]) -> list[dict[str, str]]:
    item_type_columns = raw_severity_item_type_columns()
    grouped_totals = {
        type_key: {severity.lower(): 0 for severity in RAW_SEVERITY_COLUMNS}
        for type_key, _ in item_type_columns
    }

    for record in records:
        severity_key = raw_severity_column_key(raw_severity_value(record))
        if severity_key:
            grouped_totals[raw_severity_item_type_key(record)][severity_key] += 1

    return [
        {
            "poam_item_type": label,
            "critical": safe_text(grouped_totals[type_key]["critical"]),
            "high": safe_text(grouped_totals[type_key]["high"]),
            "medium": safe_text(grouped_totals[type_key]["medium"]),
            "low": safe_text(grouped_totals[type_key]["low"]),
        }
        for type_key, label in item_type_columns
    ]


def poam_residual_risk_mitigations_risk(record: dict) -> str:
    residual_risk = record.get("residualRiskLevelMitigations")
    if safe_text(residual_risk).strip().lower() in {"", "none", "null"}:
        return ""
    return normalize_risk_value(residual_risk)


def build_type_residual_risk_mitigations_rows(records: list[dict]) -> list[dict[str, str]]:
    poam_type_labels = [*[label for _, label in POAM_TYPE_DEFINITIONS], MANUAL_POAM_TYPE]
    grouped_totals = {
        label: {risk: 0 for risk in RISK_COLUMNS}
        for label in poam_type_labels
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
        for label in poam_type_labels
    ]


def build_report_data(poamdata, system_key: str) -> dict:
    records = poam_records(poamdata)
    system_title = ""
    for record in records:
        system_title = first_value(record, ["systemTitle", "title", "systemName"])
        if system_title:
            break

    return {
        "system_key": system_key,
        "report_title": report_title_for_system(system_key, system_title),
        "system_title": system_title or "Unknown",
        "status_totals": build_status_totals(records),
        "type_status_rows": build_type_status_rows(records),
        "scheduled_completion_type_status_rows": build_scheduled_completion_type_status_rows(records),
        "ongoing_no_scheduled_completion_rows": build_ongoing_no_scheduled_completion_rows(records),
        "false_positive_type_status_rows": build_false_positive_type_status_rows(records),
        "raw_severity_item_type_rows": build_raw_severity_item_type_rows(records),
        "type_residual_risk_mitigations_rows": build_type_residual_risk_mitigations_rows(records),
        "table_of_contents_rows": build_table_of_contents_rows(),
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

    class SectionPageNumberDocTemplate(SimpleDocTemplate):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.section_page_numbers: dict[str, int] = {}

        def afterFlowable(self, flowable) -> None:
            anchor = getattr(flowable, "_toc_anchor", None)
            if anchor and anchor not in self.section_page_numbers:
                self.section_page_numbers[anchor] = self.page

    styles = getSampleStyleSheet()
    table_header_style = styles["BodyText"].clone("CenteredTableHeader")
    table_header_style.alignment = 1
    table_header_style.fontName = "Helvetica-Bold"
    contents_link_style = styles["BodyText"].clone("ContentsLink")
    contents_link_style.fontSize = 9
    contents_link_style.leading = 11
    contents_link_style.textColor = colors.blue
    status_column_backgrounds = [colors.lightblue, colors.lightgreen, colors.lightgrey]
    risk_column_backgrounds = [colors.red, colors.salmon, colors.white, colors.yellow, colors.lightgreen]

    def anchored_heading(title: str, anchor: str):
        paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', styles["Heading1"])
        paragraph._toc_anchor = anchor
        return paragraph

    def contents_link(title: str, anchor: str):
        return Paragraph(f'<a href="#{html.escape(anchor, quote=True)}" color="blue">{html.escape(title)}</a>', contents_link_style)

    def build_contents_table():
        contents_table_rows = [[Paragraph("Page Title", table_header_style), Paragraph("Page Number", table_header_style)]]
        contents_table_rows.extend(
            [
                contents_link(row["title"], row["anchor"]),
                row["page_number"],
            ]
            for row in report_data["table_of_contents_rows"]
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

    raw_severity_item_type_table = Table(
        [
            ["POAM Item Type", *[Paragraph(severity, table_header_style) for severity in RAW_SEVERITY_COLUMNS]],
            *[
                [row["poam_item_type"], row["critical"], row["high"], row["medium"], row["low"]]
                for row in report_data["raw_severity_item_type_rows"]
            ],
        ],
        hAlign="LEFT",
        colWidths=[170, 82, 82, 82, 82],
    )
    raw_severity_backgrounds = {
        "critical": colors.darkred,
        "high": colors.red,
        "medium": colors.orange,
        "low": colors.yellow,
        "blank": colors.white,
    }
    raw_severity_item_type_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
    for column_index, severity in enumerate(RAW_SEVERITY_COLUMNS, start=1):
        color_key = raw_severity_column_key(severity)
        raw_severity_item_type_styles.append(
            ("BACKGROUND", (column_index, 1), (column_index, -1), raw_severity_backgrounds[color_key])
        )
        if color_key in {"critical", "high"}:
            raw_severity_item_type_styles.append(("TEXTCOLOR", (column_index, 1), (column_index, -1), colors.white))
    raw_severity_item_type_table.setStyle(TableStyle(raw_severity_item_type_styles))

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

    def build_risk_2d_histogram(rows: list[dict[str, str]], label_key: str, title: str) -> BytesIO | None:
        try:
            import matplotlib  # pyright: ignore[reportMissingModuleSource]

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt  # pyright: ignore[reportMissingModuleSource]
        except ImportError:
            return None
        if not rows:
            return None

        row_labels = [row[label_key] for row in rows]
        column_labels = RISK_COLUMNS
        matrix = [
            [
                int(row["very_high"]),
                int(row["high"]),
                int(row["moderate"]),
                int(row["low"]),
                int(row["very_low"]),
            ]
            for row in rows
        ]
        max_value = max([value for row_values in matrix for value in row_values] or [0])
        x_edges = list(range(len(column_labels) + 1))
        y_edges = list(range(len(row_labels) + 1))

        figure_height = max(3.0, 0.45 * len(row_labels) + 1.6)
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
        axis.set_xlabel("residualRiskLevelMitigations")
        axis.set_ylabel("POAM Item Type")
        axis.set_title(title)
        axis.invert_yaxis()
        for row_index, row_values in enumerate(matrix):
            for column_index, value in enumerate(row_values):
                text_color = "white" if max_value and value > (max_value / 2) else "black"
                axis.text(column_index + 0.5, row_index + 0.5, safe_text(value), ha="center", va="center", color=text_color, fontsize=8)
        colorbar = figure.colorbar(histogram, ax=axis, pad=0.02)
        colorbar.set_label("POAM Count")
        figure.tight_layout()

        image_buffer = BytesIO()
        figure.savefig(image_buffer, format="png", bbox_inches="tight")
        plt.close(figure)
        image_buffer.seek(0)
        return image_buffer

    def build_raw_severity_item_type_heatmap(rows: list[dict[str, str]]) -> BytesIO | None:
        try:
            import matplotlib  # pyright: ignore[reportMissingModuleSource]

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt  # pyright: ignore[reportMissingModuleSource]
        except ImportError:
            return None
        if not rows:
            return None

        row_labels = [row["poam_item_type"] for row in rows]
        column_labels = RAW_SEVERITY_COLUMNS
        matrix = [[int(row[severity.lower()]) for severity in RAW_SEVERITY_COLUMNS] for row in rows]
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
        axis.set_xlabel("Raw Severity")
        axis.set_ylabel("POAM Item Type")
        axis.set_title("POAM Raw Severity by POAM Item Type 2D Histogram")
        axis.invert_yaxis()
        for row_index, row_values in enumerate(matrix):
            for column_index, value in enumerate(row_values):
                text_color = "white" if max_value and value > (max_value / 2) else "black"
                axis.text(column_index + 0.5, row_index + 0.5, safe_text(value), ha="center", va="center", color=text_color, fontsize=8)
        colorbar = figure.colorbar(histogram, ax=axis, pad=0.02)
        colorbar.set_label("POAM Count")
        figure.tight_layout()

        image_buffer = BytesIO()
        figure.savefig(image_buffer, format="png", bbox_inches="tight")
        plt.close(figure)
        image_buffer.seek(0)
        return image_buffer

    raw_severity_item_type_heatmap_image = build_raw_severity_item_type_heatmap(report_data["raw_severity_item_type_rows"])
    residual_risk_mitigations_type_heatmap_image = build_risk_2d_histogram(
        report_data["type_residual_risk_mitigations_rows"],
        "poam_type",
        "POAM Residual Risk Mitigations Totals by POAM Type 2D Histogram",
    )

    document_options = {
        "pagesize": letter,
        "title": report_data["report_title"],
        "author": "OpenRMF Professional External API Scripts",
    }
    contents_table = build_contents_table()
    story = [
        Paragraph(report_data["report_title"], styles["Title"]),
        Spacer(1, 18),
        Paragraph(f"Date Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
        Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
        Paragraph(f"System Title: {html.escape(report_data['system_title'])}", styles["Normal"]),
        Spacer(1, 18),
        Paragraph("Table of Contents", styles["Heading2"]),
        Spacer(1, 8),
        contents_table,
        PageBreak(),
        anchored_heading("POAM Status", "poam-status"),
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
    ]
    story.extend(
        [
            PageBreak(),
            anchored_heading("POAM Raw Severity by POAM Item Type", "poam-raw-severity-by-poam-item-type"),
            Spacer(1, 12),
            raw_severity_item_type_table,
            Spacer(1, 18),
            Paragraph("POAM Raw Severity by POAM Item Type 2D Histogram", styles["Heading2"]),
            Spacer(1, 8),
        ]
    )
    if raw_severity_item_type_heatmap_image:
        story.append(Image(raw_severity_item_type_heatmap_image, width=500, height=240))
    else:
        story.append(Paragraph("POAM Raw Severity by POAM Item Type 2D Histogram unavailable. Install matplotlib to render it.", styles["Normal"]))
    story.extend(
        [
            PageBreak(),
            anchored_heading("Total by POAM Residual Risk Mitigations by POAM Type", "poam-residual-risk-mitigations-by-type"),
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
            anchored_heading("Scheduled Completion by POAM Status and Type", "scheduled-completion-by-poam-status-and-type"),
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
            anchored_heading("False Positive by POAM Status and Type", "false-positive-by-poam-status-and-type"),
            Spacer(1, 12),
            Paragraph('Count of items marked true for "falsePositive" by POAM status and POAM type.', styles["Normal"]),
            Spacer(1, 12),
            false_positive_type_status_table,
        ]
    )
    measurement_document = SectionPageNumberDocTemplate(BytesIO(), **document_options)
    measurement_document.build(list(story))
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
    contents_lines = ["Table of Contents", "Page Title                                      Page Number", "--------------------------------------------  -----------"]
    contents_lines.extend([f"{row['title']:<44}  {row['page_number']:>11}" for row in report_data["table_of_contents_rows"]])
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
    raw_severity_type_lines = [
        "POAM Raw Severity by POAM Item Type",
        "",
        "POAM Item Type         Critical  High  Medium  Low",
        "---------------------  --------  ----  ------  ---",
    ]
    for row in report_data["raw_severity_item_type_rows"]:
        raw_severity_type_lines.append(
            f"{row['poam_item_type']:<21}  {row['critical']:>8}  {row['high']:>4}  {row['medium']:>6}  {row['low']:>3}"
        )
    raw_severity_type_lines.extend(["", "POAM Raw Severity by POAM Item Type 2D Histogram unavailable in fallback PDF output."])

    residual_risk_mitigations_type_lines = [
        "Total by POAM Residual Risk Mitigations by POAM Type",
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
                report_data["report_title"],
                "",
                f"Date Generated: {report_data['generated_at']}",
                f"System Key: {report_data['system_key']}",
                f"System Title: {report_data['system_title']}",
                "",
                *contents_lines,
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