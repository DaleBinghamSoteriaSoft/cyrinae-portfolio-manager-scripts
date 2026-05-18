#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional External API - Systempackage POAM Visual PDF
# API Path   : GET /systempackage/{systemKey}/poam
# Description: Calls get_systempackage_by_systemkey_poam_json.py and creates a PDF visual report with Ongoing severity counts and POAM item lists by status.
# ============================================================

import html
import json
import math
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SOURCE_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
REPORT_TITLE = "OpenRMF Professional POAM Visual"
STATUS_COLUMNS = ["Ongoing", "Completed", "Accepted"]
SEVERITY_COLUMNS = ["Critical", "High", "Medium", "Low"]
POAM_TYPE_DEFINITIONS = [
    ("patchScanId", "Patch"),
    ("artifactId", "Checklist"),
    ("vulnScanId", "Other Technology"),
    ("statementId", "Statement"),
]
MANUAL_POAM_TYPE = "Manual/Deleted"
POAM_TYPE_DISPLAY_ORDER = ["Checklist", "Patch", "Other Technology", "Statement", MANUAL_POAM_TYPE]
SOURCE_TYPE_COLUMNS = ["Checklist", "Patch", "Statement", "Inherited", "Other Tech", "Manual"]
SOURCE_TYPE_DEFINITIONS = [
    ("artifactId", "Checklist"),
    ("patchScanId", "Patch"),
    ("statementId", "Statement"),
    ("inheritedControlId", "Inherited"),
    ("vulnScanId", "Other Tech"),
]


def get_project_python_executable() -> str:
    project_python = Path(__file__).resolve().parents[1] / ".env" / "bin" / "python"
    return str(project_python) if project_python.exists() else sys.executable


def print_usage() -> None:
    print("ERROR: Missing required parameters.")
    print(
        "Usage from the scripts folder: python3 poam/"
        + Path(__file__).name
        + " <rootURL> <applicationKey> <authorizationToken> <systemKey> [KEY=VALUE ...]"
    )


def call_poam_json_script(arguments: list[str]) -> str:
    source_script = Path(__file__).resolve().parent / SOURCE_SCRIPT_NAME
    result = subprocess.run([get_project_python_executable(), str(source_script), *arguments], capture_output=True, text=True)
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
            return parsed
        except json.JSONDecodeError:
            continue
    print("ERROR: Could not find JSON in the POAM JSON script output.")
    print(output)
    sys.exit(1)


def safe_text(value) -> str:
    return "" if value is None else str(value)


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
    return bool(
        {
            "poamItemId",
            "poamLinkedId",
            "controlVulnerabilityDescription",
            "securityControlNumber",
            "status",
            "statusString",
            "poamStatus",
        }.intersection(value.keys())
    )


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


def poam_records(poamdata) -> list[dict]:
    return find_record_list(poamdata, ["records", "items", "data", "results", "poam", "poams", "poamItems", "poamRecords"])


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
        ["status", "statusString", "poamStatus", "poamStatusString", "poamStatusName", "workflowStatus", "state"],
    )
    if not status:
        status = first_nested_value(record, [["status", "name"], ["poamStatus", "name"], ["workflow", "status"]])
    return normalize_poam_status(status)


def normalize_severity_value(value: str) -> str:
    value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
    if value_text in {"critical", "very high", "veryhigh", "cat i", "cat 1", "i", "4", "5"}:
        return "Critical"
    if value_text in {"high", "cat ii", "cat 2", "ii", "3"}:
        return "High"
    if value_text in {"medium", "moderate", "cat iii", "cat 3", "iii", "2"}:
        return "Medium"
    if value_text in {"low", "very low", "verylow", "1"}:
        return "Low"
    return ""


def bool_value(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return safe_text(value).strip().lower() in {"true", "yes", "y", "1"}


def poam_severity(record: dict) -> str:
    severity = first_value(
        record,
        [
            "rawSeverity",
            "rawSeverityString",
            "rawSeverityValue",
            "severity",
            "severityString",
            "severityName",
            "risk",
            "riskLevel",
            "residualRiskLevel",
        ],
    )
    if not severity:
        severity = first_nested_value(record, [["severity", "name"], ["risk", "name"], ["riskLevel", "name"]])
    return normalize_severity_value(severity) or "Unspecified"


def poam_type(record: dict) -> str:
    for key, label in POAM_TYPE_DEFINITIONS:
        if safe_text(record.get(key)).strip().lower() not in {"", "none", "null"}:
            return label
    return MANUAL_POAM_TYPE


def poam_source_type(record: dict) -> str:
    if bool_value(record.get("manuallyAdded")):
        return "Manual"
    for key, label in SOURCE_TYPE_DEFINITIONS:
        if safe_text(record.get(key)).strip().lower() not in {"", "none", "null"}:
            return label
    return "Manual"


def poam_identifier(record: dict) -> str:
    return first_value(record, ["poamItemId", "poamLinkedId", "poamId", "id", "vulnerabilityId", "vulnId", "pluginId", "cci"]) or "N/A"


def poam_item_id(record: dict) -> str:
    return first_value(record, ["poamItemId"]) or "N/A"


def poam_control(record: dict) -> str:
    return first_value(record, ["securityControlNumber", "controlNumber", "control", "controlAcronym", "controlId", "controlName"]) or "N/A"


def poam_security_check(record: dict) -> str:
    return first_value(record, ["securityChecks"]) or "N/A"


def poam_device(record: dict) -> str:
    return first_value(record, ["devicesAffected", "deviceName", "devicename", "hostName", "hostname", "assetName", "asset", "systemName"]) or "N/A"


def poam_source(record: dict) -> str:
    return first_value(record, ["sourceIdControlVulnerability", "source", "sourceId", "sourceName"]) or "N/A"


def poam_scheduled_completion(record: dict) -> str:
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


def is_overdue_completion(record: dict) -> bool:
    scheduled_date = parse_date_value(poam_scheduled_completion(record))
    return scheduled_date is not None and scheduled_date < datetime.now().astimezone().date() and poam_status(record) == "Ongoing"


def overdue_days(record: dict) -> str:
    scheduled_date = parse_date_value(poam_scheduled_completion(record))
    if scheduled_date is None:
        return "N/A"
    return safe_text((datetime.now().astimezone().date() - scheduled_date).days)


def poam_description(record: dict) -> str:
    return first_value(
        record,
        ["controlVulnerabilityDescription", "vulnerabilityDescription", "description", "weaknessDescription", "findingDetails", "title", "name"],
    ) or "No description provided."


def compact_text(value: str, max_length: int = 120) -> str:
    value_text = re.sub(r"\s+", " ", safe_text(value)).strip()
    return value_text if len(value_text) <= max_length else value_text[: max_length - 1].rstrip() + "…"


def build_status_totals(records: list[dict]) -> dict[str, int]:
    totals = {status: 0 for status in STATUS_COLUMNS}
    for record in records:
        status = poam_status(record)
        if status in totals:
            totals[status] += 1
    return totals


def build_ongoing_severity_totals(records: list[dict]) -> dict[str, int]:
    totals = {severity: 0 for severity in SEVERITY_COLUMNS}
    for record in records:
        if poam_status(record) == "Ongoing":
            severity = poam_severity(record)
            if severity in totals:
                totals[severity] += 1
    return totals


def build_item(record: dict) -> dict[str, str]:
    return {
        "id": compact_text(poam_identifier(record), 40),
        "poam_item_id": compact_text(poam_item_id(record), 40),
        "status": poam_status(record),
        "severity": poam_severity(record),
        "control": compact_text(poam_control(record), 45),
        "security_check": compact_text(poam_security_check(record), 70),
        "device": compact_text(poam_device(record), 70),
        "source": compact_text(poam_source(record), 120),
        "scheduled_completion": compact_text(poam_scheduled_completion(record) or "N/A", 45),
        "type": compact_text(poam_type(record), 60),
        "source_type": compact_text(poam_source_type(record), 45),
        "days": overdue_days(record),
        "description": compact_text(poam_description(record), 220),
    }


def build_items_by_status(records: list[dict]) -> dict[str, list[dict[str, str]]]:
    items_by_status = {status: [] for status in STATUS_COLUMNS}
    for record in records:
        status = poam_status(record)
        if status in items_by_status:
            items_by_status[status].append(build_item(record))
    return items_by_status

def build_all_items(records: list[dict]) -> list[dict[str, str]]:
    return [build_item(record) for record in records]


def build_overdue_completion_items(records: list[dict]) -> list[dict[str, str]]:
    overdue_records = [record for record in records if is_overdue_completion(record)]
    overdue_records.sort(key=lambda record: parse_date_value(poam_scheduled_completion(record)))
    return [build_item(record) for record in overdue_records]


def build_type_totals_by_status(records: list[dict]) -> dict[str, dict[str, int]]:
    totals = {status: {label: 0 for label in POAM_TYPE_DISPLAY_ORDER} for status in STATUS_COLUMNS}
    for record in records:
        status = poam_status(record)
        if status in totals:
            totals[status][poam_type(record)] += 1
    return totals


def build_source_type_totals(records: list[dict]) -> dict[str, int]:
    totals = {source_type: 0 for source_type in SOURCE_TYPE_COLUMNS}
    for record in records:
        totals[poam_source_type(record)] += 1
    return totals


def build_report_data(poamdata, system_key: str) -> dict:
    records = poam_records(poamdata)
    system_title = ""
    for record in records:
        system_title = first_value(record, ["systemTitle", "title", "systemName"])
        if system_title:
            break
    return {
        "system_key": system_key,
        "system_title": system_title or "Unknown",
        "status_totals": build_status_totals(records),
        "ongoing_severity_totals": build_ongoing_severity_totals(records),
        "type_totals_by_status": build_type_totals_by_status(records),
        "source_type_totals": build_source_type_totals(records),
        "all_items": build_all_items(records),
        "overdue_completion_items": build_overdue_completion_items(records),
        "items_by_status": build_items_by_status(records),
        "poam_count": len(records),
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
    }


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
    try:
        from reportlab.graphics.charts.piecharts import Pie  # pyright: ignore[reportMissingModuleSource]
        from reportlab.graphics.shapes import Drawing, Rect, String  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.enums import TA_CENTER  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.pagesizes import landscape, letter  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
        from reportlab.platypus import LongTable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
    except ImportError:
        return False

    styles = getSampleStyleSheet()
    centered_style = ParagraphStyle("Centered", parent=styles["BodyText"], alignment=TA_CENTER)
    table_cell_style = ParagraphStyle("TableCell", parent=styles["BodyText"], fontSize=7, leading=8)
    table_header_style = ParagraphStyle("TableHeader", parent=styles["BodyText"], alignment=TA_CENTER, fontName="Helvetica-Bold", fontSize=7, leading=8)
    tile_style = ParagraphStyle("Tile", parent=styles["BodyText"], alignment=TA_CENTER, fontName="Helvetica-Bold", fontSize=12, leading=16)
    severity_colors = {
        "Critical": colors.HexColor("#800000"),
        "High": colors.HexColor("#C00000"),
        "Medium": colors.HexColor("#ED7D31"),
        "Low": colors.HexColor("#FFD966"),
    }
    status_colors = {
        "Ongoing": colors.HexColor("#BDD7EE"),
        "Completed": colors.HexColor("#C6E0B4"),
        "Accepted": colors.HexColor("#D9D9D9"),
    }
    type_colors = {
        "Checklist": colors.HexColor("#5B9BD5"),
        "Patch": colors.HexColor("#C0504D"),
        "Other Technology": colors.HexColor("#ED7D31"),
        "Statement": colors.HexColor("#FFD966"),
        "Manual/Deleted": colors.HexColor("#7030A0"),
    }
    source_type_colors = {
        "Checklist": colors.HexColor("#548235"),
        "Patch": colors.HexColor("#548235"),
        "Statement": colors.HexColor("#548235"),
        "Inherited": colors.HexColor("#1F4E79"),
        "Other Tech": colors.HexColor("#1F4E79"),
        "Manual": colors.HexColor("#1F4E79"),
    }
    pie_label_text_colors = {
        "Checklist": colors.white,
        "Patch": colors.white,
        "Other Technology": colors.black,
        "Statement": colors.black,
        "Manual/Deleted": colors.black,
    }

    def build_status_boxes() -> Table:
        totals = report_data["status_totals"]
        table = Table(
            [
                [
                    Paragraph(
                        f"<font size='22'>{safe_text(totals[status])}</font><br/>{html.escape(status)} Items",
                        tile_style,
                    )
                    for status in STATUS_COLUMNS
                ]
            ],
            hAlign="CENTER",
            colWidths=[125, 125, 125],
            rowHeights=[85],
        )
        table.setStyle(
            TableStyle(
                [
                    *[("BACKGROUND", (column_index, 0), (column_index, 0), status_colors[status]) for column_index, status in enumerate(STATUS_COLUMNS)],
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.grey),
                    ("INNERGRID", (0, 0), (-1, -1), 8, colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ]
            )
        )
        return table

    def build_severity_boxes() -> Table:
        totals = report_data["ongoing_severity_totals"]
        table = Table(
            [
                [
                    Paragraph(
                        f"<font size='22'>{safe_text(totals[severity])}</font><br/>{html.escape(severity)} Ongoing",
                        tile_style,
                    )
                    for severity in SEVERITY_COLUMNS
                ]
            ],
            hAlign="CENTER",
            colWidths=[125, 125, 125, 125],
            rowHeights=[85],
        )
        table.setStyle(
            TableStyle(
                [
                    *[("BACKGROUND", (column_index, 0), (column_index, 0), severity_colors[severity]) for column_index, severity in enumerate(SEVERITY_COLUMNS)],
                    ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.grey),
                    ("INNERGRID", (0, 0), (-1, -1), 8, colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ]
            )
        )
        return table

    def build_type_pie_chart(status: str) -> Drawing:
        totals = report_data["type_totals_by_status"][status]
        nonzero_totals = [(label, count) for label, count in totals.items() if count]
        type_labels = POAM_TYPE_DISPLAY_ORDER

        drawing = Drawing(230, 210)
        drawing.add(String(50, 195, f"{status} by Type", fontName="Helvetica-Bold", fontSize=11))

        if nonzero_totals:
            labels = [label for label, _ in nonzero_totals]
            values = [count for _, count in nonzero_totals]
            total = sum(values)
            pie_x = 45
            pie_y = 62
            pie_size = 125

            pie = Pie()
            pie.x = pie_x
            pie.y = pie_y
            pie.width = pie_size
            pie.height = pie_size
            pie.data = values
            pie.labels = ["" for _ in values]
            pie.slices.strokeWidth = 0.5
            for index, label in enumerate(labels):
                pie.slices[index].fillColor = type_colors.get(label, colors.lightgrey)
            drawing.add(pie)

            current_angle = 90.0
            center_x = pie_x + (pie_size / 2)
            center_y = pie_y + (pie_size / 2)
            label_radius = pie_size * 0.28
            for label, value in zip(labels, values):
                sweep_angle = 360.0 * value / total if total else 0
                middle_angle = current_angle - (sweep_angle / 2)
                radians = math.radians(middle_angle)
                label_x = center_x + (math.cos(radians) * label_radius) - 4
                label_y = center_y + (math.sin(radians) * label_radius) - 4
                drawing.add(
                    String(
                        label_x,
                        label_y,
                        safe_text(value),
                        fillColor=pie_label_text_colors.get(label, colors.black),
                        fontName="Helvetica-Bold",
                        fontSize=10,
                    )
                )
                current_angle -= sweep_angle

        legend_y = 48
        for index, label in enumerate(type_labels):
            current_y = legend_y - (index * 12)
            drawing.add(Rect(30, current_y - 1, 7, 7, fillColor=type_colors.get(label, colors.lightgrey), strokeColor=None))
            drawing.add(String(42, current_y, label, fontSize=7))
        return drawing

    def build_type_pie_charts() -> Table:
        table = Table(
            [[build_type_pie_chart(status) for status in STATUS_COLUMNS]],
            hAlign="CENTER",
            colWidths=[230, 230, 230],
        )
        table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return table

    def build_source_type_boxes() -> Table:
        totals = report_data["source_type_totals"]
        table = Table(
            [
                [
                    Paragraph(
                        f"<font size='20'>{safe_text(totals[source_type])}</font><br/>{html.escape(source_type)}",
                        tile_style,
                    )
                ]
                for source_type in SOURCE_TYPE_COLUMNS
            ],
            hAlign="LEFT",
            colWidths=[155],
            rowHeights=[58 for _ in SOURCE_TYPE_COLUMNS],
        )
        table.setStyle(
            TableStyle(
                [
                    *[("BACKGROUND", (0, row_index), (0, row_index), source_type_colors[source_type]) for row_index, source_type in enumerate(SOURCE_TYPE_COLUMNS)],
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.75, colors.grey),
                    ("INNERGRID", (0, 0), (-1, -1), 6, colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        return table

    def overdue_page_anchor(page_number: int) -> Paragraph:
        return Paragraph(f'<a name="overdue_page_{page_number}"/>', styles["Normal"])

    def overdue_page_count(page_size: int = 15) -> int:
        return max(1, math.ceil(len(report_data["overdue_completion_items"]) / page_size))

    def overdue_page_items(page_number: int, page_size: int = 15) -> list[dict[str, str]]:
        start_index = (page_number - 1) * page_size
        return report_data["overdue_completion_items"][start_index : start_index + page_size]

    def build_pagination_bar(total_items: int, current_page: int, page_size: int = 15) -> Table:
        page_count = max(1, math.ceil(total_items / page_size))
        if page_count <= 25:
            page_labels = list(range(1, page_count + 1))
        else:
            page_labels = [1]
            page_labels.extend(range(max(2, current_page - 2), min(page_count, current_page + 2) + 1))
            if page_count not in page_labels:
                page_labels.append(page_count)

        pagination_style = ParagraphStyle("Pagination", parent=styles["BodyText"], alignment=TA_CENTER, fontSize=7, leading=8)
        page_cells = []
        for page_label in page_labels:
            if page_label == current_page:
                page_cells.append(Paragraph(safe_text(page_label), pagination_style))
            else:
                page_cells.append(Paragraph(f'<link href="#overdue_page_{page_label}">{safe_text(page_label)}</link>', pagination_style))

        table = Table([page_cells], hAlign="LEFT", colWidths=[20 for _ in page_cells], rowHeights=[18])
        styles_for_table = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]
        if page_cells:
            styles_for_table.extend(
                [
                    ("BACKGROUND", (current_page - 1 if page_count <= 25 else page_labels.index(current_page), 0), (current_page - 1 if page_count <= 25 else page_labels.index(current_page), 0), colors.HexColor("#1F4E79")),
                    ("TEXTCOLOR", (current_page - 1 if page_count <= 25 else page_labels.index(current_page), 0), (current_page - 1 if page_count <= 25 else page_labels.index(current_page), 0), colors.white),
                ]
            )
        table.setStyle(TableStyle(styles_for_table))
        return table

    def build_overdue_table(items: list[dict[str, str]]) -> Table:
        preview_cell_style = ParagraphStyle("PreviewCell", parent=styles["BodyText"], fontSize=6, leading=7)
        preview_header_style = ParagraphStyle("PreviewHeader", parent=styles["BodyText"], alignment=TA_CENTER, fontName="Helvetica-Bold", fontSize=6, leading=7)
        rows = [[Paragraph(label, preview_header_style) for label in ["poamItemId", "securityChecks", "device", "source", "days"]]]
        for item in items:
            rows.append(
                [
                    Paragraph(html.escape(item["poam_item_id"]), preview_cell_style),
                    Paragraph(html.escape(item["security_check"]), preview_cell_style),
                    Paragraph(html.escape(item["device"]), preview_cell_style),
                    Paragraph(html.escape(item["source"]), preview_cell_style),
                    Paragraph(html.escape(item["days"]), preview_cell_style),
                ]
            )
        if not items:
            rows.append([Paragraph("No overdue completion dates found.", preview_cell_style), "", "", "", ""])

        table = Table(rows, hAlign="LEFT", colWidths=[55, 120, 95, 190, 55])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FB")]),
                ]
            )
        )
        return table

    def build_items_preview_panel(page_number: int = 1, page_size: int = 15) -> list:
        overdue_items = report_data["overdue_completion_items"]
        total_items = len(overdue_items)
        visible_items = overdue_page_items(page_number, page_size)
        starting_index = ((page_number - 1) * page_size) + 1 if total_items else 0
        ending_index = min(page_number * page_size, total_items)
        summary_text = f"Showing {starting_index} to {ending_index} of {total_items} entries" if total_items else "Showing 0 to 0 of 0 entries"
        return [
            Paragraph("POAM Completion Dates Overdue", styles["Heading2"]),
            build_overdue_table(visible_items),
            Spacer(1, 6),
            Paragraph(summary_text, styles["Normal"]),
            Spacer(1, 4),
            build_pagination_bar(total_items, page_number, page_size),
        ]

    def build_source_details_page() -> Table:
        table = Table(
            [[build_source_type_boxes(), build_items_preview_panel()]],
            hAlign="LEFT",
            colWidths=[170, 530],
        )
        table.setStyle(
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
        return table

    def build_item_table(items: list[dict[str, str]]) -> LongTable | Paragraph:
        if not items:
            return Paragraph("No items found for this status.", styles["Normal"])
        rows = [[Paragraph(label, table_header_style) for label in ["POAM ID", "Severity", "Control", "Scheduled Completion", "Type / Source", "Description"]]]
        for item in items:
            rows.append(
                [
                    Paragraph(html.escape(item["id"]), table_cell_style),
                    Paragraph(html.escape(item["severity"]), table_cell_style),
                    Paragraph(html.escape(item["control"]), table_cell_style),
                    Paragraph(html.escape(item["scheduled_completion"]), table_cell_style),
                    Paragraph(html.escape(item["type"]), table_cell_style),
                    Paragraph(html.escape(item["description"]), table_cell_style),
                ]
            )
        table = LongTable(rows, repeatRows=1, hAlign="LEFT", colWidths=[70, 58, 68, 78, 100, 330])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FB")]),
                ]
            )
        )
        for row_index, item in enumerate(items, start=1):
            severity_color = severity_colors.get(item["severity"])
            if severity_color:
                table.setStyle(TableStyle([("BACKGROUND", (1, row_index), (1, row_index), severity_color)]))
                if item["severity"] in {"Critical", "High"}:
                    table.setStyle(TableStyle([("TEXTCOLOR", (1, row_index), (1, row_index), colors.white)]))
        return table

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=landscape(letter),
        title=REPORT_TITLE,
        author="OpenRMF Professional External API Scripts",
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    story = [
        Paragraph(REPORT_TITLE, styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {html.escape(report_data['generated_at'])}", centered_style),
        Paragraph(f"System Key: {html.escape(report_data['system_key'])}", centered_style),
        Paragraph(f"System Title: {html.escape(report_data['system_title'])}", centered_style),
        Paragraph(f"Source Script: {SOURCE_SCRIPT_NAME}", centered_style),
        PageBreak(),
        Paragraph("POAM Details", styles["Heading1"]),
        Spacer(1, 8),
        build_severity_boxes(),
        Spacer(1, 18),
        build_status_boxes(),
        Spacer(1, 18),
        build_type_pie_charts(),
        PageBreak(),
        Paragraph("POAM Details", styles["Heading1"]),
        Spacer(1, 8),
        overdue_page_anchor(1),
        build_source_details_page(),
    ]
    for page_number in range(2, overdue_page_count() + 1):
        story.extend(
            [
                PageBreak(),
                overdue_page_anchor(page_number),
                Paragraph("POAM Completion Dates Overdue", styles["Heading1"]),
                Spacer(1, 8),
                *build_items_preview_panel(page_number),
            ]
        )
    document.build(story)
    return True


def escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_text_page(lines: list[str], font_size: int = 10) -> str:
    y_position = 560
    content = ["BT", f"/F1 {font_size} Tf"]
    for line in lines:
        content.append(f"1 0 0 1 36 {y_position} Tm ({escape_pdf_text(line)}) Tj")
        y_position -= 14
    content.append("ET")
    return "\n".join(content)


def write_minimal_pdf(output_path: Path, report_data: dict) -> None:
    severity_totals = report_data["ongoing_severity_totals"]
    status_totals = report_data["status_totals"]
    cover_lines = [
        REPORT_TITLE,
        "",
        f"Generated: {report_data['generated_at']}",
        f"System Key: {report_data['system_key']}",
        f"System Title: {report_data['system_title']}",
        f"Source Script: {SOURCE_SCRIPT_NAME}",
    ]
    lines = [
        "",
        "POAM Details",
        "",
        f"Critical: {severity_totals['Critical']}  High: {severity_totals['High']}  Medium: {severity_totals['Medium']}  Low: {severity_totals['Low']}",
        f"Ongoing: {status_totals['Ongoing']}  Completed: {status_totals['Completed']}  Accepted: {status_totals['Accepted']}",
        "",
    ]
    for status in STATUS_COLUMNS:
        items = report_data["items_by_status"][status]
        lines.extend([f"{status} Items ({len(items)})", "POAM ID | Severity | Control | Scheduled Completion | Type | Description"])
        if not items:
            lines.append("No items found for this status.")
        for item in items:
            lines.append(compact_text(f"{item['id']} | {item['severity']} | {item['control']} | {item['scheduled_completion']} | {item['type']} | {item['description']}", 150))
        lines.append("")
    page_streams = [make_text_page(cover_lines)]
    page_streams.extend(make_text_page(lines[index : index + 37]) for index in range(0, len(lines), 37))
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    page_object_numbers = []
    for page_stream in page_streams:
        page_object_number = len(objects) + 1
        content_object_number = len(objects) + 2
        page_object_numbers.append(page_object_number)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 792 612] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>".encode("latin-1"))
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
    if write_pdf_with_reportlab(output_path, report_data):
        return "reportlab"
    write_minimal_pdf(output_path, report_data)
    return "fallback"


def main() -> None:
    if len(sys.argv) < REQUIRED_ARGUMENT_COUNT:
        print_usage()
        sys.exit(1)
    system_key = sys.argv[4]
    poamdata = parse_json_value_from_output(call_poam_json_script(sys.argv[1:]))
    report_data = build_report_data(poamdata, system_key)
    output_filename = f"OpenRMFPro-POAM-Visual-{safe_filename_value(report_data['system_key'])}.pdf"
    output_path = Path(output_filename)
    pdf_writer = write_pdf(output_path, report_data)
    print(f"Created PDF: {output_filename}")
    if pdf_writer == "fallback":
        print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
    main()
