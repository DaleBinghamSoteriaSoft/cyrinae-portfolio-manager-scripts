#!/usr/bin/env python3
# ============================================================
# OpenRMF Professional External API - Systempackage POAM Risk PDF
# API Path   : GET /systempackage/{systemKey}/poam
# Description: Calls get_systempackage_by_systemkey_poam_json.py and creates a PDF chart of Ongoing POAM residual risk mitigation totals.
# ============================================================

import html
import json
import math
import re
import subprocess
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SOURCE_SCRIPT_NAME = "get_systempackage_by_systemkey_poam_json.py"
REPORT_TITLE = "OpenRMF Professional POAM Risk"
STATUS_COLUMNS = ["Ongoing", "Completed", "Accepted"]
RISK_COLUMNS = ["Very High", "High", "Moderate", "Low", "Very Low", "Completed", "Accepted", "Not Set"]
RESIDUAL_RISK_COLUMNS = ["Very High", "High", "Moderate", "Low", "Very Low"]
POAM_TYPE_COLUMNS = ["Checklist", "Patch", "Other Technology", "Statement", "Inherited", "Manual/Deleted"]
ONGOING_TYPE_CHART_TITLES = {
    "Checklist": "Ongoing Checklist Items",
    "Patch": "Ongoing Patch Items",
    "Other Technology": "Ongoing Other Technology Items",
    "Statement": "Ongoing Compliance Statement Items",
    "Inherited": "Ongoing Inherited Control Items",
    "Manual/Deleted": "Ongoing Manual/Deleted Items",
}
POAM_TYPE_DEFINITIONS = [
    ("artifactId", "Checklist"),
    ("patchScanId", "Patch"),
    ("vulnScanId", "Other Technology"),
    ("statementId", "Statement"),
    ("inheritedControlId", "Inherited"),
]
MANUAL_POAM_TYPE = "Manual/Deleted"
REPORT_SECTIONS = [
    {"title": "Details", "anchor": "details", "page_number": "2"},
    {"title": "Ongoing Items by Type and Residual Risk", "anchor": "ongoing-items-by-type-and-residual-risk", "page_number": "3"},
]


def build_table_of_contents_rows() -> list[dict[str, str]]:
    return [
        {"title": section["title"], "anchor": section["anchor"], "page_number": section["page_number"]}
        for section in REPORT_SECTIONS
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


def compact_text(value: str, max_length: int = 160) -> str:
    compacted = re.sub(r"\s+", " ", safe_text(value)).strip()
    if len(compacted) <= max_length:
        return compacted
    return compacted[: max_length - 3].rstrip() + "..."


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


def normalize_risk_value(value: str) -> str:
    value_text = safe_text(value).strip().lower().replace("_", " ").replace("-", " ")
    value_text = re.sub(r"\s+", " ", value_text)
    if value_text in {"", "none", "null", "n/a", "na", "not set", "notset", "unset", "unknown", "unspecified"}:
        return "Not Set"
    if value_text in {"very high", "veryhigh", "critical", "cat i", "cat 1", "i", "5", "4"}:
        return "Very High"
    if value_text in {"high", "cat ii", "cat 2", "ii", "3"}:
        return "High"
    if value_text in {"moderate", "medium", "cat iii", "cat 3", "iii", "2"}:
        return "Moderate"
    if value_text in {"low", "cat iv", "cat 4", "iv", "1"}:
        return "Low"
    if value_text in {"very low", "verylow", "informational", "info", "0"}:
        return "Very Low"
    if value_text in {"completed", "complete", "closed"}:
        return "Completed"
    if value_text in {"accepted", "risk accepted", "risk acceptance"}:
        return "Accepted"
    return "Not Set"


def residual_risk_mitigation_value(record: dict) -> str:
    risk_value = first_value(
        record,
        [
            "residualRiskLevelMitigations",
            "residualRiskLevelMitigation",
            "resultingResidualRisk",
            "resultingRisk",
            "residualRiskMitigations",
        ],
    )
    if not risk_value:
        risk_value = first_nested_value(
            record,
            [
                ["residualRiskLevelMitigations", "name"],
                ["residualRiskLevelMitigation", "name"],
                ["resultingResidualRisk", "name"],
            ],
        )
    return risk_value


def residual_risk_level_mitigations_value(record: dict) -> str:
    return safe_text(record.get("residualRiskLevelMitigations"))


def has_residual_risk_mitigation(record: dict) -> bool:
    value_text = residual_risk_level_mitigations_value(record).strip()
    return value_text.lower() not in {"", "null"}


def status_field_matches(record: dict, expected_status: str) -> bool:
    return normalize_poam_status(safe_text(record.get("status"))) == expected_status


def has_poam_type_value(record: dict, key: str) -> bool:
    return safe_text(record.get(key)).strip().lower() not in {"", "none", "null"}


def poam_type(record: dict) -> str:
    for key, label in POAM_TYPE_DEFINITIONS:
        if has_poam_type_value(record, key):
            return label
    return MANUAL_POAM_TYPE


def residual_risk_mitigation(record: dict) -> str:
    risk_value = residual_risk_level_mitigations_value(record)
    if risk_value.strip().lower() in {"", "null"}:
        return "Not Set"
    return normalize_risk_value(risk_value)


def build_risk_totals(records: list[dict]) -> dict[str, int]:
    totals = {risk: 0 for risk in RISK_COLUMNS}
    for record in records:
        if status_field_matches(record, "Completed"):
            if has_residual_risk_mitigation(record):
                totals["Completed"] += 1
            else:
                totals["Not Set"] += 1
            continue
        if status_field_matches(record, "Accepted"):
            if has_residual_risk_mitigation(record):
                totals["Accepted"] += 1
            else:
                totals["Not Set"] += 1
            continue
        if poam_status(record) == "Ongoing":
            totals[residual_risk_mitigation(record)] += 1
    return totals


def build_risk_totals_by_status(records: list[dict]) -> dict[str, dict[str, int]]:
    totals = {status: {risk: 0 for risk in RISK_COLUMNS} for status in STATUS_COLUMNS}
    for record in records:
        status = poam_status(record)
        if status not in totals:
            continue
        totals[status][residual_risk_mitigation(record)] += 1
    return totals


def build_type_totals_by_status(records: list[dict]) -> dict[str, dict[str, int]]:
    totals = {status: {poam_type_label: 0 for poam_type_label in POAM_TYPE_COLUMNS} for status in STATUS_COLUMNS}
    for record in records:
        status = poam_status(record)
        if status not in totals or not has_residual_risk_mitigation(record):
            continue
        totals[status][poam_type(record)] += 1
    return totals


def build_ongoing_type_risk_totals(records: list[dict]) -> dict[str, dict[str, int]]:
    totals = {poam_type_label: {risk: 0 for risk in RESIDUAL_RISK_COLUMNS} for poam_type_label in POAM_TYPE_COLUMNS}
    for record in records:
        if poam_status(record) != "Ongoing" or not has_residual_risk_mitigation(record):
            continue
        risk = residual_risk_mitigation(record)
        if risk in RESIDUAL_RISK_COLUMNS:
            totals[poam_type(record)][risk] += 1
    return totals


def build_report_data(poamdata, system_key: str) -> dict:
    records = poam_records(poamdata)
    ongoing_records = [record for record in records if poam_status(record) == "Ongoing"]
    system_title = ""
    for record in records:
        system_title = first_value(record, ["systemTitle", "title", "systemName"])
        if system_title:
            break
    return {
        "system_key": system_key,
        "system_title": system_title or "Unknown",
        "poam_count": len(records),
        "ongoing_count": len(ongoing_records),
        "risk_totals": build_risk_totals(records),
        "risk_totals_by_status": build_risk_totals_by_status(records),
        "type_totals_by_status": build_type_totals_by_status(records),
        "ongoing_type_risk_totals": build_ongoing_type_risk_totals(records),
        "table_of_contents_rows": build_table_of_contents_rows(),
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
    }


def write_pdf_with_reportlab(output_path: Path, report_data: dict) -> bool:
    try:
        from reportlab.graphics.charts.piecharts import Pie  # pyright: ignore[reportMissingModuleSource]
        from reportlab.graphics.shapes import Drawing, Rect, String  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.enums import TA_CENTER  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
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
    centered_style = ParagraphStyle("Centered", parent=styles["BodyText"], alignment=TA_CENTER)
    box_style = ParagraphStyle("RiskBox", parent=styles["BodyText"], alignment=TA_CENTER, fontName="Helvetica-Bold", fontSize=12, leading=16)
    contents_link_style = ParagraphStyle("ContentsLink", parent=styles["BodyText"], fontSize=9, leading=11, textColor=colors.blue)
    small_chart_title_style = ParagraphStyle("SmallChartTitle", parent=styles["BodyText"], alignment=TA_CENTER, fontName="Helvetica-Bold", fontSize=8, leading=10)
    risk_colors = {
        "Very High": colors.HexColor("#C00000"),
        "High": colors.HexColor("#ED7D31"),
        "Moderate": colors.white,
        "Low": colors.HexColor("#FFD966"),
        "Very Low": colors.HexColor("#70AD47"),
        "Completed": colors.HexColor("#C6E0B4"),
        "Accepted": colors.HexColor("#D9D9D9"),
        "Not Set": colors.HexColor("#A6A6A6"),
    }
    type_colors = {
        "Checklist": colors.HexColor("#5B9BD5"),
        "Patch": colors.HexColor("#D94A73"),
        "Other Technology": colors.HexColor("#ED7D31"),
        "Statement": colors.HexColor("#FFC000"),
        "Inherited": colors.HexColor("#00A6A6"),
        "Manual/Deleted": colors.HexColor("#8064A2"),
    }
    light_text_risks = {"Very High", "Very Low"}
    light_text_types = {"Checklist", "Patch", "Other Technology", "Inherited", "Manual/Deleted"}

    def anchored_heading(title: str, anchor: str):
        paragraph = Paragraph(f'<a name="{html.escape(anchor, quote=True)}"/>{html.escape(title)}', styles["Heading1"])
        paragraph._toc_anchor = anchor
        return paragraph

    def contents_link(title: str, anchor: str):
        return Paragraph(f'<a href="#{html.escape(anchor, quote=True)}" color="blue">{html.escape(title)}</a>', contents_link_style)

    def build_contents_table():
        contents_table_rows = [[Paragraph("Page Title", centered_style), Paragraph("Page Number", centered_style)]]
        contents_table_rows.extend(
            [
                contents_link(row["title"], row["anchor"]),
                row["page_number"],
            ]
            for row in report_data["table_of_contents_rows"]
        )
        table = Table(contents_table_rows, hAlign="CENTER", colWidths=[330, 90])
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

    def risk_box_label(risk: str) -> str:
        if risk in {"Very High", "High", "Moderate", "Low", "Very Low"}:
            return f"Ongoing {risk}"
        return risk

    def build_risk_boxes() -> Table:
        rows = []
        for start_index in range(0, len(RISK_COLUMNS), 4):
            rows.append(
                [
                    Paragraph(
                        f"<font size='24'>{safe_text(report_data['risk_totals'][risk])}</font><br/>{html.escape(risk_box_label(risk))}",
                        box_style,
                    )
                    for risk in RISK_COLUMNS[start_index : start_index + 4]
                ]
            )
        table = Table(rows, hAlign="CENTER", colWidths=[118, 118, 118, 118], rowHeights=[92, 92])
        table_styles = [
            ("BOX", (0, 0), (-1, -1), 0.75, colors.grey),
            ("INNERGRID", (0, 0), (-1, -1), 8, colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]
        for index, risk in enumerate(RISK_COLUMNS):
            column_index = index % 4
            row_index = index // 4
            table_styles.append(("BACKGROUND", (column_index, row_index), (column_index, row_index), risk_colors[risk]))
            if risk in light_text_risks:
                table_styles.append(("TEXTCOLOR", (column_index, row_index), (column_index, row_index), colors.white))
        table.setStyle(TableStyle(table_styles))
        return table

    def build_type_pie_chart(status: str) -> Drawing:
        totals = report_data["type_totals_by_status"][status]
        nonzero_totals = [(label, count) for label, count in totals.items() if count]
        drawing = Drawing(170, 225)
        chart_status = "Complete" if status == "Completed" else status
        drawing.add(String(35, 210, f"{chart_status} By Type", fontName="Helvetica-Bold", fontSize=10))

        if nonzero_totals:
            pie_x = 40
            pie_y = 102
            pie_size = 88
            pie = Pie()
            pie.x = pie_x
            pie.y = pie_y
            pie.width = pie_size
            pie.height = pie_size
            pie.data = [count for _, count in nonzero_totals]
            pie.labels = ["" for _ in nonzero_totals]
            pie.slices.strokeWidth = 0.5
            for index, (label, _) in enumerate(nonzero_totals):
                pie.slices[index].fillColor = type_colors[label]
            drawing.add(pie)

            total_count = sum(count for _, count in nonzero_totals)
            current_angle = 90.0
            center_x = pie_x + (pie_size / 2)
            center_y = pie_y + (pie_size / 2)
            label_radius = pie_size * 0.28
            for label, count in nonzero_totals:
                sweep_angle = 360.0 * count / total_count if total_count else 0
                middle_angle = current_angle - (sweep_angle / 2)
                radians = math.radians(middle_angle)
                label_x = center_x + (math.cos(radians) * label_radius) - 4
                label_y = center_y + (math.sin(radians) * label_radius) - 4
                drawing.add(
                    String(
                        label_x,
                        label_y,
                        safe_text(count),
                        fillColor=colors.white if label in light_text_types else colors.black,
                        fontName="Helvetica-Bold",
                        fontSize=9,
                    )
                )
                current_angle -= sweep_angle
        else:
            drawing.add(String(61, 142, "No data", fontSize=8))

        legend_y = 82
        for index, label in enumerate(POAM_TYPE_COLUMNS):
            current_y = legend_y - (index * 12)
            drawing.add(Rect(16, current_y - 1, 7, 7, fillColor=type_colors[label], strokeColor=None))
            drawing.add(String(28, current_y, label, fontSize=7))
        return drawing

    def build_type_pie_charts() -> Table:
        table = Table(
            [[build_type_pie_chart(status) for status in STATUS_COLUMNS]],
            hAlign="CENTER",
            colWidths=[170, 170, 170],
        )
        table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        return table

    def build_ongoing_type_risk_chart(poam_type_label: str) -> Table:
        totals = report_data["ongoing_type_risk_totals"][poam_type_label]
        rows = [[Paragraph(html.escape(ONGOING_TYPE_CHART_TITLES[poam_type_label]), small_chart_title_style), ""]]
        rows.extend([[risk, safe_text(totals[risk])] for risk in RESIDUAL_RISK_COLUMNS])
        table = Table(rows, hAlign="CENTER", colWidths=[118, 32], rowHeights=[26, 18, 18, 18, 18, 18])
        table_styles = [
            ("SPAN", (0, 0), (1, 0)),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
            ("GRID", (0, 1), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (0, 0), (-1, 0), "CENTER"),
            ("ALIGN", (1, 1), (1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for row_index, risk in enumerate(RESIDUAL_RISK_COLUMNS, start=1):
            table_styles.append(("BACKGROUND", (0, row_index), (1, row_index), risk_colors[risk]))
            if risk in light_text_risks:
                table_styles.append(("TEXTCOLOR", (0, row_index), (1, row_index), colors.white))
        table.setStyle(TableStyle(table_styles))
        return table

    def build_ongoing_type_risk_charts() -> Table:
        table = Table(
            [
                [build_ongoing_type_risk_chart(poam_type_label) for poam_type_label in POAM_TYPE_COLUMNS[:3]],
                [build_ongoing_type_risk_chart(poam_type_label) for poam_type_label in POAM_TYPE_COLUMNS[3:]],
            ],
            hAlign="CENTER",
            colWidths=[168, 168, 168],
            rowHeights=[150, 150],
        )
        table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        return table

    document_options = {
        "pagesize": letter,
        "title": REPORT_TITLE,
        "author": "OpenRMF Professional External API Scripts",
        "leftMargin": 36,
        "rightMargin": 36,
        "topMargin": 36,
        "bottomMargin": 36,
    }
    contents_table = build_contents_table()
    story = [
        Paragraph(REPORT_TITLE, styles["Title"]),
        Spacer(1, 10),
        Paragraph(f"Generated: {html.escape(report_data['generated_at'])}", centered_style),
        Paragraph(f"System Key: {html.escape(report_data['system_key'])}", centered_style),
        Paragraph(f"System Title: {html.escape(report_data['system_title'])}", centered_style),
        Paragraph(f"Source Script: {SOURCE_SCRIPT_NAME}", centered_style),
        Spacer(1, 18),
        Paragraph("Table of Contents", styles["Heading2"]),
        Spacer(1, 8),
        contents_table,
        PageBreak(),
        anchored_heading("Details", "details"),
        Spacer(1, 12),
        build_risk_boxes(),
        Spacer(1, 20),
        build_type_pie_charts(),
        PageBreak(),
        anchored_heading("Ongoing Items by Type and Residual Risk", "ongoing-items-by-type-and-residual-risk"),
        Spacer(1, 12),
        build_ongoing_type_risk_charts(),
    ]
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


def make_text_page(lines: list[str], font_size: int = 10) -> str:
    y_position = 740
    content = ["BT", f"/F1 {font_size} Tf"]
    for line in lines:
        content.append(f"1 0 0 1 36 {y_position} Tm ({escape_pdf_text(line)}) Tj")
        y_position -= 14
    content.append("ET")
    return "\n".join(content)


def write_minimal_pdf(output_path: Path, report_data: dict) -> None:
    risk_totals = report_data["risk_totals"]
    type_totals_by_status = report_data["type_totals_by_status"]
    ongoing_type_risk_totals = report_data["ongoing_type_risk_totals"]
    contents_lines = ["Table of Contents", "Page Title                                      Page Number", "--------------------------------------------  -----------"]
    contents_lines.extend([f"{row['title']:<44}  {row['page_number']:>11}" for row in report_data["table_of_contents_rows"]])
    cover_lines = [
        REPORT_TITLE,
        "",
        f"Generated: {report_data['generated_at']}",
        f"System Key: {report_data['system_key']}",
        f"System Title: {report_data['system_title']}",
        f"Source Script: {SOURCE_SCRIPT_NAME}",
        "",
        *contents_lines,
    ]
    chart_lines = [
        "Details",
        "",
        "Residual Risk Mitigations | Ongoing Count",
        "-------------------------- | -------------",
        "",
    ]
    for risk in RISK_COLUMNS:
        count = risk_totals[risk]
        chart_lines.append(compact_text(f"{risk:<26} | {count:>13}", 95))
    chart_lines.append("")
    for status in STATUS_COLUMNS:
        chart_status = "Complete" if status == "Completed" else status
        chart_lines.extend([f"{chart_status} By Type", "POAM Type                 | Count", "------------------------- | -----"])
        for poam_type_label in POAM_TYPE_COLUMNS:
            chart_lines.append(compact_text(f"{poam_type_label:<25} | {type_totals_by_status[status][poam_type_label]:>5}", 95))
        chart_lines.append("")
    ongoing_type_risk_lines = [
        "Ongoing Items by Type and Residual Risk",
        "",
    ]
    for poam_type_label in POAM_TYPE_COLUMNS:
        ongoing_type_risk_lines.extend(
            [
                ONGOING_TYPE_CHART_TITLES[poam_type_label],
                "Residual Risk | Count",
                "------------- | -----",
            ]
        )
        for risk in RESIDUAL_RISK_COLUMNS:
            ongoing_type_risk_lines.append(compact_text(f"{risk:<13} | {ongoing_type_risk_totals[poam_type_label][risk]:>5}", 95))
        ongoing_type_risk_lines.append("")

    page_streams = [make_text_page(cover_lines), make_text_page(chart_lines), make_text_page(ongoing_type_risk_lines)]
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    page_object_numbers = []
    for page_stream in page_streams:
        page_object_number = len(objects) + 1
        content_object_number = len(objects) + 2
        page_object_numbers.append(page_object_number)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>".encode("latin-1"))
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
    poamdata = parse_json_value_from_output(call_poam_json_script(sys.argv[1:]))
    report_data = build_report_data(poamdata, system_key)
    output_filename = f"OpenRMFPro-POAM-Residual-Risk-Overview-{safe_filename_value(report_data['system_key'])}.pdf"
    output_path = Path(output_filename)
    pdf_writer = write_pdf(output_path, report_data)
    print(f"Created PDF: {output_filename}")
    if pdf_writer == "fallback":
        print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")


if __name__ == "__main__":
    main()