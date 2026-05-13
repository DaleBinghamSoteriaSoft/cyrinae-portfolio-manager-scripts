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
from datetime import datetime
from pathlib import Path

REQUIRED_ARGUMENT_COUNT = 5
SOURCE_SCRIPT_NAME = "get_systempackage_by_systemkey_json.py"
REPORT_TITLE = "OpenRMF Professional System Package Overview"


def print_usage() -> None:
    print("ERROR: Missing required parameters.")
    print(
        "Usage: python3 "
        + Path(__file__).name
        + " <rootURL> <applicationKey> <authorizationToken> <systemKey>"
    )


def call_systempackage_json_script(arguments: list[str]) -> str:
    source_script = Path(__file__).resolve().parent / SOURCE_SCRIPT_NAME
    command = [sys.executable, str(source_script), *arguments]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode != 0:
        print("ERROR: The system package JSON script failed.")
        if result.stdout.strip():
            print(result.stdout.strip())
        if result.stderr.strip():
            print(result.stderr.strip())
        sys.exit(result.returncode)

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


def safe_text(value) -> str:
    if value is None:
        return ""
    return str(value)


def safe_filename_value(value: str) -> str:
    safe_value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return safe_value.strip(".-") or "unknown-system"


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


def build_report_data(system_package: dict) -> dict[str, str]:
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
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
    }


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, str]) -> bool:
    try:
        from reportlab.lib.pagesizes import letter  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib.styles import getSampleStyleSheet  # pyright: ignore[reportMissingModuleSource]
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # pyright: ignore[reportMissingModuleSource]
        from reportlab.lib import colors  # pyright: ignore[reportMissingModuleSource]
    except ImportError:
        return False

    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        title=REPORT_TITLE,
        author="OpenRMF Professional External API Scripts",
    )
    story = [
        Paragraph(REPORT_TITLE, styles["Title"]),
        Spacer(1, 24),
        Paragraph("System Package Overview", styles["Heading1"]),
        Spacer(1, 12),
        Paragraph(f"Generated: {html.escape(report_data['generated_at'])}", styles["Normal"]),
        Paragraph(f"System Key: {html.escape(report_data['system_key'])}", styles["Normal"]),
        Paragraph(f"Source Script: {SOURCE_SCRIPT_NAME}", styles["Normal"]),
        PageBreak(),
        Paragraph("Overview", styles["Heading1"]),
        Spacer(1, 12),
        Paragraph(f"<b>Title:</b> {html.escape(report_data['title'])}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph(f"<b>Description:</b> {html.escape(report_data['description'])}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph(
            f"<b>Number of Checklists:</b> {html.escape(report_data['number_of_checklists'])}",
            styles["Normal"],
        ),
        Spacer(1, 10),
        Paragraph(f"<b>Framework Title:</b> {html.escape(report_data['framework_title'])}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph(f"<b>Framework Acronym:</b> {html.escape(report_data['framework_acronym'])}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph(f"<b>Framework Version:</b> {html.escape(report_data['framework_version'])}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("<b>Framework Levels:</b>", styles["Normal"]),
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
            PageBreak(),
            Paragraph("Checklist", styles["Heading1"]),
            Spacer(1, 12),
            Table(
                [
                    ["Category", "Open", "Not a Finding", "Not Applicable", "Not Reviewed"],
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
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend(
        [
            Spacer(1, 24),
            Table(
                [
                    ["Category", "Total Score"],
                    *[[row["category"], row["total_score"]] for row in report_data["category_total_score_rows"]],
                ],
                hAlign="LEFT",
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend(
        [
            Spacer(1, 24),
            Table(
                [
                    ["Status", "Total"],
                    *[[row["status"], row["total"]] for row in report_data["total_status_rows"]],
                ],
                hAlign="LEFT",
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.extend(
        [
            PageBreak(),
            Paragraph("Patch", styles["Heading1"]),
            Spacer(1, 12),
            Table(
                [
                    ["Metric", "Value"],
                    *[[row["metric"], row["value"]] for row in report_data["patch_rows"]],
                ],
                hAlign="LEFT",
            ),
        ]
    )
    story[-1].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
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


def build_fallback_pages(report_data: dict[str, str]) -> list[str]:
    title_lines = [
        REPORT_TITLE,
        "",
        "System Package Overview",
        "",
        f"Generated: {report_data['generated_at']}",
        f"System Key: {report_data['system_key']}",
        f"Source Script: {SOURCE_SCRIPT_NAME}",
    ]
    detail_lines = ["Overview", "", f"Title: {report_data['title']}", "", "Description:"]
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

    checklist_lines = [
        "Checklist",
        "",
        "Category      Open       Not a Finding  Not Applicable  Not Reviewed",
        "------------  ---------  -------------  --------------  ------------",
    ]
    for row in report_data["score_rows"]:
        checklist_lines.append(
            f"{row['category']:<12}  {row['open']:>9}  {row['not_a_finding']:>13}  {row['not_applicable']:>14}  {row['not_reviewed']:>12}"
        )
    checklist_lines.extend(["", "Category      Total Score", "------------  -----------"])
    for row in report_data["category_total_score_rows"]:
        checklist_lines.append(f"{row['category']:<12}  {row['total_score']:>11}")
    checklist_lines.extend(["", "Status          Total", "--------------  ---------"])
    for row in report_data["total_status_rows"]:
        checklist_lines.append(f"{row['status']:<14}  {row['total']:>9}")

    patch_lines = ["Patch", "", "Metric         Value", "-------------  ---------"]
    for row in report_data["patch_rows"]:
        patch_lines.append(f"{row['metric']:<13}  {row['value']:>9}")

    pages = [make_text_page(title_lines, font_size=14)]
    current_lines: list[str] = []
    for line in detail_lines:
        wrapped_lines = textwrap.wrap(line, width=78) if len(line) > 78 else [line]
        for wrapped_line in wrapped_lines:
            current_lines.append(wrapped_line)
            if len(current_lines) == 36:
                pages.append(make_text_page(current_lines))
                current_lines = []
    if current_lines:
        pages.append(make_text_page(current_lines))
    pages.append(make_text_page(checklist_lines))
    pages.append(make_text_page(patch_lines))
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
report_data = build_report_data(system_package_data)
output_filename = f"OpenRMFPro-System-Package-Overview-{safe_filename_value(report_data['system_key'])}.pdf"
output_path = Path(output_filename)
pdf_writer = write_pdf(output_path, report_data)

print(f"Created PDF: {output_path}")
if pdf_writer == "fallback":
    print("NOTE: reportlab was not installed. Created the PDF with the built-in lightweight fallback writer.")
