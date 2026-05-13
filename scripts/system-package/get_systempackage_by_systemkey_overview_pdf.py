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


def build_report_data(system_package: dict) -> dict[str, str]:
    system_key = safe_text(system_package.get("systemKey")).strip()
    if not system_key:
        print("ERROR: The returned system package JSON did not include systemKey.")
        sys.exit(1)

    return {
        "system_key": system_key,
        "title": safe_text(system_package.get("title")).strip() or "Unknown",
        "description": safe_text(system_package.get("description")).strip() or "No description returned.",
        "number_of_checklists": safe_text(system_package.get("numberOfChecklists")).strip() or "0",
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %I:%M:%S %p %Z"),
    }


def write_pdf_with_reportlab(output_path: Path, report_data: dict[str, str]) -> bool:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer
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
    ]
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
    detail_lines.extend(["", f"Number of Checklists: {report_data['number_of_checklists']}"])

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
