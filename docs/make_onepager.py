"""Generate a one-page A4 project summary PDF for Fissure (ReportLab)."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepInFrame
)

OUT = r"D:\was lab\fissure\Fissure_Project_Summary.pdf"

NAVY = colors.HexColor("#12233b")
STEEL = colors.HexColor("#2b4a73")
ACCENT = colors.HexColor("#d9480f")
GREEN = colors.HexColor("#2b8a3e")
LIGHT = colors.HexColor("#eef1f5")
GREY = colors.HexColor("#5a6472")
LINE = colors.HexColor("#d7dce3")

styles = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=20, textColor=colors.white, leading=23),
    "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=9.5, textColor=colors.HexColor("#9fb3c8"), leading=13),
    "meta": ParagraphStyle("meta", fontName="Helvetica-Bold", fontSize=8.5, textColor=colors.white, alignment=2, leading=12),
    "h": ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=10.5, textColor=NAVY, spaceBefore=2, spaceAfter=3),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=8.8, textColor=colors.HexColor("#22272e"), leading=12.5),
    "bodyc": ParagraphStyle("bodyc", fontName="Helvetica", fontSize=8.8, textColor=colors.HexColor("#22272e"), leading=12.5, alignment=TA_CENTER),
    "cellh": ParagraphStyle("cellh", fontName="Helvetica-Bold", fontSize=8.6, textColor=colors.white, leading=11),
    "cell": ParagraphStyle("cell", fontName="Helvetica", fontSize=8.3, textColor=colors.HexColor("#22272e"), leading=11),
    "cellb": ParagraphStyle("cellb", fontName="Helvetica-Bold", fontSize=8.3, textColor=NAVY, leading=11),
    "pill": ParagraphStyle("pill", fontName="Helvetica-Bold", fontSize=8.3, textColor=colors.white, leading=11, alignment=TA_CENTER),
    "foot": ParagraphStyle("foot", fontName="Helvetica", fontSize=7.8, textColor=GREY, leading=10.5),
}


def header_band():
    left = [
        Paragraph("Fissure", styles["title"]),
        Paragraph("Active Web-Application Vulnerability Scanner", styles["sub"]),
    ]
    right = [
        Paragraph("Web &amp; Application Security (WAS) Lab", styles["meta"]),
        Paragraph("Mini Project", styles["meta"]),
    ]
    t = Table([[left, right]], colWidths=[118 * mm, 58 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    return t


def section(title):
    return [Paragraph(title, styles["h"]),
            HRFlowable(width="100%", thickness=1.1, color=ACCENT, spaceAfter=4, spaceBefore=0)]


def box(flowables, bg=LIGHT, pad=8):
    t = Table([[flowables]], colWidths=[176 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LEFTPADDING", (0, 0), (-1, -1), pad), ("RIGHTPADDING", (0, 0), (-1, -1), pad),
        ("TOPPADDING", (0, 0), (-1, -1), pad), ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
    ]))
    return t


def detection_table():
    head = [Paragraph("Vulnerability class", styles["cellh"]),
            Paragraph("Techniques used", styles["cellh"]),
            Paragraph("How a hit is confirmed", styles["cellh"])]
    rows = [
        ("SQL Injection", "Error- · Boolean- · Time-based blind", "DB error · true/false size diff · ~5s delay"),
        ("Command Injection", "Time-based blind (sleep/ping)", "Response delayed ~6s by injected shell command"),
        ("Reflected XSS", "Markers in HTML / attribute / script", "Payload reflected unescaped in the response"),
        ("Path Traversal / LFI", "../ sequences + encodings", "Response contains /etc/passwd or win.ini contents"),
        ("Template Injection (SSTI)", "{{a*b}} / ${} / &lt;%=%&gt; marker probe", "Engine evaluates the arithmetic expression"),
        ("CORS misconfiguration", "Reflected Origin probe", "ACAO echoes attacker origin with credentials"),
        ("Open Redirect", "External canary on nav params", "3xx Location or meta-refresh points off-site"),
        ("Default / sensitive files", "Path wordlist + autoindex check", "HTTP 200 on sensitive path · 'Index of /'"),
        ("Security headers / cookies", "Passive headers &amp; Set-Cookie flags", "Missing CSP/HSTS/XFO · HttpOnly/Secure/SameSite"),
    ]
    data = [head]
    for a, b, c in rows:
        data.append([Paragraph(a, styles["cellb"]), Paragraph(b, styles["cell"]), Paragraph(c, styles["cell"])])
    t = Table(data, colWidths=[36 * mm, 73 * mm, 67 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), STEEL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    return t


def pipeline():
    steps = ["Scope guard", "Crawl", "Active tests", "Discovery", "Report"]
    cells = []
    for i, s in enumerate(steps):
        cells.append(Paragraph(s, styles["pill"]))
        if i < len(steps) - 1:
            cells.append(Paragraph("&#8594;", ParagraphStyle("arr", fontName="Helvetica-Bold", fontSize=11, textColor=ACCENT, alignment=TA_CENTER)))
    widths = []
    for i in range(len(cells)):
        widths.append(9 * mm if i % 2 else 31.6 * mm)
    t = Table([cells], colWidths=widths)
    sty = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
           ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for i in range(len(cells)):
        if i % 2 == 0:
            sty.append(("BACKGROUND", (i, 0), (i, 0), STEEL))
    t.setStyle(TableStyle(sty))
    return t


def comparison_table():
    head = [Paragraph("Tool", styles["cellh"]), Paragraph("Category", styles["cellh"]),
            Paragraph("Confirms exploitability", styles["cellh"]), Paragraph("Footprint", styles["cellh"])]
    rows = [
        ("OWASP ZAP", "Full DAST (active + passive)", "Yes — broad", "Large · Java daemon/GUI"),
        ("Burp Suite", "Intercepting proxy + scanner", "Yes (Pro, paid)", "Large · commercial"),
        ("Nikto", "Server / misconfig scanner", "No — signature matches", "Small · Perl CLI"),
        ("sqlmap", "SQL-injection exploitation", "Yes — SQLi only", "Medium · CLI"),
        ("Fissure (ours)", "Focused active scanner + GUI", "Yes — SQLi/XSS/cmdi/LFI", "Tiny · single .exe"),
    ]
    data = [head]
    for r in rows:
        last = r[0].startswith("Fissure")
        style = styles["cellb"] if last else styles["cell"]
        data.append([Paragraph(r[0], styles["cellb"]), Paragraph(r[1], style),
                     Paragraph(r[2], style), Paragraph(r[3], style)])
    t = Table(data, colWidths=[30 * mm, 56 * mm, 46 * mm, 44 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), STEEL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#eaf5ec")),  # highlight our row
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def why_cols():
    feats = [
        "<b>Confirms, not just flags</b> — it injects and observes real behaviour (DB error, 5s delay, unescaped reflection), so a finding means <i>exploitable</i>, not merely “looks odd.”",
        "<b>Right-sized &amp; transparent</b> — one small, readable Python codebase vs. heavyweight Java/commercial suites; every check is auditable, not a black box.",
        "<b>Safe-by-default</b> — refuses public targets without explicit authorization; payloads are non-destructive (sleep/ping, never <tt>rm</tt>).",
        "<b>Zero-friction demo</b> — a single <b>Windows .exe</b> (no Python needed) plus a bundled vulnerable target; 38 automated tests; verified live against DVWA.",
        "<b>Honest severity</b> — context-aware CLEAN&#8594;CRITICAL score with CWE ids; correctly reports <i>nothing</i> when a target is properly fixed.",
        "<b>Built to grow</b> — a clean module/engine/report contract that becomes the toolbelt for <b>Fissure AI</b> (Step 2, a Claude agent that drives it).",
    ]
    left = [Paragraph("•&nbsp; " + f, styles["body"]) for f in feats[:3]]
    right = [Paragraph("•&nbsp; " + f, styles["body"]) for f in feats[3:]]
    def stack(items):
        inner = []
        for it in items:
            inner.append(it); inner.append(Spacer(1, 3))
        return inner
    t = Table([[stack(left), stack(right)]], colWidths=[88 * mm, 88 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LEFTPADDING", (0, 0), (0, 0), 0), ("RIGHTPADDING", (0, 0), (0, 0), 8),
                           ("LEFTPADDING", (1, 0), (1, 0), 8)]))
    return t


def build():
    doc = SimpleDocTemplate(OUT, pagesize=A4,
                            leftMargin=17 * mm, rightMargin=17 * mm,
                            topMargin=0, bottomMargin=10 * mm)
    S = []
    S.append(header_band())
    S.append(Spacer(1, 9))

    # Problem statement
    S += section("Problem Statement")
    ps = ("Passive and reconnaissance scanners report missing headers, open ports and known-file "
          "exposure, but they never confirm whether an input is <b>actually exploitable</b>. That leaves a "
          "gap between \u201clooks risky\u201d and \u201cis vulnerable.\u201d <b>Fissure</b> closes it: given a single "
          "<b>authorized</b> target URL, it crawls the web application, automatically discovers every query "
          "parameter and form field, and <b>actively injects payloads</b> to confirm real, exploitable "
          "vulnerabilities \u2014 then produces a scored, shareable report. It is built for authorized lab use "
          "against deliberately vulnerable targets such as DVWA.")
    S.append(box([Paragraph(ps, styles["body"])]))
    S.append(Spacer(1, 6))

    # Project scope (two steps)
    S.append(Paragraph(
        "<b>Project scope.</b> &nbsp;<b>Step 1 — Fissure</b> (this submission): the complete deterministic scanner "
        "below. &nbsp;<b>Step 2 — Fissure AI</b> (planned): a Claude-powered agent that drives Fissure as its toolbelt, "
        "chaining and confirming findings autonomously.", styles["body"]))
    S.append(Spacer(1, 8))

    # How it works
    S += section("How It Works  —  one URL in, a scored report out")
    S.append(pipeline())
    S.append(Spacer(1, 3))
    S.append(Paragraph(
        "One scan pipeline: check the target is in scope &#8594; crawl from the URL to harvest injectable inputs "
        "&#8594; fire active payloads at each input &#8594; passively audit headers &#8594; probe for sensitive files "
        "&#8594; score and render JSON + HTML + SARIF. Modules: <b>crawler, sqli, cmdi, xss, traversal, "
        "ssti, cors, redirect, discovery, headers</b>.", styles["body"]))
    S.append(Spacer(1, 7))

    # Detection capabilities
    S += section("Detection Capabilities")
    S.append(detection_table())
    S.append(Spacer(1, 7))

    # Comparison
    S += section("How Fissure Compares to Industry Tools")
    S.append(comparison_table())
    S.append(Spacer(1, 7))

    # Why
    S += section("Why Fissure")
    S.append(why_cols())
    S.append(Spacer(1, 6))

    # Validation strip
    val = ("Verified end-to-end against DVWA running in Docker. Fissure confirmed <b>error-based SQL injection</b>, "
           "<b>time-based blind SQLi</b> (5-second delay) and <b>reflected XSS</b> at low/medium security. Crucially, on "
           "<b>high-security SQLi</b> \u2014 where DVWA uses a parameterized query \u2014 it correctly reports <b>nothing</b>, "
           "demonstrating that it confirms true exploitability rather than pattern-matching. Benchmarked on a "
           "controlled target: <b>precision / recall / F1 = 1.00</b> (9/9, 0 false positives). 38 automated tests pass.")
    S.append(box([Paragraph(val, styles["body"])], bg=colors.HexColor("#eaf5ec")))
    S.append(Spacer(1, 6))

    S.append(HRFlowable(width="100%", thickness=0.6, color=LINE, spaceAfter=4))
    S.append(Paragraph(
        "<b>Tech stack:</b> Python 3.10+ · httpx (async) · Tkinter GUI · PyInstaller · MIT licensed.&nbsp;&nbsp;&nbsp;"
        "<b>Deliverables:</b> source package, CLI, standalone Fissure.exe, JSON + HTML reports, automated tests, bundled VulnLab demo target.",
        styles["foot"]))

    # Keep everything on exactly one page.
    frame_w = A4[0] - 34 * mm
    frame_h = A4[1] - 10 * mm
    doc.build([KeepInFrame(frame_w, frame_h, S, mode="shrink")])
    print("wrote", OUT)


if __name__ == "__main__":
    build()
