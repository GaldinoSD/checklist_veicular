import io
import os
import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

def get_easter_date(year):
    a = year % 19
    b = year // 100
    c = year % 100
    d = b // 4
    e = b % 4
    f = (b + 8) // 25
    g = (b - f + 1) // 3
    h = (19 * a + b - d - g + 15) % 30
    i = c // 4
    k = c % 4
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month = (h + l - 7 * m + 114) // 31
    day = ((h + l - 7 * m + 114) % 31) + 1
    return datetime.date(year, month, day)

def format_date_pt(dt, include_year=True):
    PT_WEEKDAYS = ["segunda-feira", "terça-feira", "quarta-feira", "quinta-feira", "sexta-feira", "sábado", "domingo"]
    PT_MONTHS = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"]
    w = PT_WEEKDAYS[dt.weekday()]
    m = PT_MONTHS[dt.month - 1]
    if include_year:
        return f"{w}, {dt.day} de {m} de {dt.year}"
    return f"{w}, {dt.day} de {m}"

def generate_default_annual_data(year):
    # Generates standard schedule structure for a year
    # Saturdays
    saturdays = []
    teams_cycle = ["EQUIPE ROSA", "EQUIPE AZUL", "EQUIPE AMARELA"]
    curr = datetime.date(year, 1, 1)
    team_idx = 0
    while curr.year == year:
        if curr.weekday() == 5: # Saturday
            saturdays.append({
                "date": curr.strftime("%Y-%m-%d"),
                "date_extenso": format_date_pt(curr),
                "team": teams_cycle[team_idx % len(teams_cycle)]
            })
            team_idx += 1
        curr += datetime.timedelta(days=1)

    # Sundays
    sundays = []
    curr = datetime.date(year, 1, 1)
    while curr.year == year:
        if curr.weekday() == 6: # Sunday
            sundays.append({
                "date": curr.strftime("%Y-%m-%d"),
                "date_extenso": format_date_pt(curr),
                "interno": "",
                "externo_1": "",
                "externo_2": ""
            })
        curr += datetime.timedelta(days=1)

    # Holidays
    easter = get_easter_date(year)
    carnaval = easter - datetime.timedelta(days=47)
    adoracao = easter - datetime.timedelta(days=2) # Adoração / Paixão de Cristo
    paixao = easter - datetime.timedelta(days=2)
    corpus = easter + datetime.timedelta(days=60)
    
    holidays_raw = [
        ("Carnaval", carnaval),
        ("Emancipação Municipal", datetime.date(year, 3, 13)),
        ("Adoração a Cristo", easter - datetime.timedelta(days=3)),
        ("Paixão de Cristo", easter - datetime.timedelta(days=2)),
        ("Tiradentes", datetime.date(year, 4, 21)),
        ("São Jorge", datetime.date(year, 4, 23)),
        ("Dia do Trabalhador", datetime.date(year, 5, 1)),
        ("Corpus Christi", corpus),
        ("Independência do Brasil", datetime.date(year, 9, 7)),
        ("Padroeira da Cidade", datetime.date(year, 10, 1)),
        ("NSRª Aparecida", datetime.date(year, 10, 12)),
        ("Finados", datetime.date(year, 11, 2)),
        ("Proclamação da República", datetime.date(year, 11, 15)),
        ("Consciência Negra", datetime.date(year, 11, 20)),
        ("Natal", datetime.date(year, 12, 25)),
        ("Ano-Novo", datetime.date(year + 1, 1, 1)),
    ]

    holidays = []
    for name, dt in holidays_raw:
        is_sun = dt.weekday() == 6
        holidays.append({
            "name": name,
            "date": dt.strftime("%Y-%m-%d"),
            "date_extenso": f"{name}, {format_date_pt(dt)}",
            "interno": "",
            "externo_1": "",
            "externo_2": "",
            "prevalecer_domingo": is_sun
        })

    return {
        "year": year,
        "saturdays": saturdays,
        "sundays": sundays,
        "holidays": holidays
    }

def build_pdf_annual_schedule(output_path, year, data, logo_path=None):
    # A4: 595.27 x 841.89 points
    # Printable width: 595.27 - 20 = 575.27
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=6*mm,
        rightMargin=6*mm,
        topMargin=6*mm,
        bottomMargin=6*mm
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    style_year = ParagraphStyle(
        name="YearTitle",
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        alignment=1, # Center
        textColor=colors.HexColor("#0284C7")
    )

    style_sat_date = ParagraphStyle(
        name="SatDate",
        fontName="Helvetica-Oblique",
        fontSize=6.5,
        leading=8,
        alignment=0, # Left
        textColor=colors.HexColor("#0f172a")
    )

    style_sat_team = ParagraphStyle(
        name="SatTeam",
        fontName="Helvetica-Bold",
        fontSize=6.5,
        leading=8,
        alignment=1, # Center
        textColor=colors.HexColor("#0f172a")
    )

    style_sun_date = ParagraphStyle(
        name="SunDate",
        fontName="Helvetica-Oblique",
        fontSize=6.5,
        leading=8,
        alignment=0,
        textColor=colors.HexColor("#0f172a")
    )

    style_sun_tech = ParagraphStyle(
        name="SunTech",
        fontName="Helvetica",
        fontSize=6.5,
        leading=8,
        alignment=1,
        textColor=colors.HexColor("#0f172a")
    )

    style_header_main = ParagraphStyle(
        name="HeaderMain",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=10,
        alignment=1,
        textColor=colors.black
    )

    style_header_sub = ParagraphStyle(
        name="HeaderSub",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        alignment=1,
        textColor=colors.black
    )

    style_holiday_name = ParagraphStyle(
        name="HolidayName",
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        alignment=0,
        textColor=colors.black
    )

    style_holiday_tech = ParagraphStyle(
        name="HolidayTech",
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        alignment=1,
        textColor=colors.black
    )

    style_prevalecer = ParagraphStyle(
        name="Prevalecer",
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        alignment=1,
        textColor=colors.white
    )

    # PAGE 1: Header (Year + Logo)
    header_data = [
        [
            "",
            Paragraph(f"<b>{year}</b>", style_year),
            RLImage(logo_path, width=32*mm, height=12*mm) if (logo_path and os.path.exists(logo_path)) else ""
        ]
    ]
    header_table = Table(header_data, colWidths=[160, 240, 160], rowHeights=[14*mm])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (1,0), (1,0), 'CENTER'),
        ('ALIGN', (2,0), (2,0), 'RIGHT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
    ]))

    # PAGE 1 TABLES:
    saturdays = data.get("saturdays", [])
    sundays = data.get("sundays", [])
    
    # 1. Saturday Table Data
    sat_data = [
        [Paragraph("ESCALA DE SÁBADO", style_header_main), ""],
        [Paragraph("SÁBADO", style_header_sub), Paragraph("EQUIPE", style_header_sub)]
    ]
    sat_styles = [
        ('SPAN', (0,0), (1,0)),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.7, colors.black),
        ('TOPPADDING', (0,0), (-1,-1), 1.2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 1.2),
        ('LEFTPADDING', (0,0), (-1,-1), 2.5),
        ('RIGHTPADDING', (0,0), (-1,-1), 2.5),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F8FAFC")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#F1F5F9")),
    ]

    for i, s in enumerate(saturdays):
        row_idx = len(sat_data)
        team_str = s.get("team", "")
        # Highlight team color text or subtle background
        team_color_hex = "#0f172a"
        if "ROSA" in team_str.upper():
            team_color_hex = "#db2777"
        elif "AZUL" in team_str.upper():
            team_color_hex = "#0284c7"
        elif "AMAREL" in team_str.upper():
            team_color_hex = "#ca8a04"
        elif "VERD" in team_str.upper():
            team_color_hex = "#16a34a"

        t_style = ParagraphStyle(
            f"SatT_{row_idx}",
            parent=style_sat_team,
            textColor=colors.HexColor(team_color_hex)
        )
        sat_data.append([
            Paragraph(s.get("date_extenso", s.get("date", "")), style_sat_date),
            Paragraph(team_str.upper(), t_style)
        ])

    sat_table = Table(sat_data, colWidths=[105, 95])
    sat_table.setStyle(TableStyle(sat_styles))

    # 2. Sunday Table Data
    sun_data = [
        [Paragraph("PLANTÃO DE DOMINGO", style_header_main), "", "", ""],
        [Paragraph("DOMINGO", style_header_sub), Paragraph("INTERNO", style_header_sub), Paragraph("EXTERNO", style_header_sub), Paragraph("EXTERNO", style_header_sub)]
    ]
    sun_styles = [
        ('SPAN', (0,0), (3,0)),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.7, colors.black),
        ('TOPPADDING', (0,0), (-1,-1), 1.2),
        ('BOTTOMPADDING', (0,0), (-1,-1), 1.2),
        ('LEFTPADDING', (0,0), (-1,-1), 2),
        ('RIGHTPADDING', (0,0), (-1,-1), 2),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F8FAFC")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#F1F5F9")),
    ]

    for i, s in enumerate(sundays):
        row_idx = len(sun_data)
        sun_data.append([
            Paragraph(s.get("date_extenso", s.get("date", "")), style_sun_date),
            Paragraph(s.get("interno", "") or "", style_sun_tech),
            Paragraph(s.get("externo_1", "") or "", style_sun_tech),
            Paragraph(s.get("externo_2", "") or "", style_sun_tech)
        ])
        if "reginaldo" in (s.get("externo_2", "") or "").lower() or "borges" in (s.get("externo_2", "") or "").lower():
            # Match subtle colors if needed
            pass

    sun_table = Table(sun_data, colWidths=[105, 78, 85, 92])
    sun_table.setStyle(TableStyle(sun_styles))

    # Combine side-by-side in container table
    page1_container = Table(
        [[sat_table, "", sun_table]],
        colWidths=[200, 5, 360]
    )
    page1_container.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('TOPPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 0),
    ]))

    # PAGE 2: Holidays Table
    holidays = data.get("holidays", [])
    hol_data = [
        [Paragraph("TABELA DE FERIADOS", style_header_main), "", "", ""],
        [Paragraph("FERIADO", style_header_sub), Paragraph("INTERNO", style_header_sub), Paragraph("EXTERNO", style_header_sub), Paragraph("EXTERNO", style_header_sub)]
    ]
    hol_styles = [
        ('SPAN', (0,0), (3,0)),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.7, colors.black),
        ('TOPPADDING', (0,0), (-1,-1), 3.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3.5),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F8FAFC")),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#F1F5F9")),
    ]

    for h in holidays:
        row_idx = len(hol_data)
        if h.get("prevalecer_domingo"):
            hol_data.append([
                Paragraph(h.get("date_extenso", h.get("name", "")), style_holiday_name),
                Paragraph("PREVALECERÁ O PLANTÃO DE DOMINGO", style_prevalecer),
                "",
                ""
            ])
            hol_styles.append(('SPAN', (1, row_idx), (3, row_idx)))
            hol_styles.append(('BACKGROUND', (1, row_idx), (3, row_idx), colors.HexColor("#475569")))
        else:
            hol_data.append([
                Paragraph(h.get("date_extenso", h.get("name", "")), style_holiday_name),
                Paragraph(h.get("interno", "") or "", style_holiday_tech),
                Paragraph(h.get("externo_1", "") or "", style_holiday_tech),
                Paragraph(h.get("externo_2", "") or "", style_holiday_tech)
            ])

    hol_table = Table(hol_data, colWidths=[205, 120, 120, 120])
    hol_table.setStyle(TableStyle(hol_styles))

    elements = [
        header_table,
        Spacer(1, 2*mm),
        page1_container,
        PageBreak(),
        header_table,
        Spacer(1, 4*mm),
        hol_table
    ]

    doc.build(elements)
    print(f"PDF generated successfully at {output_path}!")

if __name__ == "__main__":
    data = generate_default_annual_data(2026)
    build_pdf_annual_schedule(
        "scratch/cronograma_anual_2026.pdf",
        2026,
        data,
        logo_path="/var/www/checklist_veicular/frontend/static/uploads/layout/layout_pdf_logo_6cece00e.png"
    )
