import sys

path = '/var/www/checklist_veicular/app.py'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_func = """def generate_consolidated_report(vehicle, start_date, end_date):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    
    # timezone seguro
    try:
        from zoneinfo import ZoneInfo
        BRT = ZoneInfo("America/Sao_Paulo")
    except Exception:
        from datetime import timezone, timedelta
        BRT = timezone(timedelta(hours=-3))

    # Coleta de dados
    checklists = (Checklist.query
                  .filter(Checklist.vehicle_id == vehicle.id, 
                          Checklist.date >= start_date, 
                          Checklist.date <= end_date)
                  .order_by(Checklist.date.asc())
                  .all())

    if not checklists:
        return None

    total_checklists = len(checklists)
    km_inicial = checklists[0].km if checklists else 0
    km_final = checklists[-1].km if checklists else 0
    km_rodado = km_final - km_inicial
    tecnicos = sorted(list(set([c.technician for c in checklists if c.technician])))
    
    # Avarias no período
    avarias = (AvariaOS.query
               .filter(AvariaOS.vehicle_id == vehicle.id, 
                       AvariaOS.data_abertura >= start_date, 
                       AvariaOS.data_abertura <= end_date)
               .all())

    # Configuração do PDF
    RELATORIOS_DIR.mkdir(parents=True, exist_ok=True)
    dt_str = start_date.strftime("%Y%m%d") + "_a_" + end_date.strftime("%Y%m%d")
    filename = f"consolidado_{vehicle.plate}_{dt_str}.pdf"
    out_path = RELATORIOS_DIR / filename

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Title", parent=styles["Heading1"], alignment=1, spaceAfter=20))
    styles.add(ParagraphStyle(name="SubTitle", parent=styles["Heading2"], spaceAfter=10, textColor=colors.HexColor("#1F3C78")))
    styles.add(ParagraphStyle(name="NormalText", parent=styles["Normal"], leading=12))

    doc = SimpleDocTemplate(str(out_path), pagesize=A4)
    elements = []

    # Logo e Cabeçalho
    if LOGO_PATH.exists():
        try:
            elements.append(RLImage(str(LOGO_PATH), width=40*mm, height=20*mm))
        except:
            pass
    
    elements.append(Paragraph(f"<b>Relatório Consolidado de Frota</b>", styles["Title"]))
    elements.append(Paragraph(f"Veículo: {vehicle.brand} {vehicle.model} - Placa: {vehicle.plate}", styles["SubTitle"]))
    elements.append(Paragraph(f"Período: {start_date.strftime('%d/%m/%Y')} até {end_date.strftime('%d/%m/%Y')}", styles["NormalText"]))
    elements.append(Spacer(1, 10))

    # Tabela de Resumo
    elements.append(Paragraph("<b>Resumo de Utilização</b>", styles["SubTitle"]))
    resumo_data = [
        ["Total de Checklists", str(total_checklists)],
        ["KM Inicial", f"{km_inicial} km"],
        ["KM Final", f"{km_final} km"],
        ["Total Rodado", f"{km_rodado} km"],
        ["Técnicos Atuantes", ", ".join(tecnicos) if tecnicos else "Não informado"]
    ]
    t_resumo = Table(resumo_data, colWidths=[60*mm, 100*mm])
    t_resumo.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#F0F0F0")),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    elements.append(t_resumo)
    elements.append(Spacer(1, 15))

    # Tabela de Histórico de Checklists
    elements.append(Paragraph("<b>Histórico de Checklists</b>", styles["SubTitle"]))
    hist_data = [["Data", "Técnico", "KM", "Status"]]
    for c in checklists:
        hist_data.append([
            c.date.strftime("%d/%m/%Y %H:%M"),
            c.technician or "-",
            str(c.km),
            c.status
        ])
    t_hist = Table(hist_data, colWidths=[40*mm, 60*mm, 30*mm, 30*mm])
    t_hist.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1F3C78")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F9F9F9")]),
    ]))
    elements.append(t_hist)
    
    if avarias:
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("<b>Avarias / Ordens de Serviço</b>", styles["SubTitle"]))
        av_data = [["Data", "Descrição", "Gravidade", "Status"]]
        for a in avarias:
            av_data.append([
                a.data_abertura.strftime("%d/%m/%Y") if a.data_abertura else "-",
                a.descricao[:50] + "..." if len(a.descricao) > 50 else a.descricao,
                a.gravidade,
                a.status
            ])
        t_av = Table(av_data, colWidths=[30*mm, 70*mm, 30*mm, 30*mm])
        t_av.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#B22222")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        elements.append(t_av)

    doc.build(elements)
    return filename
"""

# Encontra a linha que começa com def generate_consolidated_report
for i, line in enumerate(lines):
    if line.startswith('def generate_consolidated_report'):
        # Substitui a linha e a seguinte (pass)
        lines[i:i+2] = [new_func + '\n']
        break

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print("Função atualizada com sucesso.")
