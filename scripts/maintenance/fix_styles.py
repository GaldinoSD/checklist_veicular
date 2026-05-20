import sys
import os

# Adiciona o diretório raiz ao path do Python (para robustez)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../app.py'))

with open(app_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Substitui as definições de estilos problemáticas
old_styles = """    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Title", parent=styles["Heading1"], alignment=1, spaceAfter=20))
    styles.add(ParagraphStyle(name="SubTitle", parent=styles["Heading2"], spaceAfter=10, textColor=colors.HexColor("#1F3C78")))
    styles.add(ParagraphStyle(name="NormalText", parent=styles["Normal"], leading=12))"""

new_styles = """    styles = getSampleStyleSheet()
    # Criar estilos apenas se não existirem no stylesheet compartilhado
    if "ReportTitle" not in styles:
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Heading1"], alignment=1, spaceAfter=20))
    if "ReportSubTitle" not in styles:
        styles.add(ParagraphStyle(name="ReportSubTitle", parent=styles["Heading2"], spaceAfter=10, textColor=colors.HexColor("#1F3C78")))
    if "ReportNormal" not in styles:
        styles.add(ParagraphStyle(name="ReportNormal", parent=styles["Normal"], leading=12))"""

content = content.replace(old_styles, new_styles)

# Atualiza os usos dos estilos
content = content.replace('styles["Title"]', 'styles["ReportTitle"]')
content = content.replace('styles["SubTitle"]', 'styles["ReportSubTitle"]')
content = content.replace('styles["NormalText"]', 'styles["ReportNormal"]')

with open(app_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Estilos corrigidos com sucesso.")
