import sys
sys.path.append("/var/www/checklist_veicular")
from app import app, db
from backend.models import Vehicle, Vistoria

with app.app_context():
    with app.test_request_context():
        # Get actual records from DB to make rendering realistic
        veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()
        registros = Vistoria.query.order_by(Vistoria.id.desc()).limit(80).all()
        
        from flask import render_template
        try:
            html = render_template(
                "vistorias_list.html",
                veiculos=veiculos,
                registros=registros,
                periodo=""
            )
            out_path = "/var/www/checklist_veicular/scratch/rendered_vistorias_list.html"
            with open(out_path, "w") as f:
                f.write(html)
            print("Successfully rendered to:", out_path)
        except Exception as e:
            print("ERROR RENDERING TEMPLATE:", e)
