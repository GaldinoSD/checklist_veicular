import sys
import os
# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, SystemConfig, db
with app.app_context():
    config = SystemConfig.query.first()
    if config:
        print(f"Start Date: {config.scale_start_date}, Rotation Order: {config.scale_rotation_order}")
    else:
        print("No config found")
