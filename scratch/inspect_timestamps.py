import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db, GPSLog, agora
from datetime import timedelta

with app.app_context():
    print("=== CHECKING TIMESTAMPS AND LOGS ===")
    current_time = agora()
    print("agora():", current_time)
    
    data_ini = (current_time - timedelta(days=3)).strftime("%Y-%m-%dT00:00")
    data_fim = current_time.strftime("%Y-%m-%dT23:59")
    print(f"Default range: {data_ini} to {data_fim}")
    
    # Let's count logs per vehicle
    for log in GPSLog.query.order_by(GPSLog.timestamp.desc()).limit(10).all():
        print(f"Log ID: {log.id} | Vehicle ID: {log.vehicle_id} | Timestamp: {log.timestamp} | Speed: {log.speed}")
