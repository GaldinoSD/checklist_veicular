import sys
from datetime import datetime, timedelta
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db, GPSLog

with app.app_context():
    print("=== TESTING DATABASE QUERIES ===")
    v_id = 3
    data_ini_str = "2026-05-19T00:00"
    data_fim_str = "2026-05-23T23:59"
    
    # Test query using string comparisons
    logs_str = GPSLog.query.filter(
        GPSLog.vehicle_id == v_id,
        GPSLog.timestamp >= data_ini_str,
        GPSLog.timestamp <= data_fim_str
    ).all()
    print(f"Query with STRING comparing: Found {len(logs_str)} logs")
    
    # Test query using parsed datetime objects
    dt_ini = datetime.strptime(data_ini_str, "%Y-%m-%dT%H:%M")
    dt_fim = datetime.strptime(data_fim_str, "%Y-%m-%dT%H:%M")
    logs_dt = GPSLog.query.filter(
        GPSLog.vehicle_id == v_id,
        GPSLog.timestamp >= dt_ini,
        GPSLog.timestamp <= dt_fim
    ).all()
    print(f"Query with DATETIME object: Found {len(logs_dt)} logs")
    
    # Let's inspect some log timestamps
    first_log = GPSLog.query.filter_by(vehicle_id=v_id).first()
    if first_log:
        print(f"First log timestamp type: {type(first_log.timestamp)} value: {first_log.timestamp}")
