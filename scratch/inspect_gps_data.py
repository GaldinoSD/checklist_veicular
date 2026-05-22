import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db, Vehicle, GPSDevice, GPSLog, SystemConfig

with app.app_context():
    print("=== INSPECTING TELEMETRY/GPS ===")
    config = SystemConfig.query.first()
    if config:
        print(f"Simulator Active: {config.simulator_active}")
        print(f"Speed Limit: {config.speed_limit}")
        print(f"Ignition Alert: {config.ignition_alert}")
    else:
        print("No SystemConfig found!")
        
    v_count = Vehicle.query.count()
    d_count = GPSDevice.query.count()
    l_count = GPSLog.query.count()
    print(f"Vehicles in DB: {v_count}")
    print(f"GPS Devices in DB: {d_count}")
    print(f"GPS Logs in DB: {l_count}")
    
    print("\n--- Vehicles ---")
    for v in Vehicle.query.all():
        device = GPSDevice.query.filter_by(vehicle_id=v.id).first()
        imei = device.imei if device else "NO_DEVICE"
        logs_count = GPSLog.query.filter_by(vehicle_id=v.id).count()
        print(f"Vehicle {v.id}: {v.plate} - {v.model} (Status: {v.status}) | Device: {imei} | Logs count: {logs_count}")
        
    print("\n--- GPS Devices ---")
    for d in GPSDevice.query.all():
        print(f"Device IMEI: {d.imei} | Model: {d.model} | Vehicle ID: {d.vehicle_id} | Active: {d.is_active}")
