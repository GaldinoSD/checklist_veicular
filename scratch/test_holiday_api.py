import sys
import json
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db

print("Validating scales API endpoint with holiday injection...")
client = app.test_client()

with app.app_context():
    # Simulate a request from FullCalendar for 2026-06-01 to 2026-06-30
    # Seropédica municipal holiday is June 13th (Santo Antônio).
    response = client.get('/api/gestao/escalas?start=2026-06-01Z&end=2026-06-30Z')
    print("Response status code:", response.status_code)
    if response.status_code == 200:
        data = response.get_json()
        print(f"Total events returned: {len(data)}")
        feriados = [e for e in data if e['id'].startswith('feriado_')]
        print(f"Total holidays returned: {len(feriados)}")
        for f in feriados:
            print(f"  Holiday Event: {f['start']} - {f['title']} (color: {f['color']})")
    else:
        print("Failed to get scales with status", response.status_code)
