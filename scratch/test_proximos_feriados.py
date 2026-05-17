import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db

print("Testing proximos_feriados local execution...")
with app.app_context():
    # Let's simulate calling the endpoint logic directly
    from datetime import date, datetime, timedelta
    import holidays
    
    today = date.today()
    years = [today.year, today.year + 1]
    h_dict = holidays.Brazil(subdiv="RJ", years=years)
    
    # Feriados Municipais de Seropédica, RJ
    for y in years:
        # 1. Santo Antônio (13 de Junho)
        h_dict[date(y, 6, 13)] = "Santo Antônio (Padroeiro)"
        
        # 2. Corpus Christi (60 dias após a Páscoa)
        a = y % 19
        b = y // 100
        c = y % 100
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
        easter_date = date(y, month, day)
        corpus_christi = easter_date + timedelta(days=60)
        h_dict[corpus_christi] = "Corpus Christi"
        
        # 3. Emancipação de Seropédica (12 de Outubro)
        h_dict[date(y, 10, 12)] = "N. Sra Aparecida / Emancipação"

    upcoming = []
    for h_date, h_name in sorted(h_dict.items()):
        if h_date >= today:
            days_pt = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
            day_name = days_pt[h_date.weekday()]
            upcoming.append({
                "date": h_date.isoformat(),
                "name": h_name,
                "day_name": day_name,
                "display_date": h_date.strftime("%d/%m")
            })
            if len(upcoming) >= 6:
                break
                
    print(f"Success! Found {len(upcoming)} upcoming holidays starting from {today}:")
    for u in upcoming:
        print(f"  {u['display_date']} ({u['day_name']}): {u['name']} - ISO Date: {u['date']}")
