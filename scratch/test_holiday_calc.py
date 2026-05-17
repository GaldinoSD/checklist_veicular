from datetime import datetime, date, timedelta
import holidays

start_str = "2026-06-01Z"
end_str = "2026-06-30Z"

start_date = datetime.fromisoformat(start_str.replace("Z", "")).date()
end_date = datetime.fromisoformat(end_str.replace("Z", "")).date()

events = []
years = list(range(start_date.year, end_date.year + 1))
h_dict = holidays.Brazil(subdiv="RJ", years=years)

for y in years:
    # 1. Santo Antônio (June 13th)
    h_dict[date(y, 6, 13)] = "Santo Antônio (Padroeiro de Seropédica)"
    
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
    h_dict[corpus_christi] = "Corpus Christi (Seropédica/RJ)"
    
    # 3. Emancipação de Seropédica (12 de Outubro)
    h_dict[date(y, 10, 12)] = "Nossa Senhora Aparecida / Emancipação de Seropédica"

for h_date, h_name in h_dict.items():
    if start_date <= h_date <= end_date:
        events.append({
            "id": f"feriado_{h_date.isoformat()}",
            "title": f"🎉 Feriado: {h_name}",
            "start": h_date.isoformat(),
            "allDay": True,
            "color": "#F43F5E",
            "extendedProps": {
                "type": "feriado",
                "name": h_name
            }
        })

print(f"Calculated {len(events)} holidays between {start_date} and {end_date}:")
for e in events:
    print(f"  {e['start']}: {e['title']} - Color: {e['color']}")
