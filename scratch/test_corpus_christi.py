import sys
import holidays
# Let's inspect all holidays generated for 2026 including optional ones
br = holidays.Brazil(subdiv="RJ", years=2026)
print("Corpus Christi in br?", any("Corpus" in name for name in br.values()))
for date, name in sorted(br.items()):
    print(f"  {date}: {name}")
