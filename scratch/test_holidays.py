import sys
import holidays
br_holidays = holidays.Brazil(subdiv="RJ", years=2026)
print("Holidays generated for RJ, 2026:")
for date, name in sorted(br_holidays.items()):
    print(f"  {date}: {name}")
