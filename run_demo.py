import json
from airlock.scenarios import email_exfiltration, search_exfiltration
for scenario in (email_exfiltration, search_exfiltration):
    for mode in ("baseline", "airlock"):
        result = scenario(mode)
        print(json.dumps({k:v for k,v in result.items() if k != "events"}, indent=2))
