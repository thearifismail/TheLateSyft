# TODO: Process all "fixed_states (fixed, not-fixed, wont-fix, unknown)" simultaneously or separately
# The file provides a list based on the number of images scanned.
# Each list element is a dictionary with image repo, tag, vulnerabilties
# Read element based on the "fixed-state" provided.


INPUT_FILE = "/home/aarif/Documents/dev-ws/insights/TheLateSyft/results/host-inventory-vuln-scan.json"

import json
 
# Opening JSON file
with open(INPUT_FILE, 'r') as openfile:
 
    # Reading from json file
    scanned_images = json.load(openfile)
 
# print(scanned_images)
print(f"Type of json object: {type(scanned_images)}")

fixed_cves = []
not_fixed_cves = []
wont_fix_cves = []
unknown_cves = []

total_vulns = 0

for entry in scanned_images:
    vulns = entry.get("vulnerabilities")
    total_vulns += len(vulns)
    print(f"\nNumber of vulnerabilities found: {len(vulns)}")
    print(f"All vulnerabilities counted so far: {total_vulns}")

    fixed= list(filter(lambda person: person['fixed_state'] == 'fixed', vulns))
    not_fixed = list(filter(lambda person: person['fixed_state'] == 'not-fixed', vulns))
    wont_fix = list(filter(lambda person: person['fixed_state'] == 'wont-fix', vulns))
    unknown = list(filter(lambda person: person['fixed_state'] == 'unknown', vulns))

    fixed_cves.extend(fixed)
    not_fixed_cves.extend(not_fixed)
    wont_fix_cves.extend(wont_fix)
    unknown_cves.extend(unknown)

    print (f"Number of fixed: {len(fixed_cves)}")
    print (f"Number of not_fixed: {len(not_fixed_cves)}")
    print (f"Number of wont_fix: {len(wont_fix_cves)}")
    print (f"Number of unknown_cves: {len(unknown_cves)}")

