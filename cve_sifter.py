import json
import logging
from os.path import exists


class CVESifter:
    def __init__(self, input_file, results_dir):
        if not exists(input_file):
            raise FileNotFoundError(f"Input file, {input_file}, not found")
        
        self.input_file = input_file
        self.results_dir = results_dir

        # known CVE types,per grype
        self.fixed_cves = []
        self.not_fixed_cves = []
        self.wont_fix_cves = []
        self.unknown_cves = []

    # At the mement, issues are not separated by services or deployments?  Should they be?
    def sift_cves(self):
        with open(self.input_file, 'r') as openfile:
            scanned_images = json.load(openfile)
        
        # logging.info(scanned_images)
        logging.info(f"Type of json object: {type(scanned_images)}")

        total_vulns = 0

        for entry in scanned_images:
            vulns = entry.get("vulnerabilities")
            total_vulns += len(vulns)

            fixed= list(filter(lambda person: person['fixed_state'] == 'fixed', vulns))
            not_fixed = list(filter(lambda person: person['fixed_state'] == 'not-fixed', vulns))
            wont_fix = list(filter(lambda person: person['fixed_state'] == 'wont-fix', vulns))
            unknown = list(filter(lambda person: person['fixed_state'] == 'unknown', vulns))

            # append cves for different images
            self.fixed_cves.extend(fixed)
            self.not_fixed_cves.extend(not_fixed)
            self.wont_fix_cves.extend(wont_fix)
            self.unknown_cves.extend(unknown)

        with open(f"{self.results_dir}/fixed_cves.json", "w") as of:
            for cve in self.fixed_cves:
                json.dump(cve, of, indent=4)

        with open(f"{self.results_dir}/not_fixed_cves.json", "w") as of:
            for cve in self.not_fixed_cves:
                json.dump(cve, of, indent=4)

        with open(f"{self.results_dir}/wont_fix_cves.json", "w") as of:
            for cve in self.wont_fix_cves:
                json.dump(cve, of, indent=4)

        with open(f"{self.results_dir}/unknown_cves.json", "w") as of:
            for cve in self.unknown_cves:
                json.dump(cve, of, indent=4)

        return total_vulns, self.fixed_cves, self.not_fixed_cves, self.wont_fix_cves, self.unknown_cves

    # TODO test what duplicate does when a cves list is empty
    def remove_duplicates(self):
        self.fixed_cves = [*set(self.fixed_cves)]
        self.not_fixed_cves = [*set(self.not_fixed_cves)]
        self.wont_fix_cves = [*set(self.wont_fix_cves)]
        self.unknown_cves = [*set(self.unknown_cves)]

        return self.fixed_cves, self.not_fixed_cves, self.wont_fix_cves, self.unknown_cves
