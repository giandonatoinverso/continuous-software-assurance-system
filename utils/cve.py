import json
import csv


class CveUtils:
    def __init__(self):
        pass

    def sort_severity(self, severity):
        severity_order = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "unknown": 1
        }
        return severity_order.get(severity.lower(), 0)

    def generate_html_table(self, data):
        sorted_data = sorted(data.items(), key=lambda x: self.sort_severity(x[1]["Details"]["Severity"]), reverse=True)
        table_html = "<style>"
        table_html += "table {font-family: Arial, sans-serif; border-collapse: collapse; width: 100%;}"
        table_html += "td, th {border: 1px solid #dddddd; text-align: left; padding: 8px;}"
        table_html += "tr:nth-child(even) {background-color: #f2f2f2;}"
        table_html += "th {background-color: #dddddd;}"
        table_html += "</style>"
        table_html += "<table border='1'>"
        table_html += "<tr><th>CVE</th><th>CWE</th><th>Targets</th><th>Title</th><th>Severity</th><th>V2 average " \
                      "score</th><th>V3 average score</th></tr> "

        for cve, info in sorted_data:
            targets = "<br>".join(info["Targets"])
            cwe = "<br>".join(info["Details"]["CWE"])
            title = info["Details"].get("Title", "")
            severity = info["Details"]["Severity"]
            severity = str(severity).lower()

            v2_score = info["Details"]["V2Score"]
            v3_score = info["Details"]["V3Score"]

            table_html += f"<tr><td style='white-space:nowrap'>{cve}</td><td style='white-space:nowrap'>{cwe}</td>"\
                          f"<td style='white-space:nowrap'>{targets}</td><td>{title}</td><td>{severity}</td><td>{v2_score}"\
                          f"</td><td>{v3_score}</td></tr>"
        table_html += "</table>"
        return table_html

    def read_json_file(self, file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data

    def json_to_html(self, json_path, output_path):
        data = self.read_json_file(json_path)

        html_content = self.generate_html_table(data)

        with open(output_path, 'w') as f:
            f.write(html_content)

    @DeprecationWarning
    def json_merge_results(self, trivy_results_file, grype_results_file, output_file):
        with open(trivy_results_file, 'r') as trivy_file:
            trivy_results = json.load(trivy_file)

        with open(grype_results_file, 'r') as grype_file:
            grype_results = json.load(grype_file)

        merged_json = {}

        for cve_id, trivy_data in trivy_results.items():
            if cve_id in grype_results:
                targets = trivy_data.get('Targets', grype_results[cve_id].get('Targets', []))
                title = trivy_data.get('Details', {}).get('Title', '')
                cvss_trivy = trivy_data['Details'].get('CVSS', {})
                cvss_grype = grype_results[cve_id]['Details'].get('CVSS', [])
                cvss = {
                    'trivy': cvss_trivy,
                    'grype': cvss_grype
                }
            else:
                targets = trivy_data.get('Targets', [])
                title = trivy_data['Details'].get('Title', '')
                cvss = {
                    'trivy': trivy_data['Details'].get('CVSS', {}),
                    'grype': {}
                }

            merged_json[cve_id] = {
                'Targets': targets,
                'Details': {
                    'Title': title,
                    'Description': trivy_data['Details']['Description'],
                    'Severity': trivy_data['Details']['Severity'],
                    'VendorSeverity': trivy_data['Details'].get('VendorSeverity', {}),
                    'CWE': trivy_data['Details']['CWE'],
                    'CVSS': cvss
                }
            }

        for cve_id, grype_data in grype_results.items():
            if cve_id not in merged_json:
                merged_json[cve_id] = {
                    'Targets': grype_data.get('Targets', []),
                    'Details': {
                        'Title': '',
                        'Description': grype_data['Details']['Description'],
                        'Severity': grype_data['Details']['Severity'],
                        'VendorSeverity': {},
                        'CWE': {},
                        'CVSS': {
                            'trivy': {},
                            'grype': grype_data['Details'].get('CVSS', {})
                        }
                    }
                }

        with open(output_file, 'w') as merged_file:
            json.dump(merged_json, merged_file, indent=4)

    @DeprecationWarning
    def write_csv_from_json(self, json_file_path, csv_file_path):
        with open(json_file_path, mode='r') as json_file:
            json_data = json.load(json_file)

        with open(csv_file_path, mode='w', newline='') as file:
            writer = csv.writer(file)

            writer.writerow(['CVE', 'Targets', 'Severity', 'VendorSeverity'])

            for cve, data in json_data.items():
                targets = ", ".join(data['Targets'])
                severity = data['Details']['Severity']

                vendor_severity = ""
                for vendor, value in data['Details']['VendorSeverity'].items():
                    vendor_severity += f"{vendor}: {value}, "

                vendor_severity = vendor_severity[:-2]

                writer.writerow([cve, targets, severity, vendor_severity])

    @DeprecationWarning
    def get_cvss_fs(info):
        v2_score = None
        if "CVSS" in info["Details"]:
            cvss_data = info["Details"]["CVSS"]
            trivy_v2_score = None

            for vendor_data in cvss_data.values():
                if "V2Score" in vendor_data:
                    trivy_v2_score = vendor_data["V2Score"]
                    break

            if trivy_v2_score is not None:
                v2_score = trivy_v2_score

        v3_scores = []
        if "CVSS" in info["Details"]:
            cvss_data = info["Details"]["CVSS"]

            for vendor_data in cvss_data.values():
                if "V3Score" in vendor_data:
                    v3_scores.append(vendor_data["V3Score"])

        if len(v3_scores) != 0:
            v3_score = sum(v3_scores) / len(v3_scores)
        else:
            v3_score = None

        return v2_score, v3_score

    @DeprecationWarning
    def get_cvss_docker(info):
        v2_score = None
        if "CVSS" in info["Details"]:
            trivy_v2_score = next((sub.get("V2Score") for sub in info["Details"]["CVSS"].get("trivy", {}).values()),
                                  None)
            grype_base_score = next(
                (item["metrics"]["baseScore"] for item in info["Details"]["CVSS"].get("grype", []) if
                 item["version"] == "2.0"), None)
            if trivy_v2_score is not None:
                v2_score = trivy_v2_score
            elif grype_base_score is not None:
                v2_score = grype_base_score

        v3_scores = []
        if "CVSS" in info["Details"]:
            trivy_v3_score = next((sub.get("V3Score") for sub in info["Details"]["CVSS"].get("trivy", {}).values()),
                                  None)
            if trivy_v3_score is not None:
                v3_scores.append(trivy_v3_score)

            grype_v3_scores = [item["metrics"]["baseScore"] for item in info["Details"]["CVSS"].get("grype", []) if
                               item["version"] == "3.1"]
            v3_scores.extend(grype_v3_scores)

        if len(v3_scores) != 0:
            v3_score = sum(v3_scores) / len(v3_scores)
        else:
            v3_score = None

        return v2_score, v3_score