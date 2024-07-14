import json


class BanditParser:
    def __init__(self, report_file_path):
        self.report = report_file_path
        self.clean_document()

    def clean_document(self):
        with open(self.report, "r") as file:
            json_content = json.load(file)

        if "errors" in json_content:
            del json_content["errors"]

        if "generated_at" in json_content:
            del json_content["generated_at"]

        if "metrics" in json_content:
            del json_content["metrics"]

        with open(self.report, "w") as file:
            json.dump(json_content, file, indent=4)

    def get_content(self):
        with open(self.report, "r") as file:
            json_content = json.load(file)

            return json_content

    def print_json(self, json_file):
        print(json.dumps(json_file, indent=4))
        print("\n")

    def cwe_targets_aggregation(self, json_file=None):
        if json_file is None:
            json_file = self.report

        with open(json_file, "r") as file:
            data = json.load(file)

        new_data = {"Issues": []}
        cwe_mapping = {}

        for issue in data["results"]:
            cwe_id = issue["issue_cwe"]["id"]
            file = issue["filename"]
            if cwe_id not in cwe_mapping:
                new_issue = {
                    "CWE": issue["issue_cwe"]["id"],
                    "Targets": {file: [{"line": issue["line_number"], "column": issue["col_offset"]}]},
                    "severity": issue["issue_severity"],
                    "confidence": issue["issue_confidence"],
                    "details": issue["issue_text"]
                }
                new_data["Issues"].append(new_issue)
                cwe_mapping[cwe_id] = len(new_data["Issues"]) - 1
            else:
                index = cwe_mapping[cwe_id]
                if file in new_data["Issues"][index]["Targets"]:
                    new_data["Issues"][index]["Targets"][file].append(
                        {"line": issue["line_number"], "column": issue["col_offset"]})
                else:
                    new_data["Issues"][index]["Targets"][file] = [{"line": issue["line_number"], "column": issue["col_offset"]}]

        with open(json_file, "w") as file:
            json.dump(new_data, file, indent=4)

        return new_data

    def sort_key(self, issue):
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1
        }
        confidence_order = {
            "high": 3,
            "medium": 2,
            "low": 1
        }

        severity_value = severity_order.get(issue["severity"].lower(), 0)
        confidence_value = confidence_order.get(issue["confidence"].lower(), 0)
        return severity_value, confidence_value

    def generate_html_table(self, issues):
        sorted_issues = sorted(issues, key=self.sort_key, reverse=True)
        table_html = "<style>"
        table_html += "table {font-family: Arial, sans-serif; border-collapse: collapse; width: 100%;}"
        table_html += "td, th {border: 1px solid #dddddd; text-align: left; padding: 8px;}"
        table_html += "tr:nth-child(even) {background-color: #f2f2f2;}"
        table_html += "th {background-color: #dddddd;}"
        table_html += "</style>"
        table_html += "<table border='1'>"
        table_html += "<tr><th>CWE</th><th>Severity</th><th>Confidence</th><th>File</th><th>Line/Column</th><th>Details</th></tr>"

        for issue in sorted_issues:
            first_target = True
            target_entries = []
            for file_path, entries in issue["Targets"].items():
                #filename = file_path.split("/")[-1]
                filename = file_path
                line_column = "<br>".join([f"{entry['line']}:{entry['column']}" for entry in entries])
                target_entries.append((filename, line_column))

            total_targets = len(target_entries)
            if total_targets > 0:
                first = True
                for filename, line_column in target_entries:
                    if first:
                        table_html += f"<tr><td rowspan='{total_targets}'>{issue['CWE']}</td><td rowspan='{total_targets}'>{issue['severity'].lower()}</td><td rowspan='{total_targets}'>{issue['confidence'].lower()}</td>"
                        table_html += f"<td>{filename}</td><td>{line_column}</td><td rowspan='{total_targets}'>{issue['details']}</td></tr>"
                        first = False
                    else:
                        table_html += f"<tr><td>{filename}</td><td>{line_column}</td></tr>"
        table_html += "</table>"
        return table_html


    def json_to_html(self, json_path, output_path):
        with open(json_path, 'r') as f:
            data = json.load(f)

        html_content = self.generate_html_table(data["Issues"])

        with open(output_path, 'w') as f:
            f.write(html_content)
