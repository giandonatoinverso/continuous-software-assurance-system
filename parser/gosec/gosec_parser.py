import json


class GosecParser:
    def __init__(self, report_file_path):
        self.report = report_file_path
        self.remove_golang_errors()

    def remove_golang_errors(self):
        with open(self.report, "r") as file:
            json_content = json.load(file)

        if "Golang errors" in json_content:
            del json_content["Golang errors"]

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
        with open(self.report, "r") as file:
            data = json.load(file)

        new_data = {"Issues": []}
        cwe_mapping = {}

        for issue in data["Issues"]:
            cwe_id = issue["cwe"]["id"]
            file = issue["file"]
            if cwe_id not in cwe_mapping:
                new_issue = {
                    "CWE": issue["cwe"]["id"],
                    "Targets": {file: [{"line": issue["line"], "column": issue["column"]}]},
                    "severity": issue["severity"],
                    "confidence": issue["confidence"],
                    "details": issue["details"]
                }
                new_data["Issues"].append(new_issue)
                cwe_mapping[cwe_id] = len(new_data["Issues"]) - 1
            else:
                index = cwe_mapping[cwe_id]
                if file in new_data["Issues"][index]["Targets"]:
                    new_data["Issues"][index]["Targets"][file].append(
                        {"line": issue["line"], "column": issue["column"]})
                else:
                    new_data["Issues"][index]["Targets"][file] = [{"line": issue["line"], "column": issue["column"]}]

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
