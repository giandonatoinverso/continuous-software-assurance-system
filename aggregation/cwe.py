import json
import os
import html
from collections import defaultdict
from html import escape
from pprint import pprint


class Cwe:
    def __init__(self):
        self.cwe_aggregation_config_content = {}
        self.severity_order = {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 3,
            "LOW": 4,
            "UNKNOWN": 5
        }
        self.severity_risk_scores = {
            "CRITICAL": 9,
            "HIGH": 7,
            "MEDIUM": 5,
            "LOW": 3,
            "UNKNOWN": 1
        }

    def _read_json_file(self, file_path):
        try:
            with open(file_path, 'r') as file:
                data = json.load(file)
            return data
        except FileNotFoundError:
            print(f"File {file_path} not found.")
            return None
        except json.JSONDecodeError:
            print(f"Error decoding JSON from file {file_path}.")
            return None

    def read_cwe_aggregation_config(self, file_path):
        self.cwe_aggregation_config_content = self._read_json_file(file_path)

    def get_cwe_aggregation_categories(self):
        if self.cwe_aggregation_config_content:
            return list(self.cwe_aggregation_config_content.keys())
        else:
            print("No cwe_aggregation_config_content")

    def get_aggregation_threats_and_cwe(self):
        if not self.cwe_aggregation_config_content:
            print("No cwe_aggregation_config_content to extract from.")
            return {}

        extracted_data = {}

        for category, details in self.cwe_aggregation_config_content.items():
            threats = details.get("threats", {})
            extracted_data[category] = threats

        return extracted_data

    def get_aggregation_unique_cwes(self):
        if not self.cwe_aggregation_config_content:
            print("No cwe_aggregation_config_content to extract from.")
            return []

        unique_cwes = set()

        for category, details in self.cwe_aggregation_config_content.items():
            threats = details.get("threats", {})
            for cwe_list in threats.values():
                unique_cwes.update(cwe_list)

        return list(unique_cwes)

    def get_files_unique_cwes(self):
        if not self.cwe_aggregation_config_content:
            print("No cwe_aggregation_config_content to extract from.")
            return []

        unique_cwes = set()

        for category, details in self.cwe_aggregation_config_content.items():
            security_controls_dict = list(details.values())[0]

            for control_name, control_config in security_controls_dict.items():
                file_path = control_config.get("final_output")
                file_data = self._read_json_file(os.getenv("REPORT_PATH")+file_path)

                if not file_data:
                    continue

                if "Issues" in file_data:
                    for issue in file_data["Issues"]:
                        if "CWE" in issue:
                            cwe_number = str(issue["CWE"]).replace("CWE-", "").replace("CWE", "").strip()
                            unique_cwes.add(cwe_number)
                else:
                    for cve_details in file_data.values():
                        if isinstance(cve_details, dict) and "Details" in cve_details and "CWE" in cve_details[
                            "Details"]:
                            for cwe in cve_details["Details"]["CWE"]:
                                cwe_number = str(cwe).replace("CWE-", "").replace("CWE", "").strip()
                                unique_cwes.add(cwe_number)

        return list(unique_cwes)

    def get_files_unique_cves(self):
        if not self.cwe_aggregation_config_content:
            print("No cwe_aggregation_config_content to extract from.")
            return []

        unique_cves = set()

        for category, details in self.cwe_aggregation_config_content.items():
            security_controls_dict = list(details.values())[0]

            for control_name, control_config in security_controls_dict.items():
                file_path = control_config.get("final_output")
                file_data = self._read_json_file(os.getenv("REPORT_PATH") + file_path)

                if not file_data:
                    continue

                if "Issues" in file_data:
                    for issue in file_data["Issues"]:
                        if "CWE" in issue:
                            continue
                else:
                    for cve_id, cve_details in file_data.items():
                        if isinstance(cve_details, dict):
                            unique_cves.add(cve_id)

        return list(unique_cves)

    def get_cve_severity_distribution(self):
        if not self.cwe_aggregation_config_content:
            print("No cwe_aggregation_config_content to extract from.")
            return {}

        severity_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }
        unique_cves = set()
        cve_severity_mapping = {}

        for category, details in self.cwe_aggregation_config_content.items():
            security_controls_dict = list(details.values())[0]

            for control_name, control_config in security_controls_dict.items():
                file_path = control_config.get("final_output")
                file_data = self._read_json_file(os.getenv("REPORT_PATH") + file_path)

                if not file_data:
                    continue

                if "Issues" in file_data:
                    continue

                else:
                    for cve_id, cve_details in file_data.items():
                        if isinstance(cve_details, dict) and "Details" in cve_details:
                            severity = cve_details["Details"].get("Severity", "UNKNOWN").upper()
                            unique_cves.add(cve_id)
                            cve_severity_mapping[cve_id] = severity

        for cve_id in unique_cves:
            severity = cve_severity_mapping.get(cve_id, "UNKNOWN")
            if severity in severity_distribution:
                severity_distribution[severity] += 1
            else:
                severity_distribution["UNKNOWN"] += 1

        return severity_distribution

    def get_found_cwes(self):
        aggregation_unique_cwes = set(map(str, self.get_aggregation_unique_cwes()))
        file_unique_cwes = set(map(str, self.get_files_unique_cwes()))
        common_cwes = aggregation_unique_cwes.intersection(file_unique_cwes)
        return list(common_cwes)

    def get_cwe_distribution_across_categories(self):
        common_cwes = self.get_found_cwes()
        cwe_distribution = defaultdict(set)

        for category, details in self.cwe_aggregation_config_content.items():
            threats = details.get("threats", {})
            for threat, cwe_list in threats.items():
                for cwe in cwe_list:
                    cwe_str = str(cwe)
                    if cwe_str in common_cwes:
                        cwe_distribution[category].add(cwe_str)

        cwe_distribution = {category: list(cwes) for category, cwes in cwe_distribution.items()}

        return cwe_distribution

    def get_cves_for_found_cwes(self):
        common_cwes = self.get_found_cwes()
        found_cwes_details = {}

        for category, details in self.cwe_aggregation_config_content.items():
            security_controls_dict = list(details.values())[0]

            for control_name, control_config in security_controls_dict.items():
                file_path = control_config.get("final_output")
                label = control_config.get("name")
                file_data = self._read_json_file(os.getenv("REPORT_PATH") + file_path)

                if not file_data:
                    continue

                if "Issues" in file_data:
                    for issue in file_data["Issues"]:
                        cwe = str(issue.get("CWE", "")).replace("CWE-", "").replace("CWE", "").strip()
                        if cwe in common_cwes:
                            cve = issue.get("CVE", "")
                            targets = issue.get("Targets", {})
                            target_files = list(targets.keys())
                            lines = [target.get("line") for target_list in targets.values() for target in target_list]
                            columns = [target.get("column") for target_list in targets.values() for target in
                                       target_list]
                            severity = issue.get("severity", "")
                            confidence = issue.get("confidence", "")
                            details_text = issue.get("details", "")

                            if cwe not in found_cwes_details:
                                found_cwes_details[cwe] = {
                                    "categories": set(),
                                    "details": []
                                }

                            found_cwes_details[cwe]["categories"].add(category)
                            detail = {
                                "type": "type1",
                                "cve": cve,
                                "target_files": target_files,
                                "lines": lines,
                                "columns": columns,
                                "severity": severity,
                                "confidence": confidence,
                                "details": details_text,
                                "tools": [label],
                                "category": category
                            }
                            if not any(existing_detail['cve'] == detail['cve'] for existing_detail in
                                       found_cwes_details[cwe]["details"]):
                                found_cwes_details[cwe]["details"].append(detail)
                            else:
                                for existing_detail in found_cwes_details[cwe]["details"]:
                                    if existing_detail['cve'] == detail['cve']:
                                        existing_detail['tools'].append(label)
                                        if not isinstance(existing_detail['category'], list):
                                            existing_detail['category'] = [existing_detail['category']]
                                        if category not in existing_detail['category']:
                                            existing_detail['category'].append(category)
                else:
                    for cve_id, cve_details in file_data.items():
                        if isinstance(cve_details, dict) and "Details" in cve_details:
                            for cwe in cve_details["Details"].get("CWE", []):
                                cwe_str = str(cwe).replace("CWE-", "").replace("CWE", "").strip()
                                if cwe_str in common_cwes:
                                    targets = cve_details.get("Targets", [])
                                    title = cve_details["Details"].get("Title", "")
                                    v2_score = cve_details["Details"].get("V2Score", "")
                                    v3_score = cve_details["Details"].get("V3Score", "")
                                    severity = cve_details["Details"].get("Severity", "")

                                    if cwe_str not in found_cwes_details:
                                        found_cwes_details[cwe_str] = {
                                            "categories": set(),
                                            "details": []
                                        }

                                    found_cwes_details[cwe_str]["categories"].add(category)
                                    detail = {
                                        "type": "type2",
                                        "cve": cve_id,
                                        "targets": targets,
                                        "title": title,
                                        "v2_score": v2_score,
                                        "v3_score": v3_score,
                                        "severity": severity,
                                        "tools": [label],
                                        "category": [category]
                                    }
                                    if not any(existing_detail['cve'] == detail['cve'] for existing_detail in
                                               found_cwes_details[cwe_str]["details"]):
                                        found_cwes_details[cwe_str]["details"].append(detail)
                                    else:
                                        for existing_detail in found_cwes_details[cwe_str]["details"]:
                                            if existing_detail['cve'] == detail['cve']:
                                                existing_detail['tools'].append(label)
                                                if not isinstance(existing_detail['category'], list):
                                                    existing_detail['category'] = [existing_detail['category']]
                                                if category not in existing_detail['category']:
                                                    existing_detail['category'].append(category)

        for cwe in found_cwes_details:
            found_cwes_details[cwe]["categories"] = list(found_cwes_details[cwe]["categories"])

        return found_cwes_details

    def get_cve_distribution_tool(self):
        cwes_details = self.get_cves_for_found_cwes()

        summary_data = {}

        for category, details in self.cwe_aggregation_config_content.items():
            security_controls_dict = list(details.values())[0]
            tool_labels = sorted([control_config["name"] for control_config in security_controls_dict.values()])

            for control_name, control_config in security_controls_dict.items():
                file_path = control_config.get("final_output")
                file_data = self._read_json_file(os.getenv("REPORT_PATH") + file_path)

                if not file_data:
                    continue

            category_summary = {}
            for threat, cwes in details.get("threats", {}).items():
                for cwe in cwes:
                    cwe_str = str(cwe)
                    if cwe_str in cwes_details:
                        tool_counts = {tool: 0 for tool in tool_labels}
                        total_count = 0

                        for detail in cwes_details[cwe_str]["details"]:
                            if category in detail["category"]:
                                for tool in detail["tools"]:
                                    if tool in tool_counts:
                                        tool_counts[tool] += 1
                                        total_count += 1

                        if total_count > 0:
                            if cwe_str not in category_summary:
                                category_summary[cwe_str] = {**tool_counts, "Total": total_count}
                            else:
                                for tool in tool_counts:
                                    category_summary[cwe_str][tool] += tool_counts[tool]
                                category_summary[cwe_str]["Total"] += total_count

            for cwe, counts in category_summary.items():
                for tool in tool_labels:
                    if counts[tool] == 0:
                        counts[tool] = "-"

            sorted_category_summary = {str(k): v for k, v in
                                       sorted(category_summary.items(), key=lambda item: int(item[0]))}
            summary_data[category] = sorted_category_summary

        return summary_data

    def get_severity_distribution_for_found_cves(self):
        found_cwes_details = self.get_cves_for_found_cwes()
        severity_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0
        }
        found_cves = set()

        for cwe, details in found_cwes_details.items():
            for detail in details["details"]:
                if "cve" in detail and detail["cve"]:
                    found_cves.add(detail["cve"])
                    severity = detail.get("severity", "UNKNOWN").upper()
                    if severity in severity_distribution:
                        severity_distribution[severity] += 1
                    else:
                        severity_distribution["UNKNOWN"] += 1

        return severity_distribution

    def _get_max_theoretical_risk(self, sum_unique_cve_with_score, sum_unique_cve_with_no_score):
        return (sum_unique_cve_with_score * self.severity_risk_scores["CRITICAL"] * 10) + \
               (sum_unique_cve_with_no_score * self.severity_risk_scores["CRITICAL"])

    def calculate_overall_risk(self):
        found_cwes_details = self.get_cves_for_found_cwes()
        total_risk = 0
        sum_unique_cve_with_score = 0
        sum_unique_cve_with_no_score = 0
        unique_cves = set()

        for cwe, details in found_cwes_details.items():
            for detail in details["details"]:
                if "cve" in detail and detail["cve"]:
                    unique_cves.add(detail["cve"])
                    severity = detail.get("severity", "UNKNOWN").upper()
                    v3_score = detail.get("v3_score", "")

                    if v3_score:
                        try:
                            v3_score = float(v3_score)
                        except ValueError:
                            v3_score = 1
                    else:
                        v3_score = 1

                    risk_score = self.severity_risk_scores.get(severity, 1) * v3_score
                    total_risk += risk_score

                    if v3_score != 1:
                        sum_unique_cve_with_score += 1
                    else:
                        sum_unique_cve_with_no_score += 1

        max_theoretical_risk = self._get_max_theoretical_risk(sum_unique_cve_with_score, sum_unique_cve_with_no_score)

        if max_theoretical_risk == 0:
            return 0

        overall_risk = (total_risk / max_theoretical_risk) * 100
        return int(overall_risk)

    def calculate_risk_per_cwe(self):
        found_cwes_details = self.get_cves_for_found_cwes()
        risk_per_cwe = {}
        max_num_vulnerabilities = max(len(details["details"]) for details in found_cwes_details.values())

        for cwe, details in found_cwes_details.items():
            total_risk = 0
            sum_unique_cve_with_score = 0
            sum_unique_cve_with_no_score = 0
            num_vulnerabilities = len(details["details"])

            for detail in details["details"]:
                severity = detail.get("severity", "UNKNOWN").upper()
                v3_score = detail.get("v3_score", "")

                if v3_score:
                    try:
                        v3_score = float(v3_score)
                    except ValueError:
                        v3_score = 1
                else:
                    v3_score = 1

                risk_score = self.severity_risk_scores.get(severity, 1) * v3_score
                total_risk += risk_score

                if v3_score != 1:
                    sum_unique_cve_with_score += 1
                else:
                    sum_unique_cve_with_no_score += 1

            max_theoretical_risk = self._get_max_theoretical_risk(sum_unique_cve_with_score,
                                                                  sum_unique_cve_with_no_score)

            if max_theoretical_risk == 0:
                normalized_risk = 0
            else:
                overall_risk = (total_risk / max_theoretical_risk) * 100
                normalized_risk = int((overall_risk * num_vulnerabilities) / max_num_vulnerabilities)

            risk_per_cwe[cwe] = normalized_risk

        return risk_per_cwe

    def calculate_risk_per_threat(self):
        found_cwes_details = self.get_cves_for_found_cwes()
        threats_risk = defaultdict(lambda: {"cwes": set(), "total_risk": 0, "num_vulnerabilities": 0})

        max_vulnerabilities = 0
        for category, details in self.cwe_aggregation_config_content.items():
            threats = details.get("threats", {})
            for threat, cwes in threats.items():
                num_vulnerabilities = sum(len(found_cwes_details.get(str(cwe), {}).get("details", [])) for cwe in cwes)
                max_vulnerabilities = max(max_vulnerabilities, num_vulnerabilities)

        for details in self.cwe_aggregation_config_content.values():
            threats = details.get("threats", {})
            for threat, cwes in threats.items():
                threat_cwes = set()
                total_risk = 0
                sum_unique_cve_with_score = 0
                sum_unique_cve_with_no_score = 0
                num_vulnerabilities = 0

                for cwe in cwes:
                    cwe_str = str(cwe)
                    if cwe_str in found_cwes_details:
                        threat_cwes.add(cwe_str)
                        cwe_details = found_cwes_details[cwe_str]
                        num_vulnerabilities += len(cwe_details["details"])

                        for detail in cwe_details["details"]:
                            severity = detail.get("severity", "UNKNOWN").upper()
                            v3_score = detail.get("v3_score", "")

                            if v3_score:
                                try:
                                    v3_score = float(v3_score)
                                except ValueError:
                                    v3_score = 1
                            else:
                                v3_score = 1

                            if v3_score != 1:
                                sum_unique_cve_with_score += 1
                            else:
                                sum_unique_cve_with_no_score += 1

                            risk_score = self.severity_risk_scores.get(severity, 1) * v3_score
                            total_risk += risk_score

                if num_vulnerabilities > 0:
                    max_theoretical_risk = self._get_max_theoretical_risk(sum_unique_cve_with_score,
                                                                          sum_unique_cve_with_no_score)
                    if max_theoretical_risk == 0:
                        normalized_risk = 0
                    else:
                        overall_risk = int((total_risk / max_theoretical_risk) * 100)
                        normalized_risk = int((overall_risk * num_vulnerabilities) / max_vulnerabilities)
                else:
                    normalized_risk = 0

                threats_risk[threat]["cwes"].update(threat_cwes)
                threats_risk[threat]["total_risk"] = normalized_risk
                threats_risk[threat]["num_vulnerabilities"] = num_vulnerabilities

        return {threat: data["total_risk"] for threat, data in threats_risk.items()}

    def get_severity_distribution_per_label(self):
        cwes_details = self.get_cves_for_found_cwes()

        severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        category_label_severity_distribution = {}

        for category, details in self.cwe_aggregation_config_content.items():
            security_controls_dict = list(details.values())[0]

            for control_name, control_config in security_controls_dict.items():
                file_path = control_config.get("final_output")
                label = control_config.get("name")
                file_data = self._read_json_file(os.getenv("REPORT_PATH") + file_path)

                if not file_data:
                    continue

                if category not in category_label_severity_distribution:
                    category_label_severity_distribution[category] = {}

                if label not in category_label_severity_distribution[category]:
                    category_label_severity_distribution[category][label] = {level: 0 for level in severity_levels}

        for cwe, cwe_details in cwes_details.items():
            for detail in cwe_details["details"]:
                for label in detail["tools"]:
                    severity = detail.get("severity", "UNKNOWN").upper()
                    if severity in severity_levels:
                        for category in detail["category"]:
                            if category in category_label_severity_distribution and label in \
                                    category_label_severity_distribution[category]:
                                category_label_severity_distribution[category][label][severity] += 1

        return category_label_severity_distribution

    def generate_html_table(self, output_path):
        files_unique_cwe_len = len(self.get_files_unique_cwes())
        files_unique_cves_len = len(self.get_files_unique_cves())
        cve_severity_distribution = self.get_cve_severity_distribution()
        cwe_searched_len = len(self.get_aggregation_unique_cwes())
        cwe_found = self.get_found_cwes()
        cwe_distribution_across_categories = self.get_cwe_distribution_across_categories()
        cve_severity_distribution_for_found_cves = self.get_severity_distribution_for_found_cves()
        overall_risk_level = self.calculate_overall_risk()
        risk_per_cwe = self.calculate_risk_per_cwe()
        risk_per_threat = self.calculate_risk_per_threat()
        aggregation_threats_and_cwe = self.get_aggregation_threats_and_cwe()
        cves_for_found_cwes = self.get_cves_for_found_cwes()
        cve_distribution_tool = self.get_cve_distribution_tool()
        severity_distribution_per_label = self.get_severity_distribution_per_label()

        stats_html = f"""
            <h2>Summary of results found</h2>
            <h3><strong>Total unique CVE:</strong> {files_unique_cves_len}</h3>
            <h3><strong>Total unique CWE:</strong> {files_unique_cwe_len}</h3>
            """

        stats_html += "<h3>Severity distribution</h3><ul>"
        for severity in sorted(cve_severity_distribution.keys(), key=lambda s: self.severity_order.get(s, 5)):
            stats_html += f"<li><strong>{escape(severity)}:</strong> {cve_severity_distribution[severity]}/{files_unique_cves_len}</li>"
        stats_html += "</ul>"

        stats_html += f"""
                    <h2>Threat aggregation summary</h2>
                    """

        stats_html += f"""<h3>CWE searched ({cwe_searched_len}):</h3>"""
        for category, threats in aggregation_threats_and_cwe.items():
            stats_html += f"<p>{category}</p><ul>"
            for threat, cwes in threats.items():
                stats_html += f"<li><b>{threat}</b>: {', '.join(map(str, sorted(cwes)))}</li>"
            stats_html += "</ul>"

        stats_html += f"""<h3>CWE found ({len(cwe_found)}/{cwe_searched_len}):</h3>"""
        stats_html += f"<ul>"
        stats_html += f"<li>{', '.join(map(str, sorted(cwe_found, key=int)))}</li>"
        stats_html += "</ul>"

        stats_html += "<h3>CWE found per category</h3><ul>"
        for category, cwe in cwe_distribution_across_categories.items():
            stats_html += f"<li><strong>{escape(category)}:</strong> {len(cwe)}/{len(cwe_found)}</li>"
        stats_html += "</ul>"

        stats_html += "<h3>Severity distribution</h3><ul>"
        for severity in sorted(cve_severity_distribution_for_found_cves.keys(),
                               key=lambda s: self.severity_order.get(s, 5)):
            stats_html += f"<li><strong>{escape(severity)}:</strong> {cve_severity_distribution_for_found_cves[severity]}/{sum(cve_severity_distribution_for_found_cves.values())}</li>"
        stats_html += "</ul>"

        stats_html += f"""
                    <h2>Risk analysis</h2>
                    <h3><strong>Normalized overall risk level:</strong> {overall_risk_level}</h3>
                    """

        stats_html += "<h3>Risk per CWE</h3><ul>"
        for cwe, risk in sorted(risk_per_cwe.items(), key=lambda item: item[1], reverse=True):
            cwe = "CWE-" + cwe
            stats_html += f"<li><strong>{escape(cwe)}:</strong> {risk}/100</li>"
        stats_html += "</ul>"

        stats_html += "<h3>Risk per Threat</h3><ul>"
        for threat, risk in sorted(risk_per_threat.items(), key=lambda item: item[1], reverse=True):
            stats_html += f"<li><strong>{escape(threat)}:</strong> {risk}/100</li>"
        stats_html += "</ul>"

        sorted_risk_per_cwe = sorted(risk_per_cwe.items(), key=lambda item: item[1], reverse=True)

        table_html_style = "<style>"
        table_html_style += "table {font-family: Arial, sans-serif; border-collapse: collapse; width: 100%;}"
        table_html_style += "td, th {border: 1px solid #dddddd; text-align: left; padding: 8px;}"
        table_html_style += "tr:nth-child(even) {background-color: #f2f2f2;}"
        table_html_style += "th {background-color: #dddddd;}"
        table_html_style += "</style>"

        cve_cwe_table = """
            <table border="1">
                <thead>
                    <tr>
                        <th>CWE</th>
                        <th>Categories</th>
                        <th>Severity</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
            """

        for cwe, risk in sorted_risk_per_cwe:
            data = cves_for_found_cwes[cwe]
            if not data['categories']:
                continue
            categories = ", ".join(data['categories'])
            severity = ", ".join(
                sorted(set(detail['severity'] for detail in data['details']),
                       key=lambda s: self.severity_order.get(s, 5)))

            details_html = ""
            for detail in data['details']:
                if detail.get('type') == "type1":
                    details_html += f"""
                                    <div>
                                      <strong>File:</strong> {html.escape(", ".join(detail.get('target_files', [])))}<br>
                                      <strong>Severity:</strong> {html.escape(str(detail.get('severity', '')))}<br>
                                      <strong>Confidence:</strong> {html.escape(str(detail.get('confidence', '')))}<br>
                                      <strong>Lines and Columns:</strong> {html.escape(", ".join(f"{line}:{col}" for line, col in zip(detail.get('lines', []), detail.get('columns', []))))}<br>
                                      <strong>Details:</strong> {html.escape(str(detail.get('details', '')))}<br>
                                      <strong>Tools:</strong> {html.escape(", ".join(detail.get('tools', [])))}
                                    </div>
                                    <hr>
                                    """
                elif detail.get('type') == "type2":
                    details_html += f"""
                                    <div>
                                        <strong>CVE:</strong> {html.escape(str(detail.get('cve', '')))}<br>
                                        <strong>Severity:</strong> {html.escape(str(detail.get('severity', '')))}<br>
                                        <strong>Target:</strong> {html.escape(", ".join(detail.get('targets', [])))}<br>
                                        <strong>Title:</strong> {html.escape(detail.get('title', ''))}<br>
                                        <strong>V2 Score:</strong> {html.escape(str(detail.get('v2_score', '')))}<br>
                                        <strong>V3 Score:</strong> {html.escape(str(detail.get('v3_score', '')))}<br>
                                        <strong>Tools:</strong> {html.escape(", ".join(detail.get('tools', [])))}
                                    </div>
                                    <hr>
                                    """

            cve_cwe_table += f"""
                <tr>
                    <td style='white-space:nowrap'>{html.escape(cwe)}</td>
                    <td>{html.escape(categories)}</td>
                    <td>{html.escape(severity)}</td>
                    <td>{details_html}</td>
                </tr>
                """

        cve_cwe_table += """
                </tbody>
            </table>
            """

        cve_distribution_tool_table = f"<h2>CVE distribution tool</h2>"
        for category, cwe_data in cve_distribution_tool.items():
            cve_distribution_tool_table += f"<h3>{category}</h3>"
            cve_distribution_tool_table += """
                <table border="1" cellspacing="0" cellpadding="5">
                    <tr>
                        <th>CWE</th>"""

            tool_labels = sorted(next(iter(cwe_data.values())).keys())
            tool_labels.remove("Total")
            for tool in tool_labels:
                cve_distribution_tool_table += f"<th>{tool}</th>"
            cve_distribution_tool_table += "<th>Total</th></tr>"

            for cwe, counts in sorted(cwe_data.items(), key=lambda item: int(item[0])):
                cve_distribution_tool_table += f"<tr><td>CWE-{cwe}</td>"
                for tool in tool_labels:
                    cve_distribution_tool_table += f"<td>{counts[tool]}</td>"
                cve_distribution_tool_table += f"<td>{counts['Total']}</td></tr>"

            cve_distribution_tool_table += "</table><br>"

        severity_distribution_per_label_table = f"<h2>Severity distribution per label</h2>"

        for category, label_data in severity_distribution_per_label.items():
            severity_distribution_per_label_table += f"<h3>{category}</h3>"

            labels = list(label_data.keys())
            num_labels = len(labels)

            for i in range(0, num_labels, 6):
                severity_distribution_per_label_table += "<div style='display: flex; justify-content: space-around; margin-bottom: 20px;'>"
                for j in range(i, min(i + 6, num_labels)):
                    label = labels[j]
                    data = label_data[label]
                    severity_distribution_per_label_table += f"<table border='1' cellspacing='0' cellpadding='5' style='width: 11%;'>"
                    severity_distribution_per_label_table += f"<caption>{label}</caption>"
                    severity_distribution_per_label_table += "<tr><th>Severity</th><th>Conteggio</th></tr>"

                    for severity, count in data.items():
                        severity_distribution_per_label_table += f"<tr><td>{severity}</td><td>{count}</td></tr>"

                    severity_distribution_per_label_table += "</table>"
                severity_distribution_per_label_table += "</div>"

        full_html = f"""
                    <html>
                    <head><title>Risk Analysis Report</title></head>
                    {table_html_style}
                    <body>
                        {stats_html}
                        {cve_cwe_table}
                        {cve_distribution_tool_table}
                        {severity_distribution_per_label_table}
                    </body>
                    </html>
                    """

        with open(output_path, 'w') as f:
            f.write(full_html)
