import os
import subprocess
from parser.gosec.gosec_parser import GosecParser
from utils.helper import Helper


class Gosec:
    def __init__(self, repository_path, input_path, output_path, html_path, evaluation_severity, evaluation_threshold,
                 target, oauth_token=None):
        self.output = dict()
        self.helper = Helper()
        self.repository_path = repository_path
        self.input_path = input_path
        self.output_path = output_path
        self.html_path = html_path
        self.evaluation_severity = evaluation_severity
        self.evaluation_threshold = evaluation_threshold
        self.target = target
        self.oauth_token = oauth_token

    def execute(self):
        self.download_resources()
        self.gosec_execute()
        self.generate_output()
        self.helper.remove_path_contents(os.getenv('TEMP_PATH'))
        return self.evaluate_output()

    def download_resources(self):
        self.helper.clone_repository(self.target, self.repository_path, self.oauth_token)

    def gosec_execute(self):
        command = f"gosec -exclude-dir=test -fmt=json {self.repository_path}/... > {os.getenv('RAW_PATH')}{self.input_path}"
        subprocess.Popen(command, shell=True).wait()

    def generate_output(self):
        gosec_parser = GosecParser(self.input_path)
        self.output = gosec_parser.cwe_targets_aggregation(os.getenv('REPORT_PATH')+self.output_path)
        gosec_parser.json_to_html(os.getenv('REPORT_PATH')+self.output_path, os.getenv('REPORT_PATH')+self.html_path)

    def evaluate_output(self):
        severity_levels = {
            "NONE": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        desired_level = int(severity_levels[self.evaluation_severity])
        counter = 0

        issues = self.output["Issues"]
        for issue in issues:
            current_severity = issue['severity']
            if severity_levels[current_severity] >= desired_level:
                counter += 1

        if counter >= int(self.evaluation_threshold):
            return 1
        else:
            return 0
