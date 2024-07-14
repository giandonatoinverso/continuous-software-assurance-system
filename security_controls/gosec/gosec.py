import os
import subprocess
from parser.gosec.gosec_parser import GosecParser
from utils.helper import Helper


class Gosec:
    gosec_output = dict()
    helper = Helper()
    repository_path = os.getenv('REPOSITORY_PATH')
    target = os.getenv('GOSEC_TARGET')
    oauth_token = os.getenv('GOSEC_OAUTH_TOKEN', None)
    input_path = os.getenv('GOSEC_INPUT')
    output_path = os.getenv('GOSEC_OUTPUT')
    html_path = os.getenv('GOSEC_HTML')
    evaluation_severity = os.getenv('GOSEC_EVALUATION_SEVERITY')
    evaluation_threshold = os.getenv('GOSEC_EVALUATION_THRESHOLD')

    def execute(self):
        self.download_resources()
        self.gosec_execute()
        self.generate_output()
        self.helper.remove_path(self.repository_path)
        return self.evaluate_output()

    def download_resources(self):
        self.helper.clone_repository(self.target, self.repository_path, self.oauth_token)

    def gosec_execute(self):
        command = f"gosec -exclude-dir=test -fmt=json {self.repository_path}/... > {self.input_path}"
        subprocess.Popen(command, shell=True).wait()

    def generate_output(self):
        gosec_parser = GosecParser(self.input_path)
        self.gosec_output = gosec_parser.cwe_targets_aggregation(self.output_path)
        gosec_parser.json_to_html(self.output_path, self.html_path)

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

        issues = self.gosec_output["Issues"]
        for issue in issues:
            current_severity = issue['severity']
            if severity_levels[current_severity] >= desired_level:
                counter += 1

        if counter >= int(self.evaluation_threshold):
            return 1
        else:
            return 0
