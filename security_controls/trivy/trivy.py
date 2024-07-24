import json
import os
import subprocess
from parser.trivy.trivy_vulnerability_analysis import TrivyVulnerabilityAnalysis
from utils.compose_utils import ComposeUtils
from utils.helper import Helper
from utils.ssh_client import SshClient


class Trivy:
    def __init__(self, mode, output_path, evaluation_severity, evaluation_threshold,
                 target=None, target_port=None, target_username=None, target_password=None, target_private_key=None,
                 oauth_token=None, target_name=None, compose_file_url=None, env_file_url=None,
                 docker_username=None, docker_host=None, docker_password=None, remotefs_timeout=None, remotefs_skipdirs=None, remotefs_skipfiles=None,
                 remotefs_version=None, remotefs_platform=None):
        supported_modes = {'docker', 'fs', 'remotefs'}
        if mode not in supported_modes:
            raise Exception(f"The parameter {mode} is invalid. Must belong to: {supported_modes}")

        self.mode = mode
        self.images_list = []
        self.trivy_grouped_vulnerabilities = dict()
        self.helper = Helper()
        self.output_path = output_path
        self.evaluation_severity = evaluation_severity
        self.evaluation_threshold = evaluation_threshold
        self.target = target
        self.target_port = target_port
        self.target_username = target_username
        self.target_password = target_password
        self.target_private_key = target_private_key
        self.oauth_token = oauth_token
        self.target_name = target_name
        self.tempfs = os.getenv('TEMP_PATH')+"repository/"
        self.compose_file_url = compose_file_url
        self.compose_file_path = os.getenv('TEMP_PATH')+"docker_compose.yaml"
        self.env_file_url = env_file_url
        self.env_file_path = os.getenv('TEMP_PATH')+"envfile.env"
        self.docker_username = docker_username
        self.docker_password = docker_password
        self.docker_host = docker_host
        self.remotefs_timeout = remotefs_timeout
        self.remotefs_skipdirs = remotefs_skipdirs
        self.remotefs_skipfiles = remotefs_skipfiles
        self.remotefs_version = remotefs_version
        self.remotefs_platform = remotefs_platform

    def execute(self):
        self.download_resources()
        self.execute_trivy()
        self.trivy_vulnerability_analysis()
        self.clean()
        return self.evaluate_output()

    def download_resources(self):
        if self.mode == "docker":
            self.helper.download_file(self.compose_file_url, self.compose_file_path, self.oauth_token)

            if self.env_file_url is not None:
                self.helper.download_file(self.env_file_url, self.env_file_path, self.oauth_token)

        elif self.mode == "fs":
            self.helper.clone_repository(self.target, self.tempfs, self.oauth_token)

        elif self.mode == "remotefs":
            ssh_client = self._get_ssh_client()
            ssh_client.connect_ssh()
            ssh_client.send_command(f"sudo wget https://github.com/aquasecurity/trivy/releases/download/v{self.remotefs_version}/trivy_{self.remotefs_version}_{self.remotefs_platform}",
                                    SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo dpkg -i trivy_{self.remotefs_version}_{self.remotefs_platform}",
                                    SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo rm -rf /tmp/*", SshClient.onNotZeroExitCodeAction.STOP)

        else:
            raise Exception(f"Invalid {self.mode}")

    def execute_trivy(self):
        if self.mode == "docker":
            self.trivy_docker()
        elif self.mode == "fs":
            self.trivy_fs()
        elif self.mode == "remotefs":
            self.trivy_remote_fs()
        else:
            raise Exception(f"Invalid {self.mode}")

    def trivy_docker(self):
        self._get_images_list()
        assert self.images_list is not None and self.images_list != "", "images input field not valid"
        for image_name_full in self.images_list:
            trivy_command = f""

            if self.docker_username is not None and self.docker_password is not None:
                trivy_command += f"TRIVY_USERNAME={self.docker_username} TRIVY_PASSWORD={self.docker_password} "

            image_name_parts = image_name_full.split("/")
            image_name = image_name_parts[-1]
            trivy_command += f"/usr/local/bin/trivy --scanners vuln image --format json --output \"{os.getenv('TEMP_PATH')}{image_name}.json\" {image_name_full} "
            if self.docker_host is not None:
                trivy_command += f"--docker-host {self.docker_host}"
            subprocess.Popen(trivy_command, shell=True).wait()

    def trivy_fs(self):
        trivy_command = f"/usr/local/bin/trivy --scanners vuln fs --format json --output \"{os.getenv('TEMP_PATH')}{self.target_name}.json\" {self.tempfs}"
        print(trivy_command)
        subprocess.Popen(trivy_command, shell=True).wait()

    def trivy_remote_fs(self):
        ssh_client = self._get_ssh_client()
        ssh_client.connect_ssh()
        trivy_command = f"""sudo trivy --scanners vuln """
        trivy_command += f"""--timeout {self.remotefs_timeout} """

        for skipdir in self.remotefs_skipdirs:
            trivy_command += f"""--skip-dirs {skipdir} """

        for skipfile in self.remotefs_skipfiles:
            trivy_command += f"""--skip-files {skipfile} """

        trivy_command += f"""rootfs --format json --output {self.target_name}.json /"""
        out_raw = ssh_client.send_command(trivy_command, SshClient.onNotZeroExitCodeAction.STOP)
        print(out_raw['stdout'])
        ssh_client.get_file(os.getenv('TEMP_PATH')+self.target_name+".json", self.target_name+".json")

    def trivy_vulnerability_analysis(self):
        trivy_analyzer = TrivyVulnerabilityAnalysis(os.getenv('TEMP_PATH'))
        trivy_grouped_vulnerabilities = trivy_analyzer.group_vulnerabilities_by_id(None, self.evaluation_severity)
        self.trivy_grouped_vulnerabilities = trivy_grouped_vulnerabilities
        trivy_grouped_vulnerabilities_json = f"{os.getenv('REPORT_PATH')}{self.output_path}"
        with open(trivy_grouped_vulnerabilities_json, mode='w') as json_file:
            json.dump(trivy_grouped_vulnerabilities, json_file, indent=4)

    def evaluate_output(self):
        severity_levels = {
            "NONE": 0,
            "UNKNOWN": 1,
            "LOW": 2,
            "MEDIUM": 3,
            "HIGH": 4,
            "CRITICAL": 5
        }

        desired_level = severity_levels[self.evaluation_severity]
        counter = 0

        for cve, details in self.trivy_grouped_vulnerabilities.items():
            if 'Details' in details and 'Severity' in details['Details']:
                current_severity = details['Details']['Severity']
                if severity_levels[current_severity] >= int(desired_level):
                    counter += 1

        if counter >= int(self.evaluation_threshold):
            return 1
        else:
            return 0

    def clean(self):
        if self.mode == "docker":
            self.helper.remove_path_contents(os.getenv('TEMP_PATH'))

        elif self.mode == "fs":
            self.helper.remove_path_contents(os.getenv('TEMP_PATH'))

        elif self.mode == "remotefs":
            ssh_client = self._get_ssh_client()
            ssh_client.connect_ssh()
            ssh_client.send_command(f"sudo rm {self.target_name}.json", SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo rm trivy*", SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo rm -rf /root/.cache/trivy", SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo rm -rf /root/.cache/trivy/db/trivy.db",
                                    SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo rm -rf /root/.cache/trivy/db", SshClient.onNotZeroExitCodeAction.STOP)
            ssh_client.send_command(f"sudo rm -rf /usr/bin/trivy", SshClient.onNotZeroExitCodeAction.STOP)

        else:
            raise Exception(f"Invalid {self.mode}")

    def _get_images_list(self):
        compose_utils = ComposeUtils(self.compose_file_path, self.env_file_path)
        self.images_list = compose_utils.get_images_list()

    def _get_ssh_client(self) -> SshClient:
        ssh_client: SshClient = SshClient(
            host=self.target,
            port=self.target_port,
            username=self.target_username,
            password=self.target_password,
            private_key=self.target_private_key,
            private_key_passphrase=None)

        return ssh_client
