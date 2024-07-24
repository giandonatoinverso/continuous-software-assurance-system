#!/usr/bin/env python
from security_controls.gosec.gosec import Gosec
from security_controls.bandit.bandit import Bandit
from security_controls.trivy.trivy import Trivy
from security_controls.lynis.lynis import Lynis
import json

""""
trivy = Trivy("fs", "mainflux_trivy.json", "MEDIUM", 2, target="https://github.com/MainfluxLabs/mainflux", target_name="Trivy Mainflux Golang")
trivy = Trivy("docker", "mainflux_docker.json", "MEDIUM", 2, target="docker.io/",
              compose_file_url="https://raw.githubusercontent.com/giandonatoinverso/continuous-software-assurance-system/main/docker_compose.yaml",
              env_file_url="https://raw.githubusercontent.com/giandonatoinverso/continuous-software-assurance-system/main/envfile.env",
              docker_host="unix:///Users/giandonatoinverso/.docker/run/docker.sock")
trivy.execute()
"""


def load_and_instantiate_controls():
    with open("config/config.json", "r") as f:
        config = json.load(f)

    with open("config/credential.json", "r") as f:
        credentials = json.load(f)

    security_controls_by_category = {}

    for category, data in config.items():
        security_controls = {}
        for control_name, control_config in data["security_controls"].items():
            credential_label = control_config.get("credential")
            control_credentials = credentials.get(credential_label, {})

            if control_name == "bandit":
                bandit = Bandit(
                    input_path=control_config["raw_output"],
                    output_path=control_config["final_output"],
                    html_path=control_config["report_output"],
                    evaluation_severity=control_config["evaluation"]["severity"],
                    evaluation_threshold=control_config["evaluation"]["threshold"],
                    target=control_config["target"],
                    oauth_token=control_credentials.get("oauth_token", "")
                )
                bandit.execute()
            elif control_name == "gosec":
                gosec = Gosec(
                    input_path=control_config["raw_output"],
                    output_path=control_config["final_output"],
                    html_path=control_config["report_output"],
                    evaluation_severity=control_config["evaluation"]["severity"],
                    evaluation_threshold=control_config["evaluation"]["threshold"],
                    target=control_config["target"],
                    oauth_token=control_credentials.get("oauth_token", "")
                )
                gosec.execute()
            elif control_name == "lynis":
                lynis = Lynis(
                    lynis_version=control_config["version"],
                    hardening_index_threshold=control_config["evaluation"]["hardening_index_threshold"],
                    output_path=control_config["final_output"],
                    target=control_config["target"],
                    target_port=control_config["target_port"],
                    target_username=control_credentials.get("username"),
                    target_password=control_credentials.get("password", ""),
                    target_private_key=control_credentials.get("private_key", ""),
                    skip_test=control_config.get("skip_test", []),
                )
                lynis.execute()
            elif control_name == "trivy_docker":
                trivy = Trivy(
                    mode=control_name,
                    target_name=control_config["name"],
                    output_path=control_config["final_output"],
                    evaluation_severity=control_config["evaluation"]["severity"],
                    evaluation_threshold=control_config["evaluation"]["threshold"],
                    target=control_config["target"],
                    compose_file_url=control_config["compose_file"],
                    env_file_url=control_config["env_file"],
                    docker_host=control_config["docker_host"],
                    docker_username=control_credentials.get("username", ""),
                    docker_password=control_credentials.get("password", "")
                )
                trivy.execute()
            elif control_name == "trivy_fs":
                trivy = Trivy(
                    mode=control_name,
                    target_name=control_config["name"],
                    output_path=control_config["final_output"],
                    evaluation_severity=control_config["evaluation"]["severity"],
                    evaluation_threshold=control_config["evaluation"]["threshold"],
                    target=control_config["target"],
                    oauth_token=control_credentials.get("oauth_token", "")
                )
                trivy.execute()
            elif control_name == "trivy_remotefs":
                trivy = Trivy(
                    mode=control_name,
                    target_name=control_config["name"],
                    output_path=control_config["final_output"],
                    evaluation_severity=control_config["evaluation"]["severity"],
                    evaluation_threshold=control_config["evaluation"]["threshold"],
                    target=control_config["target"],
                    target_port=control_config["target_port"],
                    remotefs_version=control_config["version"],
                    remotefs_platform=control_config["platform"],
                    remotefs_timeout=control_config.get("timeout", ""),
                    remotefs_skipfiles=control_config.get("skip_files", []),
                    remotefs_skipdirs=control_config.get("skip_dirs", []),
                    target_username=control_credentials.get("username"),
                    target_password=control_credentials.get("password", ""),
                    target_private_key=control_credentials.get("private_key", "")
                )
                trivy.execute()
            else:
                raise ValueError(f"Security control type not supported: {control_name}")

    return security_controls_by_category

controls = load_and_instantiate_controls()
