#!/usr/bin/env python
import os
from security_controls.gosec.gosec import Gosec
from security_controls.bandit.bandit import Bandit
from security_controls.trivy.trivy import Trivy
from security_controls.lynis.lynis import Lynis
import json
from aggregation.cwe import Cwe
from pprint import pprint


def load_and_instantiate_controls():
    with open("config/config.json", "r") as f:
        config = json.load(f)

    with open("config/credential.json", "r") as f:
        credentials = json.load(f)

    for category, data in config.items():
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
                    report_path=control_config["report_output"],
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
                    report_path=control_config["report_output"],
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
                    report_path=control_config["report_output"],
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


def report_generation():
    cwe = Cwe()
    cwe.read_cwe_aggregation_config("config/config.json")
    cwe.generate_html_table(os.getenv("REPORT_PATH")+"cwe_aggregation.html")

    print("Categories:")
    pprint(cwe.get_cwe_aggregation_categories())

    print("Threats and CWE:")
    pprint(cwe.get_aggregation_threats_and_cwe())

    print("Unique CWE searched")
    pprint(cwe.get_aggregation_unique_cwes())

    print("Unique CWE found")
    pprint(cwe.get_files_unique_cwes())

    print("Unique CVE found")
    pprint(cwe.get_files_unique_cves())

    print("Severity distribution")
    pprint(cwe.get_cve_severity_distribution())

    print("CWE found")
    pprint(cwe.get_found_cwes())

    print("CWE distribution across categories")
    pprint(cwe.get_cwe_distribution_across_categories())

    print("CVE for found CWE")
    pprint(cwe.get_cves_for_found_cwes())

    print("CVE distribution tool")
    pprint(cwe.get_cve_distribution_tool())

    print("Severity distribution for found cves")
    pprint(cwe.get_severity_distribution_for_found_cves())

    print("Overall risk")
    pprint(cwe.calculate_overall_risk())

    print("Risk per CWE")
    pprint(cwe.calculate_risk_per_cwe())

    print("Risk per threat")
    pprint(cwe.calculate_risk_per_threat())

    print("Severity distribution per label")
    pprint(cwe.get_severity_distribution_per_label())


load_and_instantiate_controls()
report_generation()
