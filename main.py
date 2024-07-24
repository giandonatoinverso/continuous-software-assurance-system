#!/usr/bin/env python
from security_controls.gosec.gosec import Gosec
from security_controls.bandit.bandit import Bandit
from security_controls.trivy.trivy import Trivy
from security_controls.lynis.lynis import Lynis

""""
trivy = Trivy("fs", "mainflux_trivy.json", "MEDIUM", 2, target="https://github.com/MainfluxLabs/mainflux", target_name="Trivy Mainflux Golang")
trivy = Trivy("docker", "mainflux_docker.json", "MEDIUM", 2, target="docker.io/",
              compose_file_url="https://raw.githubusercontent.com/giandonatoinverso/continuous-software-assurance-system/main/temp/docker_compose.yaml",
              env_file_url="https://raw.githubusercontent.com/giandonatoinverso/continuous-software-assurance-system/main/temp/envfile.env",
              docker_host="unix:///Users/giandonatoinverso/.docker/run/docker.sock")
trivy.execute()
"""