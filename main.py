#!/usr/bin/env python
from security_controls.gosec.gosec import Gosec
from security_controls.bandit.bandit import Bandit
from security_controls.trivy.trivy import Trivy

#trivy = Trivy("fs", "mainflux_trivy.json", "MEDIUM", 2, target="https://github.com/MainfluxLabs/mainflux", target_name="Trivy Mainflux Golang")
trivy = Trivy("docker", "mainflux_docker.json", "MEDIUM", 2, target="docker.io/",
              compose_file_url="https://raw.githubusercontent.com/giandonatoinverso/continuous-software-assurance-system/main/docker_compose.yaml",
              env_file_url="https://raw.githubusercontent.com/giandonatoinverso/continuous-software-assurance-system/main/envfile.env",
              docker_host="unix:///Users/giandonatoinverso/.docker/run/docker.sock")
trivy.execute()
