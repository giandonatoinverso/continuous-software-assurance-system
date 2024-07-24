#!/bin/bash

docker pull continuous-software-assurance-system:latest
docker run -i continuous-software-assurance-system:latest "python main.py"