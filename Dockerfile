FROM python:3.10

RUN mkdir -p /usr/src/app

WORKDIR /usr/src/app
ADD requirements.txt /usr/src/app

COPY --from=docker.io/golang:1.22.2-alpine /usr/local/go/ /usr/local/go/
ENV PATH="/usr/local/go/bin:${PATH}"
ENV TEMP_PATH="/usr/src/app/temp/"
ENV RAW_PATH="/usr/src/app/data/raw/"
ENV REPORT_PATH="/usr/src/app/data/report/"
ENV TRIVY_VERSION="0.49.1"
RUN wget -O - -q https://raw.githubusercontent.com/securego/gosec/master/install.sh | sh -s -- -b /usr/local/bin
RUN wget -O- -q https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v$TRIVY_VERSION
RUN wget -O- -q https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

RUN pip install --no-cache-dir -r requirements.txt

ADD . /usr/src/app

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["/usr/src/app/main.py"]