### Install and update nuclei templates ###
FROM golang:1.23 as builder
WORKDIR /app
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN nuclei update-templates

### Copy files and scan ###
FROM python:3.13.1-slim

ENV PYTHONUNBUFFERED=1
ENV HOME=/home/nuclei
RUN useradd -m -s /bin/bash nuclei
RUN mkdir -p $HOME/nuclei-templates && chown nuclei:nuclei $HOME/nuclei-templates

COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei
RUN chmod +x /usr/local/bin/nuclei && chown nuclei:nuclei /usr/local/bin/nuclei

COPY --from=builder /root/nuclei-templates $HOME/nuclei-templates
RUN chown -R nuclei:nuclei $HOME/nuclei-templates

WORKDIR /app
COPY scan.py ./
COPY targets.txt ./
USER nuclei

CMD ["python", "scan.py"]