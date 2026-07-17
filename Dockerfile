FROM python:3.11-slim

## Install rsyslong so /dev/log exists inside the container - 
## isc-agent logs to syslog and will crash on startup without it

RUN apt-get update && apt-get install -y --no-install-recommends \
rsyslog \
gosu \
&& rm -rf /var/lib/apt/lists/*

## Copy just isc_agent source

WORKDIR /srv/web
COPY isc-agent-src ./isc_agent

## Install isc_agent dependencies (there is only one)

RUN pip install --no-cache-dir requests

## Create non-root user to run as

RUN useradd --create-home --shell /bin/bash agent
RUN mkdir -p /srv/dshield/etc /srv/log && chown -R agent:agent /srv

## startup script that writes dshield.ini from env vars then lauches the agent

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

# checkov:skip=CKV_DOCKER_3:Container starts as root only to bind rsyslogd's socket and write dshield.ini; entrypoint.sh drops to the unprivileged 'agent' user via gosu before launching isc-agent itself. Static USER instruction is not applicable to this start-root-then-drop pattern.
ENTRYPOINT ["/entrypoint.sh"]

