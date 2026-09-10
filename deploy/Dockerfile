# WiFiGuard needs nothing but a Python interpreter, so the image is the base
# image plus the source. No build step, no wheels, no dependency resolution.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        iproute2 nftables wireguard-tools iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/wifiguard
COPY wifiguard/ ./wifiguard/
COPY pyproject.toml README.md ./

RUN python -m compileall -q wifiguard \
 && printf '#!/bin/sh\nexec python -m wifiguard.cli "$@"\n' > /usr/local/bin/wifiguard \
 && chmod +x /usr/local/bin/wifiguard

ENV WIFIGUARD_STATE=/var/lib/wifiguard
VOLUME ["/var/lib/wifiguard", "/etc/wifiguard"]

EXPOSE 53/udp 53/tcp 8080/tcp 51820/udp

# The self-test needs no network and no privileges, so it is a genuine health
# signal rather than a liveness ping.
HEALTHCHECK --interval=60s --timeout=30s --start-period=20s --retries=3 \
    CMD python -m wifiguard.cli selftest --port 15353 >/dev/null 2>&1 || exit 1

ENTRYPOINT ["wifiguard"]
CMD ["run"]
