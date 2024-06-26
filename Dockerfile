# Author: Daniëlle van der Tuin
# Version: 1.0 Alpine build

# Gebruik Alpine Linux als basisimage
FROM alpine:latest

# Update de package lijst en installeer benodigde packages
RUN apk update && apk upgrade && \
    apk add --no-cache \
    bash \
    build-base \
    libffi-dev \
    openssl-dev \
    libpcap-dev \
    python3 \
    python3-dev \
    py3-pip \
    nmap \
    nmap-scripts \
    iproute2

# Maak en activeer een Python virtuele omgeving
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Installeer scapy en andere Python-packages binnen de virtuele omgeving
RUN pip3 install --no-cache-dir \
    scapy \
    python-nmap \
    scapy-python3 \
    pyfiglet \
    ipaddress

# Copy the current directory contents into the container at /app
COPY . /app

# Stel het werkingsdirectory in
WORKDIR /app

# zorg dat de container open blijft (uncomment voor testen)
# ENTRYPOINT ["tail", "-f", "/dev/null"]

# laat de container direct de scan uitvoeren bij opstarten (comment voor testen)
CMD ["python", "netwerkscan.py"]