# Use Python 3.9 as base image
FROM python:3.9

# Update package lists and install dependencies
RUN apt update && apt install -y tcpdump libpcap-dev nano curl nmap

# Verify nmap installation
RUN which nmap && nmap --version

# Set working directory
WORKDIR /app

# Copy NIDS script and rules file
COPY nids.py rules.yml /app/

# Install Python dependencies
RUN pip install --no-cache-dir scapy elasticsearch pyyaml smtplib

# Start the NIDS script
CMD ["python3", "/app/nids.py"]
