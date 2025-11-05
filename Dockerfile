FROM ubuntu:22.04

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-dev \
    git \
    mininet \
    openvswitch-switch \
    suricata \
    redis-server \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Expose ports
EXPOSE 6653 8080 8000 5001

# Create directories
RUN mkdir -p /var/log/sdn-nidps /var/lib/sdn-nidps

# Set entrypoint
CMD ["bash", "scripts/start_all.sh"]
