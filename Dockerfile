FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    openvswitch-switch \
    mininet \
    hping3 \
    iperf \
    curl \
    net-tools \
    iproute2 \
    iputils-ping \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install "eventlet>=0.30.2,<0.34.0" && \
    pip3 install -r requirements.txt && \
    RYU_DIR=$(python3 -c "import ryu, os; print(os.path.dirname(ryu.__file__))" 2>/dev/null || true) && \
    if [ -n "$RYU_DIR" ]; then \
        grep -rl "collections.MutableMapping" "$RYU_DIR" 2>/dev/null | xargs -r sed -i 's/collections\.MutableMapping/collections\.abc\.MutableMapping/g' || true; \
    fi

COPY . .

EXPOSE 5000 6653

CMD ["/bin/bash", "./run_all.sh"]
