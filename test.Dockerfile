FROM haproxy:2.8

USER root

# Install dependencies for building vtest
RUN apt-get update && apt-get install -y \
    git \
    make \
    gcc \
    libc-dev \
    python3 \
    zlib1g-dev \
    libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install vtest
RUN git clone https://github.com/vtest/vtest.git /tmp/vtest \
    && cd /tmp/vtest \
    && make \
    && install -m755 vtest /usr/local/bin/vtest \
    && rm -rf /tmp/vtest

WORKDIR /app
COPY . .

# Run the tests
CMD ["sh", "-c", "vtest -Dhaproxy_version=2.8 -k -t 10 test/*.vtc"]
