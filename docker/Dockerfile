# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 – builder
#   Compiles load_balancer, controller, and the four XDP kernel objects against
#   libbpf + xdp-tools built from source.
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential        \
        git                    \
        clang                  \
        llvm                   \
        libelf-dev             \
        libpcap-dev            \
        linux-headers-generic  \
        linux-tools-generic    \
        pkg-config             \
        iproute2               \
        ca-certificates        \
        zlib1g-dev             \
        libz-dev               \
        m4                     \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── xdp-tools (provides libxdp, libxdp headers, and xdp-loader binary) ───────
RUN git clone --recurse-submodules --depth 1 \
        https://github.com/xdp-project/xdp-tools.git xdp-tools \
    && cd xdp-tools \
    && ./configure \
    && make -j"$(nproc)" \
    && make install PREFIX=/usr/local

# ── libbpf (bundled inside xdp-tools/lib/libbpf, already built above) ────────
RUN cd xdp-tools/lib/libbpf/src \
    && make install PREFIX=/usr/local

# ── Copy project sources ──────────────────────────────────────────────────────
# Place sources at /build/final/src/ so that the relative include
# "../../xdp-tools/headers/..." resolves to /build/xdp-tools/headers/...
COPY src/ /build/final/src/

# ── Build the four XDP kernel objects ─────────────────────────────────────────
# bal_kern_ingress: load-balancer input interface (client → LB)
RUN clang -O2 -g \
        -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/local/include \
        -I/usr/include/x86_64-linux-gnu \
        -I/build/xdp-tools/headers \
        -I/build/final/src \
        -c /build/final/src/bal_kern_ingress.c \
        -o /build/bal_kern_ingress.o

# bal_kern_egress: load-balancer output interfaces (LB → firewalls)
RUN clang -O2 -g \
        -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/local/include \
        -I/usr/include/x86_64-linux-gnu \
        -I/build/xdp-tools/headers \
        -I/build/final/src \
        -c /build/final/src/bal_kern_egress.c \
        -o /build/bal_kern_egress.o

# con_kern_ingress: controller input interfaces (firewalls → controller)
RUN clang -O2 -g \
        -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/local/include \
        -I/usr/include/x86_64-linux-gnu \
        -I/build/xdp-tools/headers \
        -I/build/final/src \
        -c /build/final/src/con_kern_ingress.c \
        -o /build/con_kern_ingress.o

# con_kern_egress: controller output interface (controller → server)
RUN clang -O2 -g \
        -target bpf \
        -D__TARGET_ARCH_x86 \
        -I/usr/local/include \
        -I/usr/include/x86_64-linux-gnu \
        -I/build/xdp-tools/headers \
        -I/build/final/src \
        -c /build/final/src/con_kern_egress.c \
        -o /build/con_kern_egress.o

# ── Build load_balancer ───────────────────────────────────────────────────────
RUN gcc -O2 -g \
        -I/usr/local/include \
        -I/build/xdp-tools/headers \
        -I/build/final/src \
        /build/final/src/load_balancer.c \
        -o /build/load_balancer \
        -L/usr/local/lib \
        -lxdp -lbpf -lelf -lz -lpthread

# ── Build controller ──────────────────────────────────────────────────────────
RUN gcc -O2 -g \
        -I/usr/local/include \
        -I/build/xdp-tools/headers \
        -I/build/final/src \
        /build/final/src/controller.c \
        -o /build/controller \
        -L/usr/local/lib \
        -lxdp -lbpf -lelf -lz -lpthread


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 – runtime base image
#   Shared by load_balancer and controller containers.
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS runtime-base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2      \
        iputils-ping  \
        tcpdump       \
        libelf1       \
        zlib1g        \
        ethtool       \
        kmod          \
        strace        \
    && rm -rf /var/lib/apt/lists/*

# Shared libraries and xdp-loader from builder
COPY --from=builder /usr/local/lib/libxdp.so*   /usr/local/lib/
COPY --from=builder /usr/local/lib/libbpf.so*   /usr/local/lib/
COPY --from=builder /usr/local/sbin/xdp-loader  /usr/local/sbin/xdp-loader
RUN ldconfig

# XDP kernel objects for load_balancer (bal_*) and controller (con_*)
COPY --from=builder /build/bal_kern_ingress.o  /opt/xdp/bal_kern_ingress.o
COPY --from=builder /build/bal_kern_egress.o   /opt/xdp/bal_kern_egress.o
COPY --from=builder /build/con_kern_ingress.o  /opt/xdp/con_kern_ingress.o
COPY --from=builder /build/con_kern_egress.o   /opt/xdp/con_kern_egress.o


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3a – load_balancer image
# ─────────────────────────────────────────────────────────────────────────────
FROM runtime-base AS load_balancer

COPY --from=builder /build/load_balancer        /usr/local/bin/load_balancer
COPY docker/load_balancer_entrypoint.sh         /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3b – controller image
# ─────────────────────────────────────────────────────────────────────────────
FROM runtime-base AS controller

COPY --from=builder /build/controller           /usr/local/bin/controller
COPY docker/controller_entrypoint.sh            /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3c – traffic generator (client / server / firewall simulator)
# ─────────────────────────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS traffic-gen

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2        \
        iptables        \
        iputils-ping    \
        tcpdump         \
        ncat            \
        iperf3          \
        hping3          \
        python3         \
        python3-scapy   \
        ethtool         \
    && rm -rf /var/lib/apt/lists/*

COPY docker/traffic_gen.py              /usr/local/bin/traffic_gen.py
COPY docker/net_setup.sh               /usr/local/bin/net_setup.sh
COPY docker/firewall_sim_entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/traffic_gen.py \
             /usr/local/bin/net_setup.sh   \
             /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
