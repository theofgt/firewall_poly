
## Quick start

All commands are run from the `docker/` directory where `docker-compose.yml` lives.

```bash
cd final/docker

# 1. Build all images (builder stage compiles everything from source)
docker compose build

# 2. Start the full topology
#    Order: net-setup → load_balancer → controller → fw0-3 → client/server
docker compose up -d

# 3. Watch live logs
docker compose logs -f load_balancer controller client server
```

## Tests

```bash
cd final/tests

# Correctness tests

./run_tests.sh

# Throughput test

sudo python3 throughput_iperf3.py --bandwith {100M, 500M, 750M, 1G}