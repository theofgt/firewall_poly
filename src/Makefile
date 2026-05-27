PROGS = controller load_balancer

CC = clang

CFLAGS = -O2 -g -Wall -I../xdp-tools/headers

BPF_CFLAGS = -O2 -g -Wall -target bpf

LDFLAGS = -L../xdp-tools/lib/libxdp -lxdp -lbpf -lelf -pthread

BPF_OBJ = bal_kern_egress.o bal_kern_ingress.o con_kern_ingress.o con_kern_egress.o

TMP = *.tmp

all: $(PROGS) $(BPF_OBJ)

%: %.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(PROGS) $(BPF_OBJ) $(TMP)