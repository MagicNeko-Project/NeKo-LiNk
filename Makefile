CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

all: bpf build

bpf: bpf/xdp_kern.o

bpf/xdp_kern.o: bpf/xdp_kern.c
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	go build -o vpn main.go

clean:
	rm -f vpn bpf/*.o
