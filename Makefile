CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf -Ixdp -I/usr/include/x86_64-linux-gnu

# Check for local Go installation
GO := $(shell if [ -f ./.go/bin/go ]; then echo "./.go/bin/go"; else echo "go"; fi)

all: bpf build

bpf: xdp/xdp_kern.o

xdp/xdp_kern.o: xdp/xdp_kern.c
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	$(GO) mod tidy
	$(GO) build -o neko-link .

clean:
	rm -f neko-link xdp/*.o
