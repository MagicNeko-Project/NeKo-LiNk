CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

# Check for local Go installation
GO := $(shell if [ -f ./.go/bin/go ]; then echo "./.go/bin/go"; else echo "go"; fi)

all: bpf build

bpf: xdp/xdp_kern.o

xdp/xdp_kern.o: xdp/xdp_kern.c
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	$(GO) mod tidy
	$(GO) build -o neko-link main.go

clean:
	rm -f neko-link xdp/*.o
