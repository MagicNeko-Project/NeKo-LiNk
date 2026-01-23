CLANG ?= clang
CFLAGS := -O2 -g -Wall -target bpf

all: bpf build

bpf: xdp/xdp_kern.o

xdp/xdp_kern.o: xdp/xdp_kern.c
	$(CLANG) $(CFLAGS) -c $< -o $@

build:
	go build -o neko-link main.go

clean:
	rm -f neko-link xdp/*.o
