BPF_SRC  := kernel/xdp_telemetry.c
BPF_OBJ  := kernel/xdp_telemetry.o
GO_BIN   := shield

ARCH := $(shell uname -m)

.PHONY: all build bpf clean test

all: bpf build

bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 \
		-I/usr/include/$(ARCH)-linux-gnu \
		-c $< -o $@

build: bpf
	go build -o $(GO_BIN) .

test:
	go test -v -count=1 ./...

clean:
	rm -f $(BPF_OBJ) $(GO_BIN)