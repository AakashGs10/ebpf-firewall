TARGET := xdp_telemetry.o
SRC := xdp_telemetry.c

all: $(TARGET)

$(TARGET): $(SRC)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/$(shell uname -m)-linux-gnu -c $< -o $@

clean:
	rm -f $(TARGET)