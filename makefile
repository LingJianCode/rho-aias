APP := rho-aias
GO ?= go
BPF_GEN_DIR := ./internal/ebpfs
TEST_DIR := ./test

.PHONY: all gen build run clean test help

all: gen build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h

gen:
	$(GO) generate $(BPF_GEN_DIR)

build:
	@echo "==> Building"
	$(GO) build -o $(APP)

run: all
	@echo "==> Running"
	sudo ./$(APP)

clean:
	@echo "==> Cleaning"
	rm -vf $(APP) $(BPF_GEN_DIR)/*_bpfeb.go $(BPF_GEN_DIR)/*_bpfel.go $(BPF_GEN_DIR)/*.o

test:
	@echo "==> Running tests"
	python3 $(TEST_DIR)/packet_generator.py 192.168.110.139 all

help:
	@echo "Targets:"
	@echo "  make all    - 编译"
	@echo "  make run    - 运行"
	@echo "  make clean  - 清理"
	@echo "  make test   - 测试"
