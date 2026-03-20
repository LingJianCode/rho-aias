APP := rho-aias
GO ?= go
BPF_GEN_DIR := ./internal/ebpfs

.PHONY: all gen build run clean test coverage help

all: gen build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h

gen: vmlinux.h
	$(GO) generate $(BPF_GEN_DIR)

build: gen
	@echo "==> Building"
	$(GO) build -o $(APP)

run: all
	@echo "==> Running"
	sudo ./$(APP)

clean:
	@echo "==> Cleaning"
	rm -vf $(APP) $(BPF_GEN_DIR)/*_bpfeb.go $(BPF_GEN_DIR)/*_bpfel.go $(BPF_GEN_DIR)/*.o

test:
	@echo "==> Testing"
	$(GO) test -v ./...

help:
	@echo "Targets:"
	@echo "  make all       - 生成并编译"
	@echo "  make gen       - 生成 eBPF Go 代码"
	@echo "  make build     - 编译程序"
	@echo "  make run       - 运行程序（需要 root）"
	@echo "  make clean     - 清理构建产物"
	@echo "  make test      - 运行单元测试"

