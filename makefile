APP := rho-aias
GO ?= go
BPF_GEN_DIR := ./internal/ebpfs

.PHONY: all gen build run clean test lint coverage help

all: gen build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h

gen: vmlinux.h
	$(GO) generate $(BPF_GEN_DIR)

build: gen
	@echo "==> Building"
	$(GO) build -o $(APP) ./cmd/server

run: all
	@echo "==> Running"
	sudo ./$(APP)

clean:
	@echo "==> Cleaning"
	rm -vf $(APP) $(BPF_GEN_DIR)/*_bpfeb.go $(BPF_GEN_DIR)/*_bpfel.go $(BPF_GEN_DIR)/*.o

test:
	@echo "==> Testing"
	$(GO) test -v ./...

GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null || echo "$(shell $(GO) env GOPATH)/bin/golangci-lint")

lint:
	@echo "==> Running go vet"
	$(GO) vet ./...
	@echo "==> Running golangci-lint"
	@command -v golangci-lint >/dev/null 2>&1 || $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOLANGCI_LINT) run ./...

help:
	@echo "Targets:"
	@echo "  make all       - 生成并编译"
	@echo "  make gen       - 生成 eBPF Go 代码"
	@echo "  make build     - 编译程序"
	@echo "  make run       - 运行程序（需要 root）"
	@echo "  make clean     - 清理构建产物"
	@echo "  make test      - 运行单元测试"
	@echo "  make lint      - 运行静态检查（go vet / staticcheck / golangci-lint）"

