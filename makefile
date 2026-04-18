APP := rho-aias
GO ?= go
BPF_GEN_DIR := ./internal/ebpfs
WEB_DIR := ./web

.PHONY: all gen build run clean test lint coverage help frontend

all: gen build

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpfs/vmlinux.h

# 前端构建：Vue + Vite 打包，产物复制到 internal/frontend/dist（供 go:embed 引用）
frontend:
	@echo "==> Building Frontend (Vue + Vite)"
	cd $(WEB_DIR) && npm install && npm run build
	@echo "==> Copying dist contents to internal/frontend/dist"
	rm -rf internal/frontend/dist
	mkdir -p internal/frontend/dist
	cp -r $(WEB_DIR)/dist/* internal/frontend/dist/

# 仅生成 eBPF 代码（不包含前端）
gen: vmlinux.h
	$(GO) generate $(BPF_GEN_DIR)

backend: gen
	@echo "==> Building"
	$(GO) build -o $(APP) ./cmd/server

build: frontend gen backend

run: all
	@echo "==> Running"
	sudo ./$(APP)

clean:
	@echo "==> Cleaning"
	rm -vf $(APP) $(BPF_GEN_DIR)/*_bpfeb.go $(BPF_GEN_DIR)/*_bpfel.go $(BPF_GEN_DIR)/*.o
	cd $(WEB_DIR) && rm -rf dist node_modules
	rm -rf frontend/web/dist

test:
	@echo "==> Testing"
	$(GO) test ./...

GOLANGCI_LINT := $(shell command -v golangci-lint 2>/dev/null || echo "$(shell $(GO) env GOPATH)/bin/golangci-lint")

lint:
	@echo "==> Running go vet"
	$(GO) vet ./...
	@echo "==> Running golangci-lint"
	@command -v golangci-lint >/dev/null 2>&1 || $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOLANGCI_LINT) run ./...

help:
	@echo "Targets:"
	@echo "  make all           - 完整构建（前端 + eBPF + 后端）"
	@echo "  make frontend      - 仅构建前端（Vue + Vite），产物留在 web/dist"
	@echo "  make gen           - 生成 eBPF Go 代码"
	@echo "  make build         - 完整编译（自动先构建前端 + eBPF，再编译后端）"
	@echo "  make run           - 运行程序（需要 root，执行完整构建）"
	@echo "  make clean         - 清理所有构建产物（含前端）"
	@echo "  make test      - 运行单元测试"
	@echo "  make lint      - 运行静态检查（go vet / staticcheck / golangci-lint）"

