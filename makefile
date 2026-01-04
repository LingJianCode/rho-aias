APP := rho-aias
GO ?= go
BPF_GEN_DIR := ./internal/ebpf

all: gen build

vmlinux.h: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

gen: ebpf/xdp.bpf.c
	$(GO) generate $(BPF_GEN_DIR)

build: main.go
	@echo "==> Building Go binary"
	$(GO) build -o $(APP)

# ---------- run ----------
run: all
	sudo ./$(APP)

# ---------- clean ----------
clean:
	@echo "==> Cleaning"
	rm -vf $(APP) $(BPF_GEN_DIR)/*_bpfeb.go $(BPF_GEN_DIR)/*_bpfel.go $(BPF_GEN_DIR)/*.o
