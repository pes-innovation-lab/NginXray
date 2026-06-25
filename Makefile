.PHONY: all setup vmlinux deps build generate clean filter sniffer run-filter run-sniffer fmt help

FILTER_DIR  := internal/filter
SNIFFER_DIR := internal/sniffer

FILTER_BIN  := $(FILTER_DIR)/xdp-loader
SNIFFER_BIN := $(SNIFFER_DIR)/sniffer

BPF_DIR := bpf
VMLINUX := $(BPF_DIR)/vmlinux.h

all: build

setup: $(VMLINUX) deps
	@echo "Setup complete, you can now run 'make build'"

generatefilter:
	@echo "Generating eBPF bytecode (filter)..."
	cd $(FILTER_DIR) && go generate
generatesniffer:
	@echo "Generating eBPF bytecode (sniffer)..."
	cd $(SNIFFER_DIR) && go generate


build: filter sniffer

filter: generatefilter
	@echo "Building XDP loader..."
	cd $(FILTER_DIR) && go build -buildvcs=false -o xdp-loader
	@echo "Build complete: ./$(FILTER_BIN)"

sniffer: generatesniffer
	@echo "Building SSL sniffer..."
	cd $(SNIFFER_DIR) && go build -buildvcs=false -o sniffer
	@echo "Build complete: ./$(SNIFFER_BIN)"

run-filter: 
	sudo ./$(FILTER_BIN)

run-sniffer: 
	sudo ./$(SNIFFER_BIN)


deps:
	@echo "Tidying Go dependencies..."
	go mod tidy
	@echo "Dependencies ready"


# auto-generates only if missing, so a fresh clone bootstraps itself.
# Needs root to read kernel BTF info
$(VMLINUX):
	@echo "vmlinux.h missing — generating from kernel BTF..."
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "Wrote $(VMLINUX)"	
 
vmlinux:
	@echo "Regenerating vmlinux.h from kernel BTF..."
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "Wrote $(VMLINUX)"

fmt:
	go fmt ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(FILTER_BIN) $(SNIFFER_BIN)
	rm -f $(FILTER_DIR)/bpf_bpfel.go  $(FILTER_DIR)/bpf_bpfel.o
	rm -f $(FILTER_DIR)/bpf_bpfeb.go  $(FILTER_DIR)/bpf_bpfeb.o
	rm -f $(SNIFFER_DIR)/bpf_bpfel.go $(SNIFFER_DIR)/bpf_bpfel.o
	rm -f $(SNIFFER_DIR)/bpf_bpfeb.go $(SNIFFER_DIR)/bpf_bpfeb.o
	@echo "Clean complete"

help:
	@echo "NginXray - Makefile"
	@echo "==================="
	@echo ""
	@echo "First time (fresh clone):"
	@echo "  make setup        - Generate vmlinux.h + tidy Go deps"
	@echo ""
	@echo "Build:"
	@echo "  make build              - Generate eBPF + build both binaries"
	@echo "  make filter             - Build only the XDP loader"
	@echo "  make sniffer            - Build only the SSL sniffer"
	@echo "  make generatefilter     - Run bpf2go codegen in filter dir"
	@echo "  make generatesniffer    - Run bpf2go codegen in sniffer dir"
	@echo "  make vmlinux            - Force-regenerate bpf/vmlinux.h (after kernel change)"
	@echo "  make clean              - Remove binaries and generated bpf files"
	@echo "  make deps               - go mod tidy"
	@echo "  make fmt                - go fmt ./..."
	@echo ""
	@echo "Run (requires sudo):"
	@echo "  make run-filter   - Build + run the XDP loader as root"
	@echo "  make run-sniffer  - Build + run the SSL sniffer as root"
