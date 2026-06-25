.PHONY: all build generate clean filter sniffer run-filter run-sniffer deps fmt help

FILTER_DIR  := internal/filter
SNIFFER_DIR := internal/sniffer

FILTER_BIN  := $(FILTER_DIR)/xdp-loader
SNIFFER_BIN := $(SNIFFER_DIR)/sniffer

all: build

generate:
	@echo "Generating eBPF bytecode (filter)..."
	cd $(FILTER_DIR) && go generate
	@echo "Generating eBPF bytecode (sniffer)..."
	cd $(SNIFFER_DIR) && go generate


build: filter sniffer

filter: generate
	@echo "Building XDP loader..."
	cd $(FILTER_DIR) && go build -buildvcs=false -o xdp-loader
	@echo "Build complete: ./$(FILTER_BIN)"

sniffer: generate
	@echo "Building SSL sniffer..."
	cd $(SNIFFER_DIR) && go build -buildvcs=false -o sniffer
	@echo "Build complete: ./$(SNIFFER_BIN)"

run-filter: filter
	sudo ./$(FILTER_BIN)

run-sniffer: sniffer
	sudo ./$(SNIFFER_BIN)


deps:
	go mod download
	@echo "Dependencies installed"

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
	@echo "Build:"
	@echo "  make build        - Generate eBPF + build both binaries"
	@echo "  make filter       - Build only the XDP loader"
	@echo "  make sniffer      - Build only the SSL sniffer"
	@echo "  make generate     - Run bpf2go codegen in both dirs"
	@echo "  make clean        - Remove binaries and generated bpf files"
	@echo "  make deps         - go mod download"
	@echo "  make fmt          - go fmt ./..."
	@echo ""
	@echo "Run (requires sudo):"
	@echo "  make run-filter   - Build + run the XDP loader as root"
	@echo "  make run-sniffer  - Build + run the SSL sniffer as root"
