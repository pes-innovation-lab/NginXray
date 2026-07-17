.PHONY: all setup vmlinux deps build generate clean filter sniffer h3sniffer run-sniffer run-h3sniffer fmt help docker-up docker-down docker-restart docker-logs docker-ps

FILTER_DIR    := internal/filter
SNIFFER_DIR   := internal/sniffer
H3SNIFFER_DIR := internal/http3_sniffer

FILTER_BIN    := $(FILTER_DIR)/xdp-loader
SNIFFER_BIN   := $(SNIFFER_DIR)/sniffer
H3SNIFFER_BIN := $(H3SNIFFER_DIR)/http3-sniffer

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
generateh3sniffer:
	@echo "Generating eBPF bytecode (http3_sniffer)..."
	cd $(H3SNIFFER_DIR) && go generate


build: filter sniffer 

filter: generatefilter
	@echo "Building XDP loader..."
	cd $(FILTER_DIR) && go build -buildvcs=false -o xdp-loader
	@echo "Build complete: ./$(FILTER_BIN)"

sniffer: generatesniffer
	@echo "Building SSL sniffer..."
	cd $(SNIFFER_DIR) && go build -buildvcs=false -o sniffer
	@echo "Build complete: ./$(SNIFFER_BIN)"

h3sniffer: generateh3sniffer
	@echo "Building HTTP/3 header sniffer..."
	cd $(H3SNIFFER_DIR) && go build -buildvcs=false -o http3-sniffer
	@echo "Build complete: ./$(H3SNIFFER_BIN)"


run-sniffer:
	sudo ./$(SNIFFER_BIN)

run-h3sniffer:
	sudo ./$(H3SNIFFER_BIN)


deps:
	@echo "Tidying Go dependencies..."
	go mod tidy
	@echo "Dependencies ready"

docker-up:
	@echo "Starting Elasticsearch and Kibana..."
	sudo docker compose up -d

docker-down:
	@echo "Stopping Elasticsearch and Kibana..."
	sudo docker compose down

docker-restart:
	@echo "Restarting Elasticsearch and Kibana..."
	sudo docker compose down
	sudo docker compose up -d

docker-logs:
	sudo docker compose logs -f

docker-ps:
	sudo docker compose ps

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
	rm -f $(FILTER_BIN) $(SNIFFER_BIN) $(H3SNIFFER_BIN)
	rm -f $(FILTER_DIR)/bpf_bpfel.go  $(FILTER_DIR)/bpf_bpfel.o
	rm -f $(FILTER_DIR)/bpf_bpfeb.go  $(FILTER_DIR)/bpf_bpfeb.o
	rm -f $(SNIFFER_DIR)/bpf_bpfel.go $(SNIFFER_DIR)/bpf_bpfel.o
	rm -f $(SNIFFER_DIR)/bpf_bpfeb.go $(SNIFFER_DIR)/bpf_bpfeb.o
	rm -f $(H3SNIFFER_DIR)/h3_bpfel.go $(H3SNIFFER_DIR)/h3_bpfel.o
	rm -f $(H3SNIFFER_DIR)/h3_bpfeb.go $(H3SNIFFER_DIR)/h3_bpfeb.o
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
	@echo "  make h3sniffer          - Build only the HTTP/3 header sniffer"
	@echo "  make generatefilter     - Run bpf2go codegen in filter dir"
	@echo "  make generatesniffer    - Run bpf2go codegen in sniffer dir"
	@echo "  make generateh3sniffer  - Run bpf2go codegen in http3_sniffer dir"
	@echo "  make vmlinux            - Force-regenerate bpf/vmlinux.h (after kernel change)"
	@echo "  make clean              - Remove binaries and generated bpf files"
	@echo "  make deps               - go mod tidy"
	@echo "  make fmt                - go fmt ./..."
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up        - Start Elasticsearch and Kibana"
	@echo "  make docker-down      - Stop and remove containers"
	@echo "  make docker-restart   - Restart the Docker services"
	@echo "  make docker-logs      - Follow container logs"
	@echo "  make docker-ps        - Show running containers"
	@echo ""
	@echo "Run (requires sudo):"
	@echo "  make run-sniffer     - Build + run the SSL sniffer as root"
	@echo "  make run-h3sniffer   - Build + run the HTTP/3 header sniffer as root"
