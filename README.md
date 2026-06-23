# NginXray
Kernel-Level Edge Defense & Plaintext L7 Observability: An eBPF-Based Security Agent for Nginx with Go Integration 
Mentors: Prachi Jha, Murali Krishna Rao
Interns: Uttam K R, Sarah Kazi, Rehaan Jose Mathew 

(temporary)
## Dependencies

### Arch Linux

```bash
sudo pacman -S go clang bpftool
```

### Ubuntu

```bash
sudo apt update
sudo apt install golang clang bpftool
```

## Setup

Generate `vmlinux.h`:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

Install Go dependencies:

```bash
go mod tidy
```

## Run

### XDP Filter

```bash
cd internal/filter
go generate
go run .
```

### SSL Sniffer

```bash
cd internal/sniffer
go generate
go run .
```
