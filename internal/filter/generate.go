package main
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/xdp_filter.bpf.c -- -I/usr/include
