package filter

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/xdp_filter.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type LPMKey struct {
	PrefixLen uint32
	IP        uint32
}
type LPMKey6 struct {
	PrefixLen uint32
	IP        [16]byte
}

type BlockInfo struct {
	ExpiresAtNs uint64
	HitCount    uint64
	Reason      uint32
	_           uint32
}

// manages the XDP filter and blocklist maps
type Filter struct {
	objs    bpfObjects
	xdpLink link.Link
}

const (
	BLOCK_MANUAL = iota
	BLOCK_RATELIMIT
	BLOCK_L7_DETECT
	BLOCK_THREATFEED
	BLOCK_DDOS_PROTECT
)

func monotonicNowNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("clock_gettime: %v", err)
	}
	return uint64(ts.Nano())
}

func keyIPString(key LPMKey) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], key.IP)
	return net.IP(b[:]).String()
}

func key6IPString(key LPMKey6) string {
	return net.IP(key.IP[:]).String()
}

// method on filter so its possible for sniffer program to use it
func (f *Filter) AddBlocked(cidr string, duration time.Duration, reason uint32) error {
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr += "/128" // bare IPv6
		} else {
			cidr += "/32" // bare IPv4
		}
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ones, _ := ipnet.Mask.Size() // 0-32 for v4 and 0-128 for v6

	value := BlockInfo{
		ExpiresAtNs: monotonicNowNS() + uint64(duration.Nanoseconds()),
		Reason:      reason,
	}

	if ip4 := ipnet.IP.To4(); ip4 != nil {
		key := LPMKey{
			PrefixLen: uint32(ones),
			IP:        binary.LittleEndian.Uint32(ip4),
		}
		return f.objs.LpmMap.Put(key, value)
	}

	key := LPMKey6{PrefixLen: uint32(ones)}
	copy(key.IP[:], ipnet.IP.To16())
	return f.objs.LpmMapIpv6.Put(key, value)
}

func cleanupExpired[K any](m *ebpf.Map) { // clean expired entries from the map
	now := monotonicNowNS()

	var (
		key     K
		value   BlockInfo
		expired []K
	)

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value.ExpiresAtNs != 0 && now > value.ExpiresAtNs {
			expired = append(expired, key)
		}
	}
	if err := iter.Err(); err != nil {
		log.Printf("iterator error: %v", err)
		return
	}

	for _, k := range expired {
		if err := m.Delete(k); err != nil {
			log.Printf("delete failed: %v", err)
		}
	}
}

func (f *Filter) StartGC() {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpired[LPMKey](f.objs.LpmMap)
			cleanupExpired[LPMKey6](f.objs.LpmMapIpv6)
		}
	}()
}

func (f *Filter) DumpMap() { // felt cute might delete later (only for testing atm)
	fmt.Println("printing trie map contents:")

	var k4 LPMKey
	var val BlockInfo
	it4 := f.objs.LpmMap.Iterate()
	for it4.Next(&k4, &val) {
		fmt.Printf("%s/%d  expires=%d hits=%d reason=%d\n",
			keyIPString(k4), k4.PrefixLen, val.ExpiresAtNs, val.HitCount, val.Reason)
	}
	if err := it4.Err(); err != nil {
		log.Printf("v4 iterator error: %v", err)
	}

	var k6 LPMKey6
	it6 := f.objs.LpmMapIpv6.Iterate()
	for it6.Next(&k6, &val) {
		fmt.Printf("%s/%d  expires=%d hits=%d reason=%d\n",
			key6IPString(k6), k6.PrefixLen, val.ExpiresAtNs, val.HitCount, val.Reason)
	}
	if err := it6.Err(); err != nil {
		log.Printf("v6 iterator error: %v", err)
	}
}

// detach XDP and free BPF resources
func (f *Filter) Close() {
	_ = f.xdpLink.Close()
	f.objs.Close()
}

func New(ifaceName string) (*Filter, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		objs.Close()
		return nil, err
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Filter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // works on any interface including wifi
	})
	if err != nil {
		objs.Close()
		return nil, err
	}

	fmt.Println("XDP attached to", iface.Name)

	return &Filter{
		objs:    objs,
		xdpLink: xdpLink,
	}, nil
}
