package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/xdp_filter.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	InterfaceName = "wlan0"           // replace with your interface
	TestBlockIP   = "192.192.192.192" // IP to block
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

const (
	BLOCK_MANUAL = iota
	BLOCK_RATELIMIT
	BLOCK_L7_DETECT
	BLOCK_THREATFEED
	BLOCK_DDOS_PROTECT
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

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

func AddBlocked(v4, v6 *ebpf.Map, cidr string, duration time.Duration, reason uint32) error {
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
		key := LPMKey{PrefixLen: uint32(ones), IP: binary.LittleEndian.Uint32(ip4)}
		return v4.Put(key, value)
	}

	key := LPMKey6{PrefixLen: uint32(ones)}
	copy(key.IP[:], ipnet.IP.To16())
	return v6.Put(key, value)
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

func StartGC(v4, v6 *ebpf.Map) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		defer ticker.Stop()
		for range ticker.C {
			cleanupExpired[LPMKey](v4)
			cleanupExpired[LPMKey6](v6)
		}
	}()
}

func DumpMap(v4, v6 *ebpf.Map) { // felt cute might delete later (only for testing atm)
	fmt.Println("printing trie map contents:")

	var k4 LPMKey
	var val BlockInfo
	it4 := v4.Iterate()
	for it4.Next(&k4, &val) {
		fmt.Printf("%s/%d  expires=%d hits=%d reason=%d\n",
			keyIPString(k4), k4.PrefixLen, val.ExpiresAtNs, val.HitCount, val.Reason)
	}
	if err := it4.Err(); err != nil {
		log.Printf("v4 iterator error: %v", err)
	}

	var k6 LPMKey6
	it6 := v6.Iterate()
	for it6.Next(&k6, &val) {
		fmt.Printf("%s/%d  expires=%d hits=%d reason=%d\n",
			key6IPString(k6), k6.PrefixLen, val.ExpiresAtNs, val.HitCount, val.Reason)
	}
	if err := it6.Err(); err != nil {
		log.Printf("v6 iterator error: %v", err)
	}
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.Close()

	const ifaceName = InterfaceName // use ip link and use your interface name here
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %q: %v", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Filter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // works on any interfact includnig wifi
	})
	if err != nil {
		log.Fatalf("attach xdp: %v", err)
	}
	defer xdpLink.Close()

	fmt.Println("XDP attached to", iface.Name)

	must(AddBlocked(objs.LpmMap, objs.LpmMapIpv6, TestBlockIP, 5*time.Minute, BLOCK_THREATFEED))

	DumpMap(objs.LpmMap, objs.LpmMapIpv6)
	StartGC(objs.LpmMap, objs.LpmMapIpv6)

	fmt.Println("Running, press ctrl c to stop")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Println("Detaching XDP...")
}
