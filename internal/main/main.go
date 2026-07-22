package main

import (
	"flag"
	"log"
	"time"
	filter "nginxray/internal/filter"
	h3sniffer "nginxray/internal/http3_sniffer"
	sniffer "nginxray/internal/sniffer"
)

var enableH3Sniffer = flag.Bool("h3sniffer", false, "also run the HTTP/3 header sniffer alongside the SSL sniffer")

func main() {
	flag.Parse()

	// get filter started
	fw, err := filter.New(filter.InterfaceName)
	if err != nil {
		log.Fatal(err)
	}
	defer fw.Close()

	fw.StartGC()
	fw.AddBlocked(filter.TestBlockIP, 5*time.Minute, filter.BLOCK_THREATFEED)

	if *enableH3Sniffer {
		go h3sniffer.Main(fw)
	}

	sniffer.Main(fw)
}
