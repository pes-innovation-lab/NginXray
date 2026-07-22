package main_h3

import (
	"flag"
	"log"
	filter "nginxray/internal/filter"
	h3sniffer "nginxray/internal/http3_sniffer"
	sniffer "nginxray/internal/sniffer"
	"time"
)

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

	go h3sniffer.Main(fw)
	sniffer.Main(fw)
}
