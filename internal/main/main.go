package main

import (
	"log"
	filter "nginxray/internal/filter"
	sniffer "nginxray/internal/sniffer"
	"time"
)

func main() {
	// get filter started
	fw, err := filter.New(filter.InterfaceName)
	if err != nil {
		log.Fatal(err)
	}
	defer fw.Close()

	fw.StartGC()
	fw.AddBlocked(filter.TestBlockIP, 5*time.Minute, filter.BLOCK_THREATFEED)

	sniffer.Main(fw)
}
