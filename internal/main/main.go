package main

import (
	"log"
	filter "nginxray/internal/filter"
	h3sniffer "nginxray/internal/http3_sniffer"
	sniffer "nginxray/internal/sniffer"
)

func main() {
	// get filter started
	fw, err := filter.New(filter.InterfaceName)
	if err != nil {
		log.Fatal(err)
	}
	defer fw.Close()

	fw.StartGC()

	go sniffer.Main(fw)
	h3sniffer.Main(fw)
}
