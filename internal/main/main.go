package main

import (
	"log"
	filter "nginxray/internal/filter"
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

	sniffer.Main(fw)
}
