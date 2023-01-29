package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/cr4zygoat/iocextract/classes"
	"github.com/cr4zygoat/iocextract/utilities"
)

func main() {
	proot := flag.String("f", ".", "Target file or directory to analyze")
	pscanhash := flag.Bool("hash", false, "Just scan for hashes")
	pscanip := flag.Bool("ip", false, "Just scan for IPs")
	pscanurl := flag.Bool("url", false, "Just scan for URLs")
	pscandomain := flag.Bool("domain", false, "Just scan for domains")
	flag.Parse()

	var root string = *proot
	oroot, err := os.Stat(root)
	if err != nil {
		log.Fatalln(err)
	}

	var files []string
	if oroot.IsDir() {
		fls, errors := utilities.GetRecursiveFiles(root)
		files = append(files, fls...)
		for err := range errors {
			log.Println(err)
		}
	} else {
		files = append(files, root)
	}

	tlds, err := utilities.FetchTLDs()
	if err != nil {
		log.Println(err)
	}

	extractor := classes.NewExtractor()
	extractor.TLDs = tlds

	if *pscanhash || *pscanip || *pscanurl || *pscandomain {
		extractor.IoCTypes.Hash = *pscanhash
		extractor.IoCTypes.Ip = *pscanip
		extractor.IoCTypes.Url = *pscanurl
		extractor.IoCTypes.Domain = *pscandomain
	}

	output := make(chan string)
	go func() {
		extractor.ExtractIoCs(files, output)
		close(output)
	}()

	for ioc := range output {
		fmt.Println(ioc)
	}
}
