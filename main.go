package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"cr4zygoat/iocextract/classes"
	"cr4zygoat/iocextract/utilities"
)

func main() {
	proot := flag.String("t", ".", "Target file or directory to analyze")
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

	output := make(chan string)
	go func() {
		extractor.ExtractIoCs(files, output)
		close(output)
	}()

	for ioc := range output {
		fmt.Println(ioc)
	}
}
