package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sync"
)

const REGEX_IP string = "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
const REGEX_URL string = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

func getFiles(cdir string) []string {
	var files, dirs []string
	dirs = append(dirs, cdir)

	for len(dirs) > 0 {
		var cdir string = dirs[0]
		dirs = dirs[1:]

		filenames, err := os.ReadDir(cdir)
		if err != nil {
			log.Fatalln(err)
		}

		for _, f := range filenames {
			fullpath := fmt.Sprintf("%s/%s", cdir, f.Name())
			if f.IsDir() {
				dirs = append(dirs, fullpath)
			} else {
				files = append(files, fullpath)
			}
		}
	}

	return files
}

func getFileSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

func getFileIPs(data []byte) []string {
	rex, err := regexp.Compile(REGEX_IP)
	if err != nil {
		log.Fatalln(err)
	}

	var ips []string
	matches := rex.FindAll(data, -1)
	for _, match := range matches {
		ips = append(ips, string(match))
	}
	return ips
}

func getFileURLs(data []byte) []string {
	rex, err := regexp.Compile(REGEX_URL)
	if err != nil {
		log.Fatalln(err)
	}

	var urls []string
	matches := rex.FindAll(data, -1)
	for _, match := range matches {
		urls = append(urls, string(match))
	}
	return urls
}

func getFileIOCs(filename string) []string {
	var iocs []string
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalln(err)
	}

	iocs = append(iocs, getFileSHA256(content))
	iocs = append(iocs, getFileIPs(content)...)
	iocs = append(iocs, getFileURLs(content)...)
	return iocs
}

func main() {
	var target string
	var files []string

	flag.StringVar(&target, "f", ".", "Target file or directory")
	flag.Parse()

	asset, err := os.Stat(target)
	if err != nil {
		log.Fatalln(err)
	}

	if asset.IsDir() {
		files = getFiles(target)
	} else {
		files = append(files, target)
	}

	wg := new(sync.WaitGroup)
	wg.Add(len(files))

	for _, filename := range files {
		go func(filename string) {
			defer wg.Done()
			for _, ioc := range getFileIOCs(filename) {
				fmt.Println(ioc)
			}
		}(filename)
	}

	wg.Wait()
}
