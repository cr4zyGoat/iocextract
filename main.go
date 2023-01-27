package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

const (
	TLDS_RESOURCE = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	REGEX_IPV4    = "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	REGEX_IPV6    = "((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}"
	REGEX_URL     = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
	REGEX_DOMAIN  = "([A-Za-z0-9]|(?i:[a-z0-9])(?-i:[A-Z])|(?i:[A-Z])(?-i:[a-z])-?){1,63}(\\.[A-Za-z]{2,6})"
	REGEX_MD5     = "[0-9A-Fa-f]{32}"
	REGEX_SHA1    = "[A-Fa-f0-9]{40}"
	REGEX_SHA256  = "[A-Fa-f0-9]{64}"
)

var (
	tlds []string
)

func getTLDs() {
	res, err := http.Get(TLDS_RESOURCE)
	if err != nil {
		log.Println(err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	content := strings.ToLower(string(body))
	tlds = strings.Split(content, "\n")

	for strings.HasPrefix(tlds[0], "#") {
		tlds = tlds[1:]
	}
}

func getFiles(target string) []string {
	var files, dirs []string

	asset, err := os.Stat(target)
	if err != nil {
		log.Println(err)
		return files
	}

	if !asset.IsDir() {
		files = append(files, target)
		return files
	}

	dirs = append(dirs, target)

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
	rex, err := regexp.Compile(REGEX_IPV4)
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

func getFileDomains(data []byte) []string {
	rex, err := regexp.Compile(REGEX_DOMAIN)
	if err != nil {
		log.Fatalln(err)
	}

	var domains []string
	matches := rex.FindAll(data, -1)
	for _, match := range matches {
		dom := strings.ToLower(string(match))

		if len(tlds) == 0 {
			domains = append(domains, dom)
			continue
		}

		for _, tld := range tlds {
			if strings.HasSuffix(dom, "."+tld) {
				domains = append(domains, dom)
				continue
			}
		}
	}

	return domains
}

func getFileIOCs(filename string, domains bool) []string {
	var iocs []string
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalln(err)
	}

	iocs = append(iocs, getFileSHA256(content))
	iocs = append(iocs, getFileIPs(content)...)

	for _, e := range getFileURLs(content) {
		u, err := url.Parse(e)
		if err != nil {
			continue
		}

		u.RawQuery = ""
		u.Path = strings.Trim(u.Path, ")/'\"")
		iocs = append(iocs, u.String(), u.Hostname())
	}

	if domains {
		iocs = append(iocs, getFileDomains(content)...)
	}

	return iocs
}

func main() {
	var pbdomains *bool = flag.Bool("domains", false, "Intensive domain search (many false positives)")
	flag.Parse()

	var bdomains bool = *pbdomains
	target := flag.Arg(0)
	if target == "" {
		target = "."
	}

	files := getFiles(target)
	getTLDs()

	wg := new(sync.WaitGroup)
	wg.Add(len(files))

	for _, filename := range files {
		go func(filename string) {
			defer wg.Done()
			for _, ioc := range getFileIOCs(filename, bdomains) {
				fmt.Println(ioc)
			}
		}(filename)
	}

	wg.Wait()
}
