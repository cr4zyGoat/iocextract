package classes

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

const (
	regexIPv4   = "((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
	regexIPv6   = "((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}"
	regexUrl    = "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
	regexDomain = "([A-Za-z0-9]|(?i:[a-z0-9])(?-i:[A-Z])|(?i:[A-Z])(?-i:[a-z])-?){1,63}(\\.[A-Za-z]{2,6})"
	regexSha256 = "[A-Fa-f0-9]{64}"
)

type extractor struct {
	TLDs    []string
	cregexs struct {
		ip4    *regexp.Regexp
		ip6    *regexp.Regexp
		url    *regexp.Regexp
		domain *regexp.Regexp
		sha256 *regexp.Regexp
	}
}

func (e *extractor) compileRegexs() {
	e.cregexs.ip4 = regexp.MustCompile(regexIPv4)
	e.cregexs.ip6 = regexp.MustCompile(regexIPv6)
	e.cregexs.url = regexp.MustCompile(regexUrl)
	e.cregexs.domain = regexp.MustCompile(regexDomain)
	e.cregexs.sha256 = regexp.MustCompile(regexSha256)
}

func NewExtractor() extractor {
	obj := extractor{}
	obj.compileRegexs()
	return obj
}

func (e *extractor) calcSha256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

func (e *extractor) extractIPs(data []byte) []string {
	var ips []string

	v4matches := e.cregexs.ip4.FindAll(data, -1)
	for _, match := range v4matches {
		ips = append(ips, string(match))
	}

	v6matches := e.cregexs.ip6.FindAll(data, -1)
	for _, match := range v6matches {
		ips = append(ips, string(match))
	}

	return ips
}

func (e *extractor) extractUrls(data []byte) []string {
	var urls []string

	matches := e.cregexs.url.FindAll(data, -1)
	for _, match := range matches {
		u, err := url.Parse(string(match))
		if err != nil {
			continue
		}

		u.RawQuery = ""
		u.Path = strings.Trim(u.Path, ")/'\"")
		urls = append(urls, u.String())
	}

	return urls
}

func (e *extractor) extractDomains(data []byte) []string {
	var domains []string

	matches := e.cregexs.domain.FindAll(data, -1)
	for _, match := range matches {
		domain := strings.ToLower(string(match))

		if len(e.TLDs) == 0 {
			domains = append(domains, domain)
			continue
		}

		for _, tld := range e.TLDs {
			if strings.HasSuffix(domain, "."+tld) {
				domains = append(domains, domain)
				continue
			}
		}
	}

	return domains
}

func (e *extractor) extractFileIoCs(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return []string{}, err
	}

	iocs := []string{e.calcSha256(data)}
	iocs = append(iocs, e.extractIPs(data)...)
	iocs = append(iocs, e.extractDomains(data)...)
	iocs = append(iocs, e.extractUrls(data)...)

	return iocs, nil
}

func (e *extractor) ExtractIoCs(files []string, output chan string) {
	wg := new(sync.WaitGroup)
	wg.Add(len(files))

	for _, filename := range files {
		go func(filename string) {
			iocs, err := e.extractFileIoCs(filename)
			if err != nil {
				log.Println(err)
				return
			}

			for _, ioc := range iocs {
				output <- ioc
			}

			wg.Done()
		}(filename)
	}

	wg.Wait()
}
