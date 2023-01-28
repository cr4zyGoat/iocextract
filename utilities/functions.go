package utilities

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const (
	tldsHttpResource = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
)

func FetchTLDs() ([]string, error) {
	res, err := http.Get(tldsHttpResource)
	if err != nil {
		return []string{}, err
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	content := strings.ToLower(string(body))
	tlds := strings.Split(content, "\n")

	for strings.HasPrefix(tlds[0], "#") {
		tlds = tlds[1:]
	}

	return tlds, nil
}

func GetRecursiveFiles(root string) ([]string, []error) {
	var errors []error
	var files []string
	dirs := []string{root}

	for len(dirs) > 0 {
		var cdir string = dirs[0]
		dirs = dirs[1:]

		filenames, err := os.ReadDir(cdir)
		if err != nil {
			errors = append(errors, err)
			continue
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

	return files, errors
}
