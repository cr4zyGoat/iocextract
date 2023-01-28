# IoCextract

Golang program to look recursively for a possible IoCs (Hashes, IPs, domains, URLs).

## Features

Some features already implemented are:
- Inspect one file or a whole directory recursively
- Select what type of IoC are you looking for
- Multiple threads

## Example usages

Look recursively inside the current folder (. by default):

```bash
./iocextract
```

Analyze a given file:

```bash
./iocextract -f {file}
```

Look just for URLs :

```bash
./iocextract -url
```

All options:

```
./iocextract --help
Usage of ./iocextract:
  -domain
    	Just scan for domains
  -f string
    	Target file or directory to analyze (default ".")
  -hash
    	Just scan for hashes
  -ip
    	Just scan for IPs
  -url
    	Just scan for URLs
```

## Installation

Pretty easy actually, clone the repository and compile:

```bash
git clone https://github.com/cr4zyGoat/iocextract.git
cd iocextract
go build
```

That's all, enjoy the tool ;)
