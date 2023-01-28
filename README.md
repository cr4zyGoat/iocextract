# IoCextract

Golang program to look recursively for a possible IoCs (Hashes, IPs, domains, URLs).

## Features

Some features already implemented are:
- Multiple threads
- Inspect one file or a whole directory recursively.

## Example usages

Look recursively inside the current folder (. by default):

```bash
./iocextract
```

Analyze a given file:

```bash
./iocextract -t {file}
```

Find recursively inside a given folder:

```bash
./iocextract -t {folder}
```

All options:

```
./iocextract --help
Usage of ./iocextract:
  -t string
    	Target file or directory to analyze (default ".")
```

## Installation

Pretty easy actually, clone the repository and compile:

```bash
git clone https://github.com/cr4zyGoat/iocextract.git
cd iocextract
go build
```

That's all, enjoy the tool ;)
