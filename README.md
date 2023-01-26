# IoCextract

Golang program to look recursively for a possible IoCs (Hashes, IPs, domains, URLs).

## Features

Some features already implemented are:
- Multiple threads
- Inspect one file or a whole directory recursively.
- Domains are deactivated by default due to the high amount of false positives.

## Example usages

Look recursively inside the current folder (. by default):

```bash
./iocextract
```

Analyze a given file:

```bash
./iocextract {file}
```

Find recursively inside a given folder:

```bash
./iocextract {folder}
```

All options:

```
./iocextract --help
Usage of ./iocextract:
  -domains
    	Intensive domain search (many false positives)
```

## Installation

Pretty easy actually, clone the repository and compile:

```bash
git clone https://github.com/cr4zyGoat/iocextract.git
cd iocextract
go build
```

That's all, enjoy the tool ;)
