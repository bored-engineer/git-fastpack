# git-fastpack [![Go Reference](https://pkg.go.dev/badge/github.com/bored-engineer/git-fastpack.svg)](https://pkg.go.dev/github.com/bored-engineer/git-fastpack)
A "fast" Golang parser for [git packfiles](https://git-scm.com/book/en/v2/Git-Internals-Packfiles), operating exclusive on byte slices.

```go
package main

import (
	"log"
	"os"

	fastpack "github.com/bored-engineer/git-fastpack"
)

func main() {
	// Create a scanner and set the internal LRU cache size
	scanner, err := fastpack.NewScanner(10000)
	if err != nil {
		log.Fatalf("fastpack.NewScanner failed: %v", err)
	}

	// Read the entire packfile into memory (hint: use mmap)
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("os.ReadFile failed: %v", err)
	}
	scanner.Reset(b)

	// Loop over the packfile contents
	_, objects, err := scanner.Header()
	if err != nil {
		log.Fatalf("(*fastpack.Scanner).Header failed: %v", err)
	}
	for range objects {
		ot, buf, err := scanner.Object()
		if err != nil {
			log.Fatalf("(*fastpack.Scanner).Object failed: %v", err)
		}
		oid := fastpack.OID(ot, buf)
		log.Printf("%x: %s(%d bytes)", oid, ot, len(buf))
	}
	if _, err := scanner.Trailer(); err != nil {
		log.Fatalf("(*fastpack.Scanner).Trailer failed: %v", err)
	}
}
```
