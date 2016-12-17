// An example of CPAN.ReadIndex(): converts a 02packages.tar.gz to JSON.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/dolmen-go/CPAN"
)

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	defer f.Close()

	_, entries, done := CPAN.ReadPackagesIndex(f)

	sep := "[\n"
LOOP:
	for {
		select {
		case entry := <-entries:
			os.Stdout.WriteString(sep)
			sep = ",\n"
			buf, _ := json.Marshal(entry)
			os.Stdout.Write(buf)
		case err = <-done:
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			break LOOP
		}
	}
	if sep[0] != '[' {
		os.Stdout.Write([]byte{']', '\n'})
	}
}
