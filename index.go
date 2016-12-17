package CPAN

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/textproto"
)

type PackagesIndexEntry struct {
	Package string `json:"package"`
	Version string `json:"version"`
	Path    string `json:"path"`
}

var ReadPackagesIndexBufferSize int = 4096

func ReadPackagesIndex(r io.Reader) (
	header map[string][]string,
	entries <-chan *PackagesIndexEntry,
	done chan error,
) {
	done = make(chan error)
	r, err := gzip.NewReader(r)
	if err != nil {
		done <- err
		return nil, nil, done
	}
	headerR := textproto.NewReader(bufio.NewReader(r))
	header, err = headerR.ReadMIMEHeader()
	if err != nil {
		done <- err
		return nil, nil, done
	}

	ent := make(chan *PackagesIndexEntry, 5)

	go func() {
		s := bufio.NewScanner(headerR.R)
		headerR = nil
	LOOP:
		for s.Scan() {
			var entry PackagesIndexEntry
			line := s.Bytes()
			i := bytes.IndexByte(line, ' ')
			if i == -1 {
				err = errors.New("invalid line: missing space separator")
				break
			}
			if i == 0 {
				err = errors.New("invalid line: no package")
				break
			}
			entry.Package = string(line[:i])
			j := bytes.LastIndexByte(line, ' ')
			if j == len(line)-1 {
				err = errors.New("invalid line: no dist")
				break
			}
			entry.Path = string(line[j+1:])
			// TODO check the DistPath format: no "/../"

			entry.Version = string(bytes.Trim(line[i:j], " "))

			select {
			case ent <- &entry:
			case _, cont := <-done:
				if !cont {
					break LOOP
				}
			default:
			}
		}
		if err == nil {
			err = s.Err()
		}
		done <- err
		close(ent)
	}()

	return header, ent, done
}
