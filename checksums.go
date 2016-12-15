package CPAN

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
)

type CheckSum struct {
	MD5    string `json:"md5"`
	MTime  string `json:"mtime"`
	Sha256 string `json:"sha256"`
	Size   int    `json:"size"`
	IsDir  int    `json:"isdir"`
}

var (
	ErrNoData = errors.New("no data")
	ErrSyntax = errors.New("syntax error")
)

func parseCheckSums(buf []byte) (map[string]CheckSum, error) {
	// Skip perl comments
	for {
		if len(buf) == 0 {
			return nil, ErrNoData
		}
		if buf[0] != '#' {
			break
		}
		// Skip line
		i := bytes.IndexByte(buf, '\n')
		if i == -1 {
			return nil, ErrNoData
		}
		buf = buf[i+1:]
	}

	i := bytes.IndexByte(buf, '{')
	buf = buf[i:]
	j := bytes.LastIndexByte(buf, '}')
	if i == -1 {
		return nil, ErrSyntax
	}
	if j == -1 {
		return nil, ErrSyntax
	}
	buf = buf[:j+1]

	// Transform the Perl hashref into JSON
	// FIXME fragile code
	for i, c := range buf {
		switch c {
		// Forbid chars that could break our basic Perl-to-JSON transform
		case '\\', '"':
			return nil, ErrSyntax
		case '\'':
			buf[i] = '"'
		case '=':
			if len(buf) > i+2 && buf[i+1] == '>' {
				buf[i] = ':'
				buf[i+1] = ' '
			}
		}
	}

	var checksums map[string]CheckSum
	if err := json.Unmarshal(buf, &checksums); err != nil {
		return nil, err
	}

	return checksums, nil
}

// ReadCheckSums loads the content of a CHECKSUMS file.
// The PGP signature is verified.
func ReadCheckSums(r io.Reader, pubkey *packet.PublicKey) (map[string]CheckSum, error) {
	content, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	block, _ := clearsign.Decode(content)
	if block == nil {
		return nil, errors.New("no signed block found")
	}

	sigblock := block.ArmoredSignature

	if sigblock == nil || sigblock.Type != openpgp.SignatureType {
		return nil, errors.New("invalid signature block")
	}

	reader := packet.NewReader(sigblock.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, fmt.Errorf("error reading signature: %s", err)
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	hash := sig.Hash.New()
	hash.Write(block.Bytes)

	err = pubkey.VerifySignature(hash, sig)
	if err != nil {
		return nil, fmt.Errorf("verify failure: %s", err)
	}

	return parseCheckSums(block.Bytes)
}
