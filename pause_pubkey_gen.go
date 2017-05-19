// +build generate

package main

import (
	"errors"
	"fmt"
	"math/big"
	"text/template"
	//"fmt"
	"crypto/dsa"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/dolmen-go/codegen"
)

func readPubKey(path string) (*packet.PublicKey, error) {
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("not a public key")
	}

	r := packet.NewReader(block.Body)
	pkt, err := r.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, errors.New("invalid public key")
	}

	return key, nil
}

const tmpl = `// Code generated by go run -tags generate pause_pubkey_gen.go # DO NOT EDIT.

package CPAN

import (
	"crypto/dsa"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

// PAUSEPublicKey is the embeded public key of the central PAUSE indexer
var PAUSEPublicKey *packet.PublicKey

func init() {
	var dsaPubKey dsa.PublicKey
	dsaPubKey.P, _ = new(big.Int).SetString("{{Text .DSA.P 36}}", 36)
	dsaPubKey.Q, _ = new(big.Int).SetString("{{Text .DSA.Q 36}}", 36)
	dsaPubKey.G, _ = new(big.Int).SetString("{{Text .DSA.G 36}}", 36)
	dsaPubKey.Y, _ = new(big.Int).SetString("{{Text .DSA.Y 36}}", 36)

	PAUSEPublicKey = packet.NewDSAPublicKey(time.Unix({{.CreationTime.sec}}, {{.CreationTime.nsec}}), &dsaPubKey)
}
`

func main() {
	pubkey, err := readPubKey("testdata/pause.pubkey")
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
	if dsaPubKey, ok := pubkey.PublicKey.(*dsa.PublicKey); ok {
		//f := (*big.Int).Text
		//fmt.Println(f(dsaPubKey.P, 36))
		t := &codegen.CodeTemplate{
			Template: template.Must(template.New("").Funcs(template.FuncMap{
				"Text": (*big.Int).Text,
			}).Parse(tmpl)),
		}
		err = t.CreateFile("pause_pubkey.go", map[string]interface{}{
			"CreationTime": map[string]int64{
				"sec":  pubkey.CreationTime.Unix(),
				"nsec": pubkey.CreationTime.UnixNano() % 1000000000,
			},
			"DSA": dsaPubKey,
		})
		if err != nil {
			fmt.Fprint(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		fmt.Fprint(os.Stderr, "Not a DSA public key")
		os.Exit(1)
	}
}
