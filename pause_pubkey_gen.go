// +build generate

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"text/template"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	pgperrors "golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/dolmen-go/codegen"
)

func readKeyRing(path string) (openpgp.EntityList, error) {
	in, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(buf))
	if err == nil {
		if len(keyring) > 1 {
			return nil, errors.New("single public key expected in this keyring")
		}
	}
	if _, ok := err.(pgperrors.UnsupportedError); !ok {
		return keyring, err
	}

	fmt.Println("Applying workaround for https://github.com/golang/go/issues/20686")
	// Below is the workaround for https://github.com/golang/go/issues/20686
	// We basically bypass some UserId signature checks because some details of the signature are not yet supported

	e := new(openpgp.Entity)
	e.Identities = make(map[string]*openpgp.Identity)

	block, err := armor.Decode(bytes.NewReader(buf))
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
	var ok bool
	if e.PrimaryKey, ok = pkt.(*packet.PublicKey); !ok {
		return nil, pgperrors.StructuralError("first packet was not a private key")
	}

	if !e.PrimaryKey.PubKeyAlgo.CanSign() {
		return nil, pgperrors.StructuralError("primary key cannot be used for signatures")
	}

	var uid *openpgp.Identity

	for {
		pkt, err := r.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			if _, ok := err.(pgperrors.UnsupportedError); ok {
				fmt.Printf("Skip packet: %s\n", err)
				continue
			}
			return nil, err
		}

		switch pkt := pkt.(type) {
		case *packet.PublicKey:
			if !pkt.IsSubkey {
				return nil, errors.New("single public key expected in this keyring")
			}
			e.Subkeys = append(e.Subkeys, openpgp.Subkey{PublicKey: pkt})
		case *packet.UserId:
			uid = &openpgp.Identity{Name: pkt.Id, UserId: pkt}
			e.Identities[pkt.Id] = uid
			// signatures of the uid
			for {
				p, err := r.Next()
				if err != nil {
					if err == io.EOF {
						return nil, io.ErrUnexpectedEOF
					}
					if _, ok := err.(pgperrors.UnsupportedError); ok {
						fmt.Printf("Skip packet: %s\n", err)
						continue
					}
				}
				sig, ok := p.(*packet.Signature)
				if !ok {
					return nil, pgperrors.StructuralError("user ID packet not followed by self-signature")
				}
				if (sig.SigType == packet.SigTypePositiveCert || sig.SigType == packet.SigTypeGenericCert) && sig.IssuerKeyId != nil && *sig.IssuerKeyId == e.PrimaryKey.KeyId {
					if err = e.PrimaryKey.VerifyUserIdSignature(pkt.Id, e.PrimaryKey, sig); err != nil {
						return nil, pgperrors.StructuralError("user ID self-signature invalid: " + err.Error())
					}
					uid.SelfSignature = sig
					break
				}
				uid.Signatures = append(uid.Signatures, sig)
			}
		case *packet.Signature:
			if pkt.SigType == packet.SigTypeKeyRevocation {
				fmt.Printf("Skip %T packet\n", pkt)
			} else if pkt.SigType == packet.SigTypeDirectSignature {
				// TODO: RFC4880 5.2.1 permits signatures
				// directly on keys (eg. to bind additional
				// revocation keys).
			} else if uid == nil {
				return nil, pgperrors.StructuralError("signature packet found before user id packet")
			} else {
				uid.Signatures = append(uid.Signatures, pkt)
			}
		default:
			// Skip anything else (revocation lists...)
			fmt.Printf("Skip %T packet\n", pkt)
		}
	}

	return openpgp.EntityList{e}, nil
}

const tmpl = `// Code generated by go run -tags generate pause_pubkey_gen.go # DO NOT EDIT.

package CPAN

import (
	"crypto/dsa"
	"math/big"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/elgamal"
)

// PAUSEKeyRing contains the embeded public keys of the central PAUSE indexer
var PAUSEKeyRing openpgp.KeyRing

{{define "PublicKey"}}{{/* printf "%#v" . */}}
{{- if (eq .PubKeyAlgo 0x11) -}}
newDSAPublicKey(
	{{CreationTime .}}, // CreationTime
	"{{Text .PublicKey.P 36}}", // P
	"{{Text .PublicKey.Q 36}}", // Q
	"{{Text .PublicKey.G 36}}", // G
	"{{Text .PublicKey.Y 36}}", // Y
){{- else if (eq .PubKeyAlgo 0x10) -}}
newElGamalPublicKey(
	{{CreationTime .}}, // CreationTime
	"{{Text .PublicKey.G 36}}", // G
	"{{Text .PublicKey.P 36}}", // P
	"{{Text .PublicKey.Y 36}}", // Y
){{- else -}}
nil /* Unsupported public key algo {{printf "%#x" .PubKeyAlgo}} */
{{- end -}}
{{end}}

func init() {
	// FIXME also dump self signatures to expose usage flags

	{{- /* printf "%#v" . */}}
	var e openpgp.Entity
	e.PrimaryKey = {{template "PublicKey" .PrimaryKey}}
	{{if .Subkeys}}
	var pubkey *packet.PublicKey
	{{end}}
	{{- range .Subkeys}}
	pubkey = {{template "PublicKey" .PublicKey}}
	pubkey.IsSubkey = true
	e.Subkeys = append(e.Subkeys, openpgp.Subkey{PublicKey: pubkey})
	{{end}}
	PAUSEKeyRing = openpgp.EntityList{&e}
}

func newDSAPublicKey(creationTime time.Time, P36, Q36, G36, Y36 string) *packet.PublicKey {
	var dsaPubKey dsa.PublicKey
	dsaPubKey.P, _ = new(big.Int).SetString(P36, 36)
	dsaPubKey.Q, _ = new(big.Int).SetString(Q36, 36)
	dsaPubKey.G, _ = new(big.Int).SetString(G36, 36)
	dsaPubKey.Y, _ = new(big.Int).SetString(Y36, 36)
	return packet.NewDSAPublicKey(creationTime, &dsaPubKey)
}

func newElGamalPublicKey(creationTime time.Time, G36, P36, Y36 string) *packet.PublicKey {
	var elgamalPubKey elgamal.PublicKey
	elgamalPubKey.G, _ = new(big.Int).SetString(G36, 36)
	elgamalPubKey.P, _ = new(big.Int).SetString(P36, 36)
	elgamalPubKey.Y, _ = new(big.Int).SetString(Y36, 36)
	return packet.NewElGamalPublicKey(creationTime, &elgamalPubKey)
}
`

func main() {
	keyring, err := readKeyRing("testdata/pause.pubkey")
	if err != nil && keyring == nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}

	// fmt.Printf("Keyring: %#v\n", keyring)
	// fmt.Printf("PrimaryKey: %#v\n", keyring[0].PrimaryKey)
	// fmt.Printf("Subkeys: %#v\n", keyring[0].Subkeys)
	// fmt.Printf("Subkeys[0]: %#v\n", keyring[0].Subkeys[0].PublicKey)

	t := &codegen.CodeTemplate{
		Template: template.Must(template.New("").Funcs(template.FuncMap{
			"Text": (*big.Int).Text,
			"CreationTime": func(pubkey *packet.PublicKey) string {
				return fmt.Sprintf("time.Unix(%d, %d)",
					pubkey.CreationTime.Unix(),
					pubkey.CreationTime.Unix()%1000000000,
				)
			},
		}).Parse(tmpl)),
	}
	err = t.CreateFile("pause_pubkey.go", keyring[0])
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
